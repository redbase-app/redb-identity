using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Ldap;
using static redb.Route.Ldap.LdapDsl;

namespace redb.Identity.Ldap;

/// <summary>
/// Health check that probes each registered LDAP provider via an anonymous RootDSE search.
/// Tests the full LDAP stack: TCP → TLS → LDAP protocol.
/// </summary>
public sealed class LdapHealthCheck : IHealthCheck
{
    private readonly LdapExternalUserProvider[] _ldapProviders;
    private readonly ILogger<LdapHealthCheck> _logger;

    public LdapHealthCheck(
        IEnumerable<IExternalUserProvider> providers,
        ILogger<LdapHealthCheck> logger)
    {
        _ldapProviders = (providers ?? [])
            .OfType<LdapExternalUserProvider>()
            .ToArray();
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken ct = default)
    {
        if (_ldapProviders.Length == 0)
            return HealthCheckResult.Healthy("No LDAP providers registered.");

        var data = new Dictionary<string, object>();
        var allHealthy = true;

        foreach (var provider in _ldapProviders)
        {
            var key = $"ldap:{provider.ProviderName}";
            var options = provider.Options;

            try
            {
                var sw = Stopwatch.StartNew();

                // Pre-flight DNS+TCP probe — bounds the unreachable-host case to
                // ConnectTimeoutSeconds instead of OS-level TCP retransmit (~21 s).
                await LdapConnectivityProbe.ProbeAsync(
                    options.Server, options.EffectivePort,
                    options.ConnectTimeoutSeconds, ct).ConfigureAwait(false);

                var builder = Search("")
                    .Server(options.Server)
                    .Port(options.EffectivePort)
                    .Scope(LdapSearchScope.Base)
                    .Filter("(objectClass=*)")
                    .SizeLimit(1);

                if (options.UseSsl) builder.Ssl();
                if (options.UseStartTls) builder.StartTls();
                if (options.SkipCertificateValidation) builder.SkipCertificateValidation();
                if (options.OperationTimeoutSeconds > 0)
                    builder.OperationTimeout(options.OperationTimeoutSeconds * 1000);

                var component = new LdapComponent();
                var endpoint = component.CreateEndpoint(EndpointUriParser.Parse(builder.Build()));
                var producer = endpoint.CreateProducer();

                try
                {
                    await producer.Start(ct).ConfigureAwait(false);
                    var exchange = new Exchange(new Message());
                    await producer.Process(exchange, ct).ConfigureAwait(false);

                    sw.Stop();
                    data[key] = $"OK ({sw.ElapsedMilliseconds}ms) {options.Server}:{options.EffectivePort}";
                    _logger.LogDebug("LDAP health OK: {Provider} {Server}:{Port} in {Ms}ms",
                        provider.ProviderName, options.Server, options.EffectivePort, sw.ElapsedMilliseconds);
                }
                finally
                {
                    await producer.Stop(ct).ConfigureAwait(false);
                    (endpoint as IDisposable)?.Dispose();
                }
            }
            catch (OperationCanceledException)
            {
                allHealthy = false;
                data[key] = $"Timeout {options.Server}:{options.EffectivePort}";
            }
            catch (TimeoutException ex)
            {
                allHealthy = false;
                data[key] = $"Connect timeout: {options.Server}:{options.EffectivePort} ({ex.Message})";
                _logger.LogWarning("LDAP health check connect-timeout for {Provider}: {Error}",
                    provider.ProviderName, ex.Message);
            }
            catch (SocketException ex)
            {
                allHealthy = false;
                data[key] = $"Connection failed: {options.Server}:{options.EffectivePort} ({ex.Message})";
                _logger.LogWarning("LDAP health check failed for {Provider}: {Error}",
                    provider.ProviderName, ex.Message);
            }
            catch (Exception ex)
            {
                allHealthy = false;
                data[key] = $"Error: {options.Server}:{options.EffectivePort} ({ex.Message})";
                _logger.LogWarning(ex, "LDAP health check failed for {Provider}",
                    provider.ProviderName);
            }
        }

        var status = allHealthy
            ? HealthCheckResult.Healthy("All LDAP servers reachable.", data)
            : new HealthCheckResult(
                context?.Registration.FailureStatus ?? HealthStatus.Degraded,
                "One or more LDAP servers unreachable.",
                data: data);

        return status;
    }
}
