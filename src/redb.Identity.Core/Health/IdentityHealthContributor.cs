using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using redb.Core;
using redb.Tsak.Contracts;
using redb.Tsak.Core.Contracts;

namespace redb.Identity.Core.Health;

/// <summary>
/// Per-module health probe for redb.Identity. Surfaces the module under
/// <c>module:identity</c> in the aggregated <c>/api/health/{startup,live,ready}</c>
/// endpoints exposed by <c>redb.Tsak</c>.
/// <para>
/// Probes (worst status wins):
/// <list type="bullet">
///   <item><b>db</b> — <see cref="IRedbService.GetDbVersionAsync"/> returns a non-empty
///   string. Failure → <see cref="HealthStatus.Unhealthy"/>.</item>
///   <item><b>signing-keys</b> — at least one signing credential is registered with the
///   OpenIddict server. Empty → <see cref="HealthStatus.Unhealthy"/> (token issuance
///   would fail).</item>
///   <item><b>data-protection</b> — the active key-ring exposes at least one key.
///   Empty → <see cref="HealthStatus.Degraded"/> (cookie / state protection still works
///   on the in-memory bootstrap key, but nothing is persisted yet).</item>
/// </list>
/// </para>
/// <remarks>
/// Registered as a singleton in <c>AddRedbIdentityServer</c>. Resolves
/// <see cref="IRedbService"/> through a transient scope to honour its scoped lifetime.
/// All exceptions are caught locally so a misbehaving probe cannot crash the health
/// endpoint (Tsak additionally guards via <see cref="HealthStatus.Unhealthy"/> fallback).
/// </remarks>
/// </summary>
public sealed class IdentityHealthContributor : IModuleHealthContributor
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IdentityHealthContributor> _logger;

    public IdentityHealthContributor(
        IServiceProvider serviceProvider,
        ILogger<IdentityHealthContributor> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public string ModuleName => "identity";

    /// <inheritdoc />
    public async Task<HealthStatus> CheckHealthAsync(CancellationToken ct)
    {
        var dbOk = await CheckDatabaseAsync(ct).ConfigureAwait(false);
        var signingOk = CheckSigningKeys();
        var dataProtectionOk = CheckDataProtection();

        if (!dbOk || !signingOk)
            return HealthStatus.Unhealthy;

        if (!dataProtectionOk)
            return HealthStatus.Degraded;

        return HealthStatus.Healthy;
    }

    private async Task<bool> CheckDatabaseAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
            var version = await redb.GetDbVersionAsync(ct).ConfigureAwait(false);
            return !string.IsNullOrWhiteSpace(version);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Identity health: database probe failed");
            return false;
        }
    }

    private bool CheckSigningKeys()
    {
        try
        {
            var monitor = _serviceProvider.GetService<IOptionsMonitor<OpenIddictServerOptions>>();
            if (monitor is null)
                return false;
            return monitor.CurrentValue.SigningCredentials.Count > 0;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Identity health: signing-key probe failed");
            return false;
        }
    }

    private bool CheckDataProtection()
    {
        try
        {
            var keyManager = _serviceProvider.GetService<IKeyManager>();
            if (keyManager is null)
            {
                // DataProtection not wired (atypical) — degraded rather than unhealthy:
                // session cookies / state protectors will fail later but other Identity
                // surfaces (token issuance) can still serve.
                return false;
            }

            // GetAllKeys is cached — single-digit ms even on hot key-rings.
            var keys = keyManager.GetAllKeys();
            return keys.Count > 0;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Identity health: data-protection probe failed");
            return false;
        }
    }
}
