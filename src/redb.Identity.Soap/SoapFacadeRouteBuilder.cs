using Microsoft.Extensions.Options;
using redb.Identity.Soap.Processors;
using redb.Route.Core;
using redb.Route.Soap;
using SoapDsl = redb.Route.Soap.Fluent.Soap;

namespace redb.Identity.Soap;

/// <summary>
/// WS-Trust facade for redb.Identity. Maps <c>Issue</c>, <c>Validate</c>, <c>Cancel</c> and
/// <c>Renew</c> onto the same <c>direct-vm://identity-*</c> routes HTTP and gRPC use.
/// <para>
/// One route, not four. This is where the shape departs from the gRPC facade, and not by preference:
/// WS-Trust puts all four operations on one address and distinguishes them by the WS-Addressing
/// <c>Action</c>. Generated clients expect exactly that, so the operation is resolved by parsing rather
/// than by routing.
/// </para>
/// <para>
/// Scope is the service-to-service subset, as on gRPC. Browser flows stay on HTTP because they need a
/// browser, redirects and a cookie session; DPoP stays on HTTP because RFC 9449 binds its proof to an
/// HTTP method and URL. See <c>doc/SOAP/README.md</c>.
/// </para>
/// </summary>
public class SoapFacadeRouteBuilder : RouteBuilder
{
    private readonly IdentitySoapTransportOptions _options;

    public SoapFacadeRouteBuilder(IOptions<IdentitySoapTransportOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    /// <summary>Registry key for the TLS material, kept out of the endpoint URI on purpose.</summary>
    private const string TlsFactoryName = "identity-soap-tls";

    protected override void Configure()
    {
        var soap = _options.Soap;

        RequireTransportSecurity(soap);

        From(BuildListener(soap))
            .RouteId("soap-identity-sts")
            .Process(SoapIdentityProcessors.PropagateCorrelationId)
            .Process(SoapIdentityProcessors.MapRequest)
            // The operation is known only after the body is parsed, so it is named here rather than by
            // the address. Core's idempotency cache keys on it.
            .Process(TagResolvedOperation)
            // Enrich, not To: several Core processors end with exchange.Stop(), and that flag would stop
            // this pipeline too, sending the raw dictionary out instead of an RSTR. See AdoptCoreAnswer.
            .Enrich(
                e => e.Properties.TryGetValue(SoapIdentityProcessors.EndpointProperty, out var endpoint)
                    ? endpoint as string ?? string.Empty
                    : string.Empty,
                SoapIdentityProcessors.AdoptCoreAnswer)
            .Process(SoapIdentityProcessors.MapResponse);
    }

    /// <summary>
    /// Tags the operation once <see cref="SoapIdentityProcessors.MapRequest"/> has resolved it. Without
    /// a name, every call through this facade shares Core's idempotency bucket "default", and two
    /// different operations carrying one key would collide.
    /// </summary>
    private static Task TagResolvedOperation(redb.Route.Abstractions.IExchange exchange, CancellationToken ct)
    {
        var requestType = exchange.Properties.TryGetValue(
            SoapIdentityProcessors.RequestTypeProperty, out var value) ? value as string : null;

        if (!string.IsNullOrEmpty(requestType))
            exchange.In.Headers["operation"] = requestType!.ToLowerInvariant();

        return Task.CompletedTask;
    }

    /// <summary>
    /// Refuses to start without transport security.
    /// <para>
    /// This is stricter than the other facades, and the reason is specific rather than cautious:
    /// <c>UsernameToken</c> carries the client secret in clear text unless the digest form is used, so
    /// an STS on plain HTTP publishes credentials to anyone on the path. A warning in the log would be
    /// read after the fact; a refusal is read before.
    /// </para>
    /// <para>
    /// <see cref="SoapTransportOptions.AllowPlaintext"/> is the way out for a run behind a terminating
    /// proxy, and it exists so the operator states that choice rather than stumbling into it.
    /// </para>
    /// </summary>
    private static void RequireTransportSecurity(SoapTransportOptions soap)
    {
        if (soap.Ssl || soap.AllowPlaintext) return;

        throw new InvalidOperationException(
            "redb.Identity.Soap refuses to start without TLS: WS-Security UsernameToken carries the " +
            "client secret in clear text. Set IdentityTransport:Soap:Ssl=true with a certificate, or " +
            "set AllowPlaintext=true if the connection is already terminated by a trusted proxy.");
    }

    /// <summary>
    /// Builds the listener. TLS material travels through a named connection factory rather than in the
    /// endpoint URI: the URI is the route key, handled as a plain string in plenty of places, and a
    /// value never put there cannot be disclosed by a path that forgets to redact it.
    /// </summary>
    private string BuildListener(SoapTransportOptions soap)
    {
        var mode = ParseClientCertificateMode(soap.ClientCertificateMode);

        Context!.AddToRegistry(TlsFactoryName, new SoapConnectionFactory
        {
            Ssl = soap.Ssl,
            SslCertPath = soap.SslCertPath,
            SslCertPassword = soap.SslCertPassword,
            ClientCertificateMode = mode,
            AllowedClientThumbprints = soap.AllowedClientThumbprints,

            // The contract, served on GET. The audience for this facade builds clients with generators,
            // and a generator needs a document to read.
            Wsdl = soap.Wsdl ? WsdlDocument.ReadContent() : null,
        });

        var builder = SoapDsl.Listen(soap.Path)
            .Host(soap.Host)
            .Port(soap.Port)
            .ConnectionFactory(TlsFactoryName)
            // Core's IP-keyed processors — the per-IP throttle, the brute-force lockout, device metadata
            // — read redbHttp.RemoteAddress. Without this bridge they would see no address and quietly
            // do nothing, so the facade would be the one surface where those protections are absent.
            .HttpCompatHeaders(soap.EmitHttpCompatHeaders);

        // TLS and the client-certificate policy are stated on the factory, so the URI carries neither a
        // certificate path nor a password. The scheme still has to say TLS, because that is where the
        // component reads the decision from.
        if (soap.Ssl) builder = builder.Ssl();

        return builder.Build();
    }

    /// <summary>
    /// Reads the configured client-certificate mode. An unrecognised value is refused rather than
    /// silently treated as «no certificate»: a typo in this setting would turn mTLS off on an endpoint
    /// whose operator believes it is on.
    /// </summary>
    private static SoapClientCertificateMode ParseClientCertificateMode(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return SoapClientCertificateMode.NoCertificate;

        if (Enum.TryParse<SoapClientCertificateMode>(configured, ignoreCase: true, out var mode))
            return mode;

        throw new InvalidOperationException(
            $"Unknown IdentityTransport:Soap:ClientCertificateMode value '{configured}'. " +
            $"Expected one of: {string.Join(", ", Enum.GetNames<SoapClientCertificateMode>())}.");
    }
}
