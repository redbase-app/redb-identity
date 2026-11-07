using Google.Protobuf;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Routes;
using redb.Identity.Grpc.Processors;
using redb.Identity.Grpc.V1;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Grpc;

namespace redb.Identity.Grpc;

/// <summary>
/// gRPC facade for redb.Identity. Maps gRPC method addresses to <c>direct-vm://identity-*</c> routes.
/// <para>
/// One method address = one route. The address is the route key, so every operation gets its own
/// <c>RouteId</c>, policies, metrics and lifecycle, and they all share a single port.
/// </para>
/// <para>
/// Scope is the service-to-service subset of the protocol. Browser flows (authorize, login, consent, MFA
/// pages, device verification) stay on HTTP: they need a browser, redirects and a cookie session. DPoP
/// stays on HTTP too — RFC 9449 binds its proof to the HTTP method and URL.
/// See <c>doc/gRPC/ARCHITECTURE.md</c>.
/// </para>
/// </summary>
public class GrpcFacadeRouteBuilder : RouteBuilder
{
    private readonly IdentityGrpcTransportOptions _options;

    public GrpcFacadeRouteBuilder(IOptions<IdentityGrpcTransportOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    /// <summary>Package-qualified service name of the published contract.</summary>
    private const string Service = "/identity.v1.Identity";

    protected override void Configure()
    {
        ConfigureProtocolOperations();
        ConfigureGenericFallback();
    }

    /// <summary>
    /// The service-to-service protocol surface. One method address per operation, so each gets its own
    /// route id, policies, metrics and lifecycle — visible individually in the dashboard and suspendable
    /// individually through the control bus.
    /// </summary>
    private void ConfigureProtocolOperations()
    {
        var port = _options.Grpc.PublicPort;

        // RFC 6749 §3.2. Client authentication is whatever the caller used — fields in the message or
        // `authorization: Basic` metadata; Core reads both, so the facade adds no step for it.
        Operation<TokenRequest, TokenResponse>(port, "Token", IdentityEndpoints.Token,
            TokenRequest.Parser, overflow: "extra");

        // RFC 7662.
        Operation<IntrospectRequest, IntrospectResponse>(port, "Introspect", IdentityEndpoints.Introspect,
            IntrospectRequest.Parser, overflow: "extra");

        // RFC 7009. A successful revocation carries no payload — the empty message is the answer.
        Operation<RevokeRequest, RevokeResponse>(port, "Revoke", IdentityEndpoints.Revoke,
            RevokeRequest.Parser, overflow: "extra");

        // OIDC Core §5.3. The Bearer token travels as metadata or as the message field; Core reads both.
        Operation<UserInfoRequest, UserInfoResponse>(port, "UserInfo", IdentityEndpoints.Userinfo,
            UserInfoRequest.Parser, overflow: "claims");

        // Discovery and JWKS are documents, passed through verbatim. The discovery document advertises
        // the server's HTTP endpoints — those are the real ones, and rewriting them here would hand
        // callers addresses that do not exist.
        Document<DiscoveryRequest, DiscoveryResponse>(port, "Discovery", IdentityEndpoints.Discovery,
            DiscoveryRequest.Parser, field: "document");

        Document<JwksRequest, JwksResponse>(port, "Jwks", IdentityEndpoints.Jwks,
            JwksRequest.Parser, field: "document");
    }

    /// <summary>Wires one operation: parse → boundary → status → encode.</summary>
    private void Operation<TRequest, TResponse>(
        int port, string method, string endpoint, MessageParser<TRequest> parser, string overflow)
        where TRequest : IMessage<TRequest>
        where TResponse : IMessage<TResponse>, new()
    {
        From(BuildListener(port).Method($"{Service}/{method}"))
            .RouteId($"grpc-identity-{method.ToLowerInvariant()}")
            .Process(GrpcIdentityProcessors.PropagateCorrelationId)
            .Process(GrpcIdentityProcessors.TagOperation(method.ToLowerInvariant()))
            .Process(GrpcIdentityProcessors.MapRequest(parser))
            .Enrich(endpoint, GrpcIdentityProcessors.AdoptCoreAnswer)
            .Process(GrpcIdentityProcessors.MapErrorToGrpcStatus)
            .Process(GrpcIdentityProcessors.MapResponse<TResponse>(overflow));
    }

    /// <summary>Wires an operation whose answer is a single pass-through document.</summary>
    private void Document<TRequest, TResponse>(
        int port, string method, string endpoint, MessageParser<TRequest> parser, string field)
        where TRequest : IMessage<TRequest>
        where TResponse : IMessage<TResponse>, new()
    {
        From(BuildListener(port).Method($"{Service}/{method}"))
            .RouteId($"grpc-identity-{method.ToLowerInvariant()}")
            .Process(GrpcIdentityProcessors.PropagateCorrelationId)
            .Process(GrpcIdentityProcessors.TagOperation(method.ToLowerInvariant()))
            .Process(GrpcIdentityProcessors.MapRequest(parser))
            .Enrich(endpoint, GrpcIdentityProcessors.AdoptCoreAnswer)
            .Process(GrpcIdentityProcessors.MapErrorToGrpcStatus)
            .Process(GrpcIdentityProcessors.MapDocumentResponse<TResponse>(field));
    }

    /// <summary>
    /// The generic <c>RedbService</c> address — the envelope fallback for callers that do not want to
    /// carry <c>identity.v1.proto</c>. It also opens the port and, with <c>.Health()</c>, mounts
    /// <c>grpc.health.v1.Health/Check</c> for Kubernetes / Consul / Envoy probes.
    /// </summary>
    private void ConfigureGenericFallback()
    {
        From(BuildListener(_options.Grpc.PublicPort))
            .RouteId("grpc-identity-envelope")
            .Process(GrpcIdentityProcessors.PropagateCorrelationId)
            // No TagOperation here: the envelope's own `operation` header already names the operation,
            // and that is the header Core's idempotency cache reads.
            .Process(GrpcIdentityProcessors.MapEnvelopeRequest)
            // Enrich, not DynamicRouter: the address is already decided, and the hop has to be isolated
            // for the same reason the typed routes isolate theirs - see AdoptCoreAnswer.
            .Enrich(
                e => e.Properties.Remove(GrpcIdentityProcessors.EndpointProperty, out var endpoint)
                    ? endpoint as string ?? string.Empty
                    : string.Empty,
                GrpcIdentityProcessors.AdoptCoreAnswer)
            .Process(GrpcIdentityProcessors.MapErrorToGrpcStatus)
            .Process(GrpcIdentityProcessors.MapEnvelopeResponse);
    }

    /// <summary>
    /// Builds a listener URI from the transport options. Health is mounted on every listening port: the
    /// probe answers «is <i>this</i> listener serving», which a probe on another port cannot show.
    /// </summary>
    /// <summary>Registry key for the TLS material, kept out of the endpoint URI on purpose.</summary>
    private const string TlsFactoryName = "identity-grpc-tls";

    private GrpcBuilder BuildListener(int port)
    {
        var grpc = _options.Grpc;

        var builder = GrpcDsl.Listen($"{grpc.Host}:{port}")
            .MaxMessageSize(grpc.MaxMessageSize)
            .Health(grpc.Health)
            // Core keys its per-IP throttle and brute-force lockout on redbHttp.RemoteAddress. Without
            // this bridge those protections silently do nothing for gRPC callers — they no-op when the
            // header is absent rather than failing loudly.
            .EmitHttpCompatHeaders(grpc.EmitHttpCompatHeaders);

        if (!string.IsNullOrWhiteSpace(grpc.Compression)
            && Enum.TryParse<GrpcCompression>(grpc.Compression, ignoreCase: true, out var compression))
        {
            builder = builder.Compression(compression);
        }

        if (grpc.Ssl)
        {
            builder = builder.Ssl();

            // TLS material travels through a named connection factory rather than in the endpoint URI.
            // Not because the URI would disclose it — SslCertPassword is [Sensitive], so it is redacted
            // wherever the URI is rendered — but because this keeps the secret out of the route key
            // altogether. The key is handled as a plain string in plenty of places; a value that was
            // never put in it cannot be disclosed by a path that forgets to render it through the
            // redactor.
            Context!.AddToRegistry(TlsFactoryName, new GrpcConnectionFactory
            {
                Ssl = true,
                SslCertPath = grpc.SslCertPath,
                SslCertPassword = grpc.SslCertPassword,
            });
            builder = builder.ConnectionFactory(TlsFactoryName);

            // mTLS is opt-in: deployments without a client-certificate PKI must not be blocked. For the
            // management port it is the recommended production setting — see doc/gRPC/OPEN_QUESTIONS.md.
            if (Enum.TryParse<GrpcClientCertificateMode>(grpc.ClientCertificateMode, ignoreCase: true, out var mode)
                && mode != GrpcClientCertificateMode.NoCertificate)
            {
                var thumbprints = (grpc.AllowedClientThumbprints ?? string.Empty)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                builder = builder.ClientCertificates(mode, thumbprints);
            }
        }
        else
        {
            builder = builder.Plaintext();
        }

        return builder;
    }
}
