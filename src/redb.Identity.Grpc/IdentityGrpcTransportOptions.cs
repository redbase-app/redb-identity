using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Grpc;

/// <summary>
/// Configuration for the Identity gRPC transport facade. Mirrors
/// <c>redb.Identity.Http.IdentityTransportOptions</c> in shape so operators configure both facades the
/// same way: transport-local settings here, cross-module state through <c>direct-vm://</c> into Core.
/// </summary>
public class IdentityGrpcTransportOptions
{
    /// <summary>gRPC-specific transport settings (ports, TLS, codec).</summary>
    public GrpcTransportOptions Grpc { get; set; } = new();

    /// <summary>
    /// Cross-module shared options (Issuer + Features). Same instance type as
    /// <c>RedbIdentityOptions.Shared</c> and <c>IdentityTransportOptions.Shared</c>, so a value declared
    /// once in <c>Identity:*</c> is observed identically by Core and by every facade.
    /// </summary>
    public IdentitySharedOptions Shared { get; set; } = new();

    /// <summary>
    /// Issuer URI of the identity server. Proxy onto <see cref="Shared"/>. The gRPC facade does not
    /// rewrite the discovery document, so this is used only where a route needs to know its own identity.
    /// </summary>
    public Uri Issuer
    {
        get => Shared.Issuer;
        set => Shared.Issuer = value;
    }

    /// <summary>Cross-module feature toggles. Proxy onto <see cref="Shared"/>.</summary>
    public IdentityFeatureFlags Features
    {
        get => Shared.Features;
        set => Shared.Features = value;
    }
}

/// <summary>gRPC listener settings.</summary>
public class GrpcTransportOptions
{
    /// <summary>Bind address. Default <c>0.0.0.0</c>.</summary>
    public string Host { get; set; } = "0.0.0.0";

    /// <summary>
    /// Port for the protocol surface (token, introspect, revoke, userinfo, discovery, jwks).
    /// Default 5001.
    /// <para>
    /// This port is never shared with the HTTP facade: gRPC needs HTTP/2 while the HTTP facade serves
    /// HTTP/1.1 + HTTP/2, and one Kestrel listener has a single protocol set. The shared host enforces
    /// this — registering both on one port throws rather than failing later with a framing error.
    /// </para>
    /// </summary>
    public int PublicPort { get; set; } = 5001;

    /// <summary>
    /// Port for the management surface. <c>null</c> means «same as <see cref="PublicPort"/>», which is
    /// the single-node default and needs no extra configuration.
    /// <para>
    /// Splitting it matters in production: the protocol surface is called by every relying party, the
    /// management surface only by admin tooling. Different consumers, different blast radius — so the
    /// admin port gets firewalled separately. Same semantics as the HTTP facade's
    /// <c>ManagementPort ?? PublicPort</c>, so both facades are configured alike.
    /// </para>
    /// </summary>
    public int? ManagementPort { get; set; }

    /// <summary>Enable TLS. Requires <see cref="SslCertPath"/>.</summary>
    public bool Ssl { get; set; }

    /// <summary>Path to the PFX certificate used when <see cref="Ssl"/> is true.</summary>
    public string? SslCertPath { get; set; }

    /// <summary>Password for <see cref="SslCertPath"/>.</summary>
    public string? SslCertPassword { get; set; }

    /// <summary>
    /// Client-certificate policy (mTLS): <c>NoCertificate</c> (default), <c>AllowCertificate</c> or
    /// <c>RequireCertificate</c>. Off by default so deployments without a client-certificate PKI are not
    /// blocked; recommended for the management port in production.
    /// </summary>
    public string ClientCertificateMode { get; set; } = "NoCertificate";

    /// <summary>
    /// Comma-separated SHA-1 thumbprints of accepted client certificates. When set, a certificate whose
    /// thumbprint is not listed is rejected even if its chain validates.
    /// </summary>
    public string? AllowedClientThumbprints { get; set; }

    /// <summary>Reply compression: <c>None</c> (default) or <c>Gzip</c>. Requests are always inflated.</summary>
    public string Compression { get; set; } = "None";

    /// <summary>Max message size in bytes for both directions. Default 4 MB.</summary>
    public int MaxMessageSize { get; set; } = 4 * 1024 * 1024;

    /// <summary>
    /// Serve <c>grpc.health.v1.Health/Check</c> on every listening port. Standard probe for Kubernetes,
    /// Consul and Envoy. Default true — the check is unauthenticated and costs two bytes.
    /// </summary>
    public bool Health { get; set; } = true;

    /// <summary>
    /// Mirror the resolved client address into <c>redbHttp.RemoteAddress</c> so the IP-keyed processors in
    /// Core (per-IP throttle, brute-force lockout, device metadata) work behind this facade unchanged.
    /// Default true: without it those protections silently do nothing for gRPC callers.
    /// </summary>
    public bool EmitHttpCompatHeaders { get; set; } = true;

    /// <summary>Effective management port — <see cref="ManagementPort"/> or <see cref="PublicPort"/>.</summary>
    public int EffectiveManagementPort => ManagementPort ?? PublicPort;
}
