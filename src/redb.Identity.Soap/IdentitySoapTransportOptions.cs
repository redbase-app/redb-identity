using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Soap;

/// <summary>
/// Configuration for the Identity WS-Trust facade. Mirrors the HTTP and gRPC transport options in shape
/// so operators configure every facade the same way: transport-local settings here, cross-module state
/// through <c>direct-vm://</c> into Core.
/// </summary>
public class IdentitySoapTransportOptions
{
    /// <summary>SOAP-specific transport settings (path, port, TLS).</summary>
    public SoapTransportOptions Soap { get; set; } = new();

    /// <summary>
    /// Cross-module shared options (Issuer + Features). Same instance type as
    /// <c>RedbIdentityOptions.Shared</c>, so a value declared once in <c>Identity:*</c> is observed
    /// identically by Core and by every facade.
    /// </summary>
    public IdentitySharedOptions Shared { get; set; } = new();

    /// <summary>Issuer URI of the identity server. Proxy onto <see cref="Shared"/>.</summary>
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

/// <summary>WS-Trust listener settings.</summary>
public class SoapTransportOptions
{
    /// <summary>Bind address. Default <c>0.0.0.0</c>.</summary>
    public string Host { get; set; } = "0.0.0.0";

    /// <summary>
    /// Port of the security token service. Default 5021.
    /// <para>
    /// Kept off the HTTP facade's port by default. SOAP is ordinary HTTP/1.1 and could technically share
    /// a host, unlike gRPC which needs HTTP/2; the separation here buys something else: WS-Trust can be
    /// closed off from the internet while plain OIDC stays open, and the two surfaces get their own
    /// limits and their own suspend switch.
    /// </para>
    /// </summary>
    public int Port { get; set; } = 5021;

    /// <summary>Path the STS answers on. Default <c>/sts</c>.</summary>
    public string Path { get; set; } = "/sts";

    /// <summary>
    /// TLS. Unlike the other facades this is not merely recommended: <c>UsernameToken</c> carries the
    /// client secret in clear text unless the digest form is used, so the facade refuses to start
    /// without TLS. See <see cref="AllowPlaintext"/> for the single escape hatch.
    /// </summary>
    public bool Ssl { get; set; } = true;

    /// <summary>Path to the PFX certificate used when <see cref="Ssl"/> is true.</summary>
    public string? SslCertPath { get; set; }

    /// <summary>Password for <see cref="SslCertPath"/>.</summary>
    public string? SslCertPassword { get; set; }

    /// <summary>
    /// Starts the facade without TLS. Off by default, and deliberately awkward to reach: it exists for
    /// a local run behind a terminating proxy, and it is the operator's statement that the wire is
    /// already protected. With <c>Ssl = false</c> and this flag unset the facade refuses to start rather
    /// than quietly serving credentials in clear text.
    /// </summary>
    public bool AllowPlaintext { get; set; }

    /// <summary>
    /// Client-certificate policy (mTLS): <c>NoCertificate</c> (default), <c>AllowCertificate</c> or
    /// <c>RequireCertificate</c>. Off by default so deployments without a client-certificate PKI are not
    /// blocked; the natural choice for an STS in a closed contour is to require one.
    /// </summary>
    public string ClientCertificateMode { get; set; } = "NoCertificate";

    /// <summary>
    /// Comma-separated SHA-1 thumbprints of accepted client certificates. When set, a certificate whose
    /// thumbprint is not listed is rejected even if its chain validates.
    /// </summary>
    public string? AllowedClientThumbprints { get; set; }

    /// <summary>
    /// Serve the WSDL on GET. Default true: the audience for this facade builds its clients with
    /// generators, and a generator needs a document to read.
    /// </summary>
    public bool Wsdl { get; set; } = true;

    /// <summary>
    /// Mirror the resolved client address into <c>redbHttp.RemoteAddress</c> so the IP-keyed processors
    /// in Core (per-IP throttle, brute-force lockout, device metadata) work behind this facade unchanged.
    /// Default true: without it those protections silently do nothing rather than failing loudly.
    /// </summary>
    public bool EmitHttpCompatHeaders { get; set; } = true;
}
