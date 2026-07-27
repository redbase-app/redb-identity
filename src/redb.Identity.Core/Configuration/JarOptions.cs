namespace redb.Identity.Core.Configuration;

/// <summary>
/// How strictly a client's declared <c>request_object_signing_alg</c> is enforced once
/// JAR (RFC 9101) is switched on.
/// </summary>
public enum JarEnforcementMode
{
    /// <summary>
    /// The declared algorithm is ignored: any algorithm this server supports is accepted,
    /// as long as the signature itself verifies.
    /// </summary>
    Off,

    /// <summary>
    /// A mismatch is logged as a warning and the request proceeds. Use this to find out who
    /// would break <b>before</b> switching to <see cref="Enforce"/> — the values were editable
    /// long before anything read them, so some are guesses rather than statements of fact.
    /// </summary>
    LogOnly,

    /// <summary>
    /// A mismatch is rejected with <c>invalid_request_object</c>. The intended end state.
    /// </summary>
    Enforce,
}

/// <summary>
/// JAR (RFC 9101) — JWT-Secured Authorization Request. Applies only when
/// <c>Features.EnableJar</c> is <see langword="true"/>.
/// </summary>
public sealed class JarOptions
{
    /// <summary>
    /// How to treat a mismatch between the request object's <c>alg</c> and the client's stored
    /// <c>RequestObjectSigningAlg</c>. Default: <see cref="JarEnforcementMode.LogOnly"/>.
    /// <para>
    /// The default is deliberately not <see cref="JarEnforcementMode.Enforce"/>. Those per-client
    /// values were accepted by the admin API and UI for releases while nothing enforced them, so an
    /// existing deployment may hold values nobody verified. Starting in <c>LogOnly</c> surfaces the
    /// mismatches in the log instead of turning them into sign-in failures on upgrade day.
    /// </para>
    /// </summary>
    public JarEnforcementMode EnforcementMode { get; set; } = JarEnforcementMode.LogOnly;

    /// <summary>
    /// Signature algorithms accepted on a request object. Asymmetric only — see
    /// <c>IClientKeyResolver</c> for why <c>HS*</c> cannot work here (the client secret is
    /// stored as a BCrypt hash). <c>none</c> is never accepted and cannot be added.
    /// </summary>
    public string[] AllowedSigningAlgorithms { get; set; } =
        ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    /// <summary>
    /// Clock-skew tolerance when checking <c>exp</c> / <c>nbf</c> / <c>iat</c>. Default: 60 seconds.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Maximum accepted size of the <c>request</c> parameter in characters. Default: 50 000.
    /// A real request object is a few hundred bytes; the cap keeps a hostile client from making
    /// us parse megabytes on an unauthenticated endpoint.
    /// </summary>
    public int MaxRequestObjectLength { get; set; } = 50_000;

    /// <summary>
    /// Require that <c>exp</c> be present. RFC 9101 §4 lists it as required; some clients omit it.
    /// Default: <see langword="true"/> — without an expiry a captured request object stays
    /// replayable forever.
    /// </summary>
    public bool RequireExpiration { get; set; } = true;

    /// <summary>
    /// Accept a <c>request_uri</c> parameter (the request object by reference, fetched over HTTP)
    /// in addition to an inline <c>request</c>. Default: <see langword="true"/> when JAR is on.
    /// <para>
    /// PAR's <c>urn:ietf:params:oauth:request_uri:*</c> values are never affected by this — those
    /// are resolved by the PAR pipeline, not fetched.
    /// </para>
    /// </summary>
    public bool EnableRequestUri { get; set; } = true;

    /// <summary>
    /// Timeout for fetching a <c>request_uri</c>. Default: 5 seconds — an authorization request is
    /// blocked on it.
    /// </summary>
    public TimeSpan RequestUriFetchTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Require <c>https</c> for a <c>request_uri</c>. Default: <see langword="true"/>. Over plain
    /// HTTP the request object could be swapped in transit, defeating the signature it carries.
    /// Relax only for local development.
    /// </summary>
    public bool RequestUriRequireHttps { get; set; } = true;

    /// <summary>
    /// Allow a <c>request_uri</c> to resolve to a non-public address (loopback, private, link-local).
    /// Default: <see langword="false"/> — the URL comes from the client, so an internal target is an
    /// SSRF attempt. Enable only for local development / integration tests.
    /// </summary>
    public bool RequestUriAllowPrivateNetworkTargets { get; set; }
}
