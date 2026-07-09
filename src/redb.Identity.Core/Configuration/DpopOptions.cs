namespace redb.Identity.Core.Configuration;

/// <summary>
/// Z4 (RFC 9449): Demonstrating Proof-of-Possession at the Application Layer.
/// Configures DPoP proof validation and replay prevention for the Identity server's
/// token endpoint. When <see cref="Enabled"/> = false, all DPoP headers are ignored
/// and access tokens are issued as plain bearer tokens.
/// <para>
/// <b>Default policy:</b> SOFT — clients MAY send a DPoP proof; absence of one yields
/// a normal bearer token. Per-client strict enforcement is opt-in via
/// <c>ApplicationProps.RequireDpop</c> (when present) or via
/// <see cref="RequireForAccessTokens"/>=true (server-wide).
/// </para>
/// </summary>
public sealed class DpopOptions
{
    /// <summary>
    /// Master switch for DPoP support (validation + cnf.jkt binding + discovery).
    /// Default: false.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// When <c>true</c>, every access-token request MUST present a valid DPoP proof
    /// or be rejected with <c>invalid_dpop_proof</c>. Default: false (soft mode —
    /// clients opt-in by sending the header).
    /// </summary>
    public bool RequireForAccessTokens { get; set; }

    /// <summary>
    /// Allowed JWS algorithms in DPoP proofs. RFC 9449 §4.2 mandates asymmetric
    /// algorithms only. Defaults to ES256, ES384, RS256, PS256.
    /// </summary>
    public string[] AllowedSigningAlgorithms { get; set; } =
        ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

    /// <summary>
    /// Maximum age of the <c>iat</c> claim in seconds (clock-skew + transit tolerance).
    /// RFC 9449 §11.1 recommends a small window. Default: 60 seconds.
    /// </summary>
    public int IatToleranceSeconds { get; set; } = 60;

    /// <summary>
    /// Replay-store backend selector — see <see cref="DpopReplayStoreOptions"/>.
    /// </summary>
    public DpopReplayStoreOptions ReplayStore { get; set; } = new();

    /// <summary>
    /// Z4 P2 (RFC 9449 §8): when <c>true</c>, every DPoP proof MUST carry a valid
    /// server-issued <c>nonce</c> claim, and proofs without one are rejected with
    /// <c>use_dpop_nonce</c> + <c>DPoP-Nonce</c> response header. Default: false.
    /// </summary>
    public bool RequireNonce { get; set; }

    /// <summary>
    /// Z4 P2 (RFC 9449 §8): nonce validity window for stateless HMAC nonces. The
    /// server emits a fresh nonce on every response; clients have this much time to
    /// reuse it before they MUST request a new one. Default: 5 minutes.
    /// </summary>
    public TimeSpan NonceLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Z4 P2 (RFC 9449 §8): override secret used to sign stateless HMAC nonces.
    /// When unset, a process-stable random secret is generated at startup so a
    /// cluster of servers will not honour each other's nonces unless this is
    /// pinned to a shared value (e.g. via <c>IConfiguration</c>).
    /// </summary>
    public string? NonceSigningSecret { get; set; }
}

/// <summary>
/// Replay-store configuration for DPoP proof <c>jti</c> de-duplication.
/// <para>
/// <b>SECURITY:</b> the in-process Memory backend is single-instance only. In
/// multi-node deployments behind a load balancer the same DPoP proof can land on
/// different nodes, defeating replay protection. <b>Switch to <c>redis</c> or
/// <c>redb</c> for any multi-instance setup.</b>
/// </para>
/// </summary>
public sealed class DpopReplayStoreOptions
{
    /// <summary>
    /// Backend identifier — <c>memory</c> (default), <c>redis</c>, or <c>redb</c>.
    /// </summary>
    public string Backend { get; set; } = "memory";

    /// <summary>
    /// Connection string for the Redis backend. Falls back to
    /// <see cref="RedbIdentityOptions.RateLimit"/>'s Redis CS when omitted.
    /// </summary>
    public string? RedisConnectionString { get; set; }

    /// <summary>Key prefix for Redis entries. Default: <c>identity:dpop:jti:</c>.</summary>
    public string RedisKeyPrefix { get; set; } = "identity:dpop:jti:";

    /// <summary>
    /// Sweep interval for the in-memory backend (cleanup of expired entries).
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan MemorySweepInterval { get; set; } = TimeSpan.FromMinutes(5);
}
