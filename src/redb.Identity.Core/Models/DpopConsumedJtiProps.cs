using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// Z4 (RFC 9449 §11.1): persisted marker for a consumed DPoP proof <c>jti</c>.
/// Used by the <c>redb</c> replay-store backend to provide cluster-safe replay
/// detection when in-process Memory store is insufficient.
/// <para>
/// The composite primary lookup key is <c>(Jkt, Jti)</c> — the jkt scoping prevents
/// distinct clients with colliding (cryptographically improbable but possible) jti
/// values from being treated as replays of each other. Cleanup runs from
/// <c>timer://identity-dpop-replay-cleanup</c> when <see cref="ExpiresAt"/> is past.
/// </para>
/// </summary>
[RedbScheme("identity.dpop_consumed_jti")]
public class DpopConsumedJtiProps
{
    /// <summary>JWK SHA-256 thumbprint (RFC 7638) of the proof's public key, base64url.</summary>
    public string Jkt { get; set; } = "";

    /// <summary>The <c>jti</c> claim from the DPoP proof JWT.</summary>
    public string Jti { get; set; } = "";

    /// <summary>When the proof was consumed (UTC).</summary>
    public DateTimeOffset ConsumedAt { get; set; }

    /// <summary>Absolute expiry — eligible for cleanup when past.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
