namespace redb.Identity.Core.Services;

/// <summary>
/// Z4 (RFC 9449 §11.1): DPoP proof <c>jti</c> replay-prevention store.
/// Implementations MUST atomically reserve a <c>(jkt, jti)</c> pair so that a
/// concurrent replay attempt sees the prior reservation and is rejected.
/// </summary>
public interface IDpopReplayStore
{
    /// <summary>
    /// Attempts to reserve the given <paramref name="jti"/> bound to the proof's
    /// <paramref name="jkt"/> for the duration of <paramref name="ttl"/>.
    /// </summary>
    /// <param name="jkt">Base64url-encoded JWK SHA-256 thumbprint (RFC 7638) of the
    /// proof's public key. Scoping the reservation by jkt prevents cross-client jti
    /// collisions from being treated as replays.</param>
    /// <param name="jti">The <c>jti</c> claim from the DPoP proof.</param>
    /// <param name="ttl">Reservation TTL — typically the iat-tolerance window.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// <c>true</c> if the jti was newly reserved (proof is fresh);
    /// <c>false</c> if a prior reservation exists (proof is a replay).
    /// </returns>
    Task<bool> TryReserveAsync(string jkt, string jti, TimeSpan ttl, CancellationToken ct = default);
}
