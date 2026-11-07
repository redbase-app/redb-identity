using System.Collections.Immutable;
using Microsoft.IdentityModel.Tokens;

namespace redb.Identity.Core.Keys;

/// <summary>
/// In-memory representation of a signing / encryption key loaded from PROPS storage
/// (<see cref="Models.SigningKeyProps"/>).
/// </summary>
public sealed record SigningKeyMaterial(
    string Kid,
    string KeyKind,
    string Algorithm,
    SecurityKey SecurityKey,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool IsActive);

/// <summary>
/// Persistent store for OpenIddict signing / encryption keys backed by redb PROPS
/// (<see cref="Models.SigningKeyProps"/>). A3 replaces ephemeral in-memory keys so that
/// cluster replicas share the same JWKS and tokens survive restarts.
/// </summary>
public interface ISigningKeyStore
{
    /// <summary>Returns all keys currently in the store with NotAfter still in the future (active + still-valid rotated-out).</summary>
    Task<ImmutableArray<SigningKeyMaterial>> GetAllAsync(CancellationToken ct = default);

    /// <summary>
    /// Returns every key row in the store, regardless of whether <see cref="SigningKeyMaterial.NotAfter"/>
    /// is in the past (i.e. including retired keys). Used by the admin /signing-keys list endpoint to
    /// surface the full audit trail; the JWKS endpoint must still use <see cref="GetAllAsync"/> so
    /// retired keys do not get advertised to RPs.
    /// </summary>
    Task<ImmutableArray<SigningKeyMaterial>> ListAllIncludingRetiredAsync(CancellationToken ct = default);

    /// <summary>
    /// Generates an initial active key for the given kind if the store contains no active key.
    /// Idempotent: once an active key of the requested kind exists, the call is a no-op.
    /// </summary>
    Task EnsureBootstrappedAsync(string keyKind, CancellationToken ct = default);

    /// <summary>
    /// Generates a fresh key of the given kind and marks every currently-active key of the same kind
    /// as inactive (so OpenIddict will pick the new one for future signing). The previously-active key
    /// is NOT retired — its <see cref="SigningKeyMaterial.NotAfter"/> is left untouched so RPs that
    /// cached the JWKS continue to validate any in-flight tokens that were signed with it. Call
    /// <see cref="RetireAsync"/> once the RP cache TTL (typically 1 h) has elapsed.
    /// </summary>
    /// <returns>The newly-created key material.</returns>
    Task<SigningKeyMaterial> RotateAsync(string keyKind, CancellationToken ct = default);

    /// <summary>
    /// Immediately ends the validity window of <paramref name="kid"/> by setting NotAfter to "now".
    /// The key disappears from JWKS on the next request. Tokens previously signed with this key will
    /// fail signature validation against the live JWKS — call this only after the rotation grace
    /// window has elapsed.
    /// </summary>
    /// <returns><c>true</c> when the key was found and retired; <c>false</c> when no key with that kid exists.</returns>
    Task<bool> RetireAsync(string kid, CancellationToken ct = default);
}
