using Microsoft.IdentityModel.Tokens;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Resolves the public signing keys of a <b>client application</b> — the keys used to verify
/// something the client signed (a JAR request object per RFC 9101, a <c>private_key_jwt</c>
/// client assertion per RFC 7523).
/// <para>
/// Two sources, in this order:
/// <list type="number">
///   <item>inline <see cref="ApplicationProps.JsonWebKeySet"/> — the JWKS pasted into the client record;</item>
///   <item><see cref="ApplicationProps.JwksUri"/> — an absolute HTTPS URL fetched and cached.</item>
/// </list>
/// They are mutually exclusive by the admin UI's contract (see <see cref="ApplicationProps.JwksUri"/>),
/// but if both are present the inline set wins: it is operator-controlled and needs no network call.
/// </para>
/// <para>
/// <b>Asymmetric only.</b> HMAC (<c>HS*</c>) cannot be supported: <see cref="ApplicationProps.ClientSecret"/>
/// stores a <b>BCrypt hash</b>, and verifying an HMAC signature needs the original secret, which is
/// unrecoverable by design. FAPI 2.0 forbids <c>HS*</c> for request objects anyway and mandates
/// <c>PS256</c>/<c>ES256</c>, so this is a correctness boundary rather than a gap.
/// </para>
/// </summary>
public interface IClientKeyResolver
{
    /// <summary>
    /// Returns the client's public signing keys, or an empty collection when the client has
    /// published none (no inline JWKS and no reachable <c>jwks_uri</c>).
    /// </summary>
    /// <param name="application">The client application record.</param>
    /// <param name="forceRefresh">
    /// When <see langword="true"/>, bypasses the cached copy of a <c>jwks_uri</c> document and
    /// re-fetches it. Used for a single retry after a <c>kid</c> miss, so that a client rotating
    /// its keys does not break sign-in until the cache expires. Never set it on the first attempt —
    /// an unauthenticated caller must not be able to trigger outbound fetches at will.
    /// </param>
    /// <returns>Keys suitable for signature verification; never <see langword="null"/>.</returns>
    ValueTask<IReadOnlyCollection<SecurityKey>> GetSigningKeysAsync(
        RedbObject<ApplicationProps> application,
        bool forceRefresh = false,
        CancellationToken cancellationToken = default);
}
