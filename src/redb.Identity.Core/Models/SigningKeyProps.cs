using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS Props for persistent OpenIddict signing / encryption keys (A3).
/// One row per key; the active key for signing new tokens is the row with
/// <see cref="IsActive"/> = true and <see cref="KeyKind"/> = "signing"; older keys remain in
/// the JWKS (and in OpenIddict's credential list) until <see cref="NotAfter"/> so that
/// tokens signed by them continue to validate through the rotation-overlap window.
/// <para>
/// <see cref="EncryptedPem"/> is produced by <c>IDataProtector.Protect</c> over the raw PEM
/// bytes with purpose <c>redb.identity.signing-keys.v1</c>. This reuses the
/// <c>RedbXmlRepository</c> DataProtection key ring that is loaded earlier in the route
/// lifecycle, which means the key ring MUST be seeded first
/// (<c>RedbXmlRepositoryInitListener</c> runs before <c>SigningKeyInitListener</c> in
/// <c>InitRoute.main</c>).
/// </para>
/// </summary>
[RedbScheme("identity.signing_key")]
public class SigningKeyProps
{
    /// <summary>Unique key id (URL-safe).</summary>
    public string Kid { get; set; } = "";

    /// <summary>"signing" or "encryption".</summary>
    public string KeyKind { get; set; } = "";

    /// <summary>JWS/JWE algorithm identifier (e.g. RS256, RSA-OAEP).</summary>
    public string Algorithm { get; set; } = "";

    /// <summary>DataProtection-protected PEM-encoded private key (base64).</summary>
    public string EncryptedPem { get; set; } = "";

    /// <summary>Earliest UTC time the key may be used to sign / encrypt.</summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>Latest UTC time the key may be used to validate / decrypt. Past this, drop from JWKS.</summary>
    public DateTimeOffset NotAfter { get; set; }

    /// <summary>
    /// True for the single current key used to sign / encrypt new tokens. Older keys remain
    /// <see cref="IsActive"/> = false but are still exposed in the JWKS / credentials list
    /// until <see cref="NotAfter"/>.
    /// </summary>
    public bool IsActive { get; set; }
}
