using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.SigningKeys;

/// <summary>
/// One row of the signing-key store as exposed by the admin /signing-keys list endpoint.
/// The private material is intentionally never surfaced; only the kid, algorithm metadata,
/// validity window, and active flag travel on the wire.
/// </summary>
public sealed class SigningKeyResponse
{
    [JsonPropertyName("kid")]
    public string Kid { get; set; } = "";

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "";

    [JsonPropertyName("notBefore")]
    public DateTimeOffset NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    public DateTimeOffset NotAfter { get; set; }

    /// <summary>
    /// <c>true</c> when this key is what OpenIddict picks for NEW token signing. Multiple
    /// keys can have <c>NotAfter &gt; now</c> at once (rotation grace window) but at most
    /// one of any given <c>Kind</c> is <c>IsActive=true</c>.
    /// </summary>
    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; }

    /// <summary>
    /// <c>true</c> when this row is still inside its validity window
    /// (<see cref="NotAfter"/> &gt; now) and therefore still appears in the live JWKS.
    /// </summary>
    [JsonPropertyName("inJwks")]
    public bool InJwks { get; set; }
}

/// <summary>Response shape for <c>GET /signing-keys</c>.</summary>
public sealed class SigningKeyListResponse
{
    [JsonPropertyName("keys")]
    public List<SigningKeyResponse> Keys { get; set; } = [];
}

/// <summary>Request shape for <c>POST /signing-keys/rotate</c>.</summary>
public sealed class RotateSigningKeyRequest
{
    /// <summary>
    /// Key kind to rotate. Currently supported: <c>"signing"</c> (RSA / RS256) and
    /// <c>"encryption"</c> (RSA / RSA-OAEP). Defaults to <c>"signing"</c> when omitted.
    /// </summary>
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }
}
