using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 error response (RFC 7644 §3.12).
/// </summary>
public class ScimError
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.ErrorSchema];

    /// <summary>HTTP status code as string, e.g. "404".</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = null!;

    /// <summary>SCIM detail error type (RFC 7644 §3.12 Table 9), e.g. "uniqueness", "mutability".</summary>
    [JsonPropertyName("scimType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ScimType { get; set; }

    /// <summary>Human-readable error detail.</summary>
    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }
}
