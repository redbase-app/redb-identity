using System.Text.Json;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 PATCH request (RFC 7644 §3.5.2).
/// </summary>
public class ScimPatchRequest
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.PatchOpSchema];

    [JsonPropertyName("Operations")]
    public List<ScimPatchOperation> Operations { get; set; } = [];
}

/// <summary>
/// Single PATCH operation (RFC 7644 §3.5.2).
/// </summary>
public class ScimPatchOperation
{
    /// <summary>"add", "replace", or "remove".</summary>
    [JsonPropertyName("op")]
    public string Op { get; set; } = null!;

    /// <summary>Attribute path, e.g. "displayName", "members", "members[value eq \"123\"]".</summary>
    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }

    /// <summary>Value to apply. Can be a primitive, object, or array.</summary>
    [JsonPropertyName("value")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Value { get; set; }
}
