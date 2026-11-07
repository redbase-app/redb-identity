using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 Group resource (RFC 7643 §4.2).
/// </summary>
public class ScimGroup
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.GroupSchema];

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; set; }

    [JsonPropertyName("externalId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExternalId { get; set; }

    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; } = null!;

    [JsonPropertyName("members")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ScimMemberRef>? Members { get; set; }

    [JsonPropertyName("meta")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ScimMeta? Meta { get; set; }
}
