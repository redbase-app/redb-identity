using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class GroupResponse
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("groupType")]
    public string? GroupType { get; set; }

    [JsonPropertyName("parentId")]
    public long? ParentId { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset? CreatedAt { get; set; }

    [JsonPropertyName("modifiedAt")]
    public DateTimeOffset? ModifiedAt { get; set; }

    /// <summary>
    /// B.2 — populated by the list-page search response with the count of
    /// direct memberships, drives the per-row badge. Null when not requested.
    /// </summary>
    [JsonPropertyName("memberCount")]
    public int? MemberCount { get; set; }
}
