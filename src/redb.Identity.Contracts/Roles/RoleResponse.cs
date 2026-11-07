using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Roles;

public sealed class RoleResponse
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>"organization" or "application".</summary>
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = "organization";

    [JsonPropertyName("applicationId")]
    public long? ApplicationId { get; set; }

    [JsonPropertyName("applicationName")]
    public string? ApplicationName { get; set; }

    [JsonPropertyName("isSystem")]
    public bool IsSystem { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset? CreatedAt { get; set; }

    [JsonPropertyName("modifiedAt")]
    public DateTimeOffset? ModifiedAt { get; set; }

    /// <summary>
    /// B.3 list page — count of total assignments (users + groups). Null
    /// when the response was returned by a non-list path.
    /// </summary>
    [JsonPropertyName("assignmentCount")]
    public int? AssignmentCount { get; set; }
}
