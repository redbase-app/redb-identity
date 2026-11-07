using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Roles;

/// <summary>
/// B.3 — a single assignment row, surfaces both directions:
///   * "for role X, who has it?" — list assignees with kind='user'/'group';
///   * "what roles does user/group Y have?" — list roles with role + audience.
/// </summary>
public sealed class RoleAssignmentResponse
{
    [JsonPropertyName("roleId")]
    public long RoleId { get; set; }

    [JsonPropertyName("roleName")]
    public string RoleName { get; set; } = "";

    [JsonPropertyName("audience")]
    public string Audience { get; set; } = "organization";

    [JsonPropertyName("applicationId")]
    public long? ApplicationId { get; set; }

    /// <summary>"user" or "group".</summary>
    [JsonPropertyName("subjectKind")]
    public string SubjectKind { get; set; } = "user";

    [JsonPropertyName("subjectId")]
    public long SubjectId { get; set; }

    [JsonPropertyName("subjectLabel")]
    public string? SubjectLabel { get; set; }

    [JsonPropertyName("assignedAt")]
    public DateTimeOffset AssignedAt { get; set; }

    [JsonPropertyName("assignedByUserId")]
    public long? AssignedByUserId { get; set; }
}
