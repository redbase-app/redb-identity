using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Roles;

public sealed class CreateRoleRequest
{
    [Required(AllowEmptyStrings = false)]
    [StringLength(60, MinimumLength = 1)]
    [JsonPropertyName("name")]
    public required string Name { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>"organization" (default) or "application".</summary>
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = "organization";

    /// <summary>Required when Audience='application'. Null for organization.</summary>
    [JsonPropertyName("applicationId")]
    public long? ApplicationId { get; set; }
}
