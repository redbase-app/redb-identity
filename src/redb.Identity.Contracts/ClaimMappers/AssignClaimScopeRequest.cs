using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimMappers;

/// <summary>H5: Assign a Client Scope to an Application.</summary>
public sealed class AssignClaimScopeRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "applicationId is required.")]
    [JsonPropertyName("applicationId")]
    public string ApplicationId { get; set; } = string.Empty;

    [Required(AllowEmptyStrings = false, ErrorMessage = "scopeId is required.")]
    [JsonPropertyName("scopeId")]
    public string ScopeId { get; set; } = string.Empty;
}

public sealed class ClaimScopeAssignmentResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("applicationId")]
    public string ApplicationId { get; set; } = string.Empty;

    [JsonPropertyName("scopeId")]
    public string ScopeId { get; set; } = string.Empty;

    [JsonPropertyName("scopeName")]
    public string? ScopeName { get; set; }

    [JsonPropertyName("assignedAt")]
    public DateTimeOffset AssignedAt { get; set; }

    [JsonPropertyName("assignedBy")]
    public string? AssignedBy { get; set; }
}
