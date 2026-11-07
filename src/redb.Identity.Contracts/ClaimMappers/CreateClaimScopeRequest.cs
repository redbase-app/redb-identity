using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimMappers;

/// <summary>H5: Create a reusable Client Scope (named bundle of claim mappers).</summary>
public sealed class CreateClaimScopeRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "name is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;
}
