using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimDefinitions;

/// <summary>
/// S2 — admin create DTO. The (ClaimName, Scope, ApplicationId) triplet is
/// the uniqueness key; the server returns 409 on conflict.
/// </summary>
public sealed class CreateClaimDefinitionRequest
{
    [Required(AllowEmptyStrings = false)]
    [StringLength(120, MinimumLength = 1)]
    [JsonPropertyName("claimName")]
    public required string ClaimName { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>"string" (default) / "int" / "long" / "bool" / "datetime" / "url" / "email".</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = "string";

    [JsonPropertyName("required")]
    public bool Required { get; set; }

    [JsonPropertyName("defaultValue")]
    public string? DefaultValue { get; set; }

    /// <summary>Regex pattern; ignored for non-string types.</summary>
    [JsonPropertyName("validationPattern")]
    public string? ValidationPattern { get; set; }

    /// <summary>"global" (default) or "application".</summary>
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = "global";

    /// <summary>Required when Scope = "application"; null for global.</summary>
    [JsonPropertyName("applicationId")]
    public long? ApplicationId { get; set; }

    [JsonPropertyName("emitOnIdToken")]
    public bool EmitOnIdToken { get; set; } = true;

    [JsonPropertyName("emitOnAccessToken")]
    public bool EmitOnAccessToken { get; set; } = true;
}
