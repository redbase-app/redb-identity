using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimDefinitions;

/// <summary>
/// S2 — admin update DTO. Null fields leave the existing stored value
/// unchanged (PATCH semantics). ClaimName + Scope + ApplicationId are
/// IMMUTABLE post-create — rename / re-scope = delete + re-create.
/// </summary>
public sealed class UpdateClaimDefinitionRequest
{
    [Required]
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("required")]
    public bool? Required { get; set; }

    [JsonPropertyName("defaultValue")]
    public string? DefaultValue { get; set; }

    [JsonPropertyName("validationPattern")]
    public string? ValidationPattern { get; set; }

    [JsonPropertyName("emitOnIdToken")]
    public bool? EmitOnIdToken { get; set; }

    [JsonPropertyName("emitOnAccessToken")]
    public bool? EmitOnAccessToken { get; set; }
}
