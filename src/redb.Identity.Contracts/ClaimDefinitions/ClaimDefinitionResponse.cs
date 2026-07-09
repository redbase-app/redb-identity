using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimDefinitions;

/// <summary>
/// S2 — admin read DTO for a claim definition. See
/// <c>redb.Identity.Core.Models.ClaimDefinitionProps</c> for the schema
/// rationale and the three-mechanism overview (mappers + per-user storage +
/// definitions).
/// </summary>
public sealed class ClaimDefinitionResponse
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("claimName")]
    public string ClaimName { get; set; } = "";

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = "string";

    [JsonPropertyName("required")]
    public bool Required { get; set; }

    [JsonPropertyName("defaultValue")]
    public string? DefaultValue { get; set; }

    [JsonPropertyName("validationPattern")]
    public string? ValidationPattern { get; set; }

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = "global";

    [JsonPropertyName("applicationId")]
    public long? ApplicationId { get; set; }

    [JsonPropertyName("emitOnIdToken")]
    public bool EmitOnIdToken { get; set; } = true;

    [JsonPropertyName("emitOnAccessToken")]
    public bool EmitOnAccessToken { get; set; } = true;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }

    [JsonPropertyName("modifiedAt")]
    public DateTimeOffset ModifiedAt { get; set; }
}
