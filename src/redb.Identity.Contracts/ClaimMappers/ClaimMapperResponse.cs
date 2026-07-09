using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimMappers;

public sealed class ClaimMapperResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("claimType")]
    public string? ClaimType { get; set; }

    [JsonPropertyName("sourceKind")]
    public string? SourceKind { get; set; }

    [JsonPropertyName("sourcePath")]
    public string? SourcePath { get; set; }

    [JsonPropertyName("constantValue")]
    public string? ConstantValue { get; set; }

    [JsonPropertyName("requiredScopes")]
    public string[]? RequiredScopes { get; set; }

    [JsonPropertyName("destinations")]
    public string[]? Destinations { get; set; }

    [JsonPropertyName("required")]
    public bool Required { get; set; }

    [JsonPropertyName("order")]
    public int Order { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Resolved owner: <c>"global"</c>, <c>"application:{id}"</c> or <c>"scope:{id}"</c>.
    /// </summary>
    [JsonPropertyName("owner")]
    public string Owner { get; set; } = "global";
}
