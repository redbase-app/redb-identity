using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimMappers;

/// <summary>H5: Update an existing claim mapper. Owner / scope is immutable post-creation.</summary>
public sealed class UpdateClaimMapperRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "id is required.")]
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
    public bool? Required { get; set; }

    [JsonPropertyName("order")]
    public int? Order { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
