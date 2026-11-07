using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.ClaimMappers;

/// <summary>
/// H5: Create a new <c>identity.claim_mapper</c> PROPS row. Scope is determined by
/// <see cref="ParentId"/>: <c>null</c> for global; ApplicationId for per-app overlay;
/// ClaimScopeId for a Client Scope rule.
/// </summary>
public sealed class CreateClaimMapperRequest
{
    /// <summary>Administrator-facing label (stored in <c>name</c>).</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "name is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Claim type emitted into the token.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "claimType is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("claimType")]
    public string ClaimType { get; set; } = string.Empty;

    /// <summary>Source kind. One of: <c>Constant</c>, <c>CustomClaim</c>, <c>UserProps</c>.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "sourceKind is required.")]
    [JsonPropertyName("sourceKind")]
    public string SourceKind { get; set; } = string.Empty;

    /// <summary>Path or key into the source. Required for <c>CustomClaim</c> / <c>UserProps</c>.</summary>
    [JsonPropertyName("sourcePath")]
    public string? SourcePath { get; set; }

    /// <summary>Constant value emitted when <see cref="SourceKind"/> = <c>Constant</c>.</summary>
    [JsonPropertyName("constantValue")]
    public string? ConstantValue { get; set; }

    /// <summary>Required scopes (subset) for the mapper to fire.</summary>
    [JsonPropertyName("requiredScopes")]
    public string[]? RequiredScopes { get; set; }

    /// <summary>Token destinations: <c>access_token</c>, <c>id_token</c>. Empty defaults to both.</summary>
    [JsonPropertyName("destinations")]
    public string[]? Destinations { get; set; }

    /// <summary>When true, missing source value rejects token issuance with <c>invalid_request</c>.</summary>
    [JsonPropertyName("required")]
    public bool Required { get; set; }

    /// <summary>Application order ascending; last-write-wins by claim type.</summary>
    [JsonPropertyName("order")]
    public int Order { get; set; }

    /// <summary>When false, mapper is loaded but skipped at apply-time.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>Free-form description.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Owner discriminator: <c>null</c> = global, <c>application:{id}</c> per-app overlay,
    /// <c>scope:{id}</c> for a Client Scope. The processor parses this and sets
    /// <c>parent_id</c> accordingly.
    /// </summary>
    [JsonPropertyName("owner")]
    public string? Owner { get; set; }
}
