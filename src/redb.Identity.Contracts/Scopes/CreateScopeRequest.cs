using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scopes;

public sealed class CreateScopeRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "name is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("resources")]
    public string[]? Resources { get; set; }
}
