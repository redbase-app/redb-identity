using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scopes;

public sealed class UpdateScopeRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "id is required.")]
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("resources")]
    public string[]? Resources { get; set; }

    [JsonPropertyName("concurrencyToken")]
    public string? ConcurrencyToken { get; set; }
}
