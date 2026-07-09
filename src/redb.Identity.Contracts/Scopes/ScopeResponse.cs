using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scopes;

public sealed class ScopeResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("resources")]
    public string[]? Resources { get; set; }

    [JsonPropertyName("concurrencyToken")]
    public string? ConcurrencyToken { get; set; }
}
