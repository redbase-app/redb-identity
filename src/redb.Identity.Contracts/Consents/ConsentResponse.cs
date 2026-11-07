using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Consents;

/// <summary>
/// Consent grant record returned by the management API.
/// </summary>
public sealed class ConsentResponse
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("userId")]
    public long UserId { get; set; }

    [JsonPropertyName("applicationId")]
    public long ApplicationId { get; set; }

    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }

    [JsonPropertyName("applicationName")]
    public string? ApplicationName { get; set; }

    [JsonPropertyName("scopes")]
    public string[]? Scopes { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }
}
