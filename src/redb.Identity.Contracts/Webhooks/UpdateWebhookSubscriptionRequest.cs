using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Webhooks;

/// <summary>
/// Null fields preserve existing values (PATCH semantics). HMAC secret is
/// managed through the dedicated rotate endpoint to keep the lifecycle
/// explicit and audit-friendly.
/// </summary>
public sealed class UpdateWebhookSubscriptionRequest
{
    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("eventTypeFilter")]
    public string? EventTypeFilter { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("timeoutMs")]
    public int? TimeoutMs { get; set; }

    [JsonPropertyName("maxAttempts")]
    public int? MaxAttempts { get; set; }

    [JsonPropertyName("retryBackoffMs")]
    public int? RetryBackoffMs { get; set; }

    [JsonPropertyName("extraHeaders")]
    public Dictionary<string, string>? ExtraHeaders { get; set; }
}
