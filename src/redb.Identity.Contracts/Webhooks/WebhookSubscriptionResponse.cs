using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Webhooks;

public sealed class WebhookSubscriptionResponse
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("eventTypeFilter")]
    public string EventTypeFilter { get; set; } = "*";

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; set; }

    [JsonPropertyName("maxAttempts")]
    public int MaxAttempts { get; set; }

    [JsonPropertyName("retryBackoffMs")]
    public int RetryBackoffMs { get; set; }

    [JsonPropertyName("extraHeaders")]
    public Dictionary<string, string>? ExtraHeaders { get; set; }

    /// <summary>
    /// Plaintext HMAC secret — populated ONLY on the create response and
    /// the secret-rotate response. List / get / update never return it.
    /// </summary>
    [JsonPropertyName("hmacSecret")]
    public string? HmacSecret { get; set; }

    /// <summary>True after the first delivery / get / list response when the secret is server-resident only.</summary>
    [JsonPropertyName("hasHmacSecret")]
    public bool HasHmacSecret { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset? CreatedAt { get; set; }

    [JsonPropertyName("modifiedAt")]
    public DateTimeOffset? ModifiedAt { get; set; }
}
