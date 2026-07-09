using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Webhooks;

public sealed class CreateWebhookSubscriptionRequest
{
    [Required(AllowEmptyStrings = false)]
    [JsonPropertyName("url")]
    public required string Url { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>"*" (default) or comma-separated event ids / cat: tokens.</summary>
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

    /// <summary>
    /// Optional operator-supplied HMAC secret. When omitted the server
    /// generates a 256-bit random secret. When supplied, must be at least
    /// 16 chars (basic strength check).
    /// </summary>
    [JsonPropertyName("hmacSecret")]
    public string? HmacSecret { get; set; }
}
