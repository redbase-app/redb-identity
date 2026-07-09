using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Sessions;

/// <summary>
/// Session record returned by the management API.
/// </summary>
public sealed class SessionResponse
{
    [JsonPropertyName("sessionId")]
    public long SessionId { get; set; }

    [JsonPropertyName("userId")]
    public long UserId { get; set; }

    /// <summary>Login of the session owner — populated by the admin list / list-all paths
    /// for table rendering. Null when the user no longer exists or lookup failed.</summary>
    [JsonPropertyName("userLogin")]
    public string? UserLogin { get; set; }

    [JsonPropertyName("applicationId")]
    public long ApplicationId { get; set; }

    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }

    [JsonPropertyName("applicationName")]
    public string? ApplicationName { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>Client IP captured at session creation (sanitized when behind a trusted proxy).</summary>
    [JsonPropertyName("ipAddress")]
    public string? IpAddress { get; set; }

    /// <summary>Raw <c>User-Agent</c> header at session creation.</summary>
    [JsonPropertyName("userAgent")]
    public string? UserAgent { get; set; }

    /// <summary>Human-friendly device label (e.g. "Chrome 135 on Windows 10").</summary>
    [JsonPropertyName("deviceLabel")]
    public string? DeviceLabel { get; set; }

    /// <summary>S-track: timestamp of the most recent token-refresh / cookie / userinfo activity.</summary>
    [JsonPropertyName("lastAccessedAt")]
    public DateTimeOffset? LastAccessedAt { get; set; }

    /// <summary>S-track: short label of the activity that bumped LastAccessedAt ("refresh_token", "cookie", …).</summary>
    [JsonPropertyName("lastAccessedBy")]
    public string? LastAccessedBy { get; set; }
}
