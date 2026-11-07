namespace redb.Identity.Client.Backchannel;

/// <summary>
/// Configuration for the service-to-service backchannel identity client
/// (W6-0). Holds <c>client_credentials</c> creds for the dedicated service
/// account that publishes/polls revoked-sids on behalf of a Web BFF.
/// </summary>
public sealed class BackchannelIdentityClientOptions
{
    /// <summary>Base URL of the Identity HTTP API (same authority that issues tokens).</summary>
    public Uri BaseUrl { get; set; } = new("https://localhost/");

    /// <summary>Client_id of the backchannel service account.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client_secret of the backchannel service account.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Scopes requested via <c>client_credentials</c>. Defaults to <c>identity:manage</c>.</summary>
    public string[] Scopes { get; set; } = ["identity:manage"];

    /// <summary>Per-request timeout. Default 30s.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}
