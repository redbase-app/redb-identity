using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Applications;

public sealed class CreateApplicationRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "clientId is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("clientId")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("clientSecret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("clientType")]
    public string? ClientType { get; set; }

    [JsonPropertyName("consentType")]
    public string? ConsentType { get; set; }

    [JsonPropertyName("applicationType")]
    public string? ApplicationType { get; set; }

    [JsonPropertyName("permissions")]
    public string[]? Permissions { get; set; }

    [JsonPropertyName("redirectUris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("postLogoutRedirectUris")]
    public string[]? PostLogoutRedirectUris { get; set; }

    [JsonPropertyName("requirements")]
    public string[]? Requirements { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 endpoint. Absolute HTTPS (or http for
    /// localhost/dev) URL the server POSTs a signed <c>logout_token</c> to when
    /// the user's session is terminated. Stored on the application as the
    /// <c>backchannel_logout_uri</c> custom property.
    /// </summary>
    [JsonPropertyName("backchannelLogoutUri")]
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 — when true, the dispatched
    /// <c>logout_token</c> includes a <c>sid</c> claim so the RP can
    /// invalidate the matching session. Defaults to true (RFC-recommended)
    /// when <see cref="BackchannelLogoutUri"/> is set without an explicit
    /// value.
    /// </summary>
    [JsonPropertyName("backchannelLogoutSessionRequired")]
    public bool? BackchannelLogoutSessionRequired { get; set; }
}
