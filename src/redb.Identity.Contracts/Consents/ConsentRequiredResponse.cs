using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Consents;

/// <summary>
/// Machine-readable counterpart of the <c>consent_required</c> 302 redirect from
/// <c>/connect/authorize</c>. Returned with HTTP 400 + <c>error=consent_required</c>
/// when the caller signals <c>X-Identity-Delegate-Consent: 1</c> on the authorize
/// request. Lets BFFs render a native consent UI instead of bouncing the browser
/// to the host's HTML fallback page.
/// </summary>
public sealed class ConsentRequiredResponse
{
    /// <summary>Standard OAuth error code — always <c>consent_required</c> for this DTO.</summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = "consent_required";

    /// <summary>OAuth client_id of the relying application.</summary>
    [JsonPropertyName("clientId")]
    public string ClientId { get; set; } = "";

    /// <summary>Human-readable application name for the consent dialog.</summary>
    [JsonPropertyName("appName")]
    public string AppName { get; set; } = "";

    /// <summary>Scope identifiers the application is requesting.</summary>
    [JsonPropertyName("scopes")]
    public string[] Scopes { get; set; } = Array.Empty<string>();

    /// <summary>Subject (numeric user id as string) of the currently signed-in user.</summary>
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = "";

    /// <summary>Original authorize URL to resume after the user grants consent.</summary>
    [JsonPropertyName("returnUrl")]
    public string ReturnUrl { get; set; } = "";
}
