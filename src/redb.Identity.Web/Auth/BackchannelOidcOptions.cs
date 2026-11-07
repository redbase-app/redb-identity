namespace redb.Identity.Web.Auth;

/// <summary>
/// Options for the BFF-side backchannel OIDC client. The browser interacts only with
/// the BFF; the BFF talks server-to-server with the Identity host to perform the
/// authorization-code + PKCE handshake on behalf of the user.
/// </summary>
public sealed class BackchannelOidcOptions
{
    /// <summary>Base URL of the Identity host (e.g. <c>http://127.0.0.1:8080</c>).
    /// All backchannel paths (<c>/login</c>, <c>/connect/authorize</c>, <c>/connect/token</c>) are relative to this.</summary>
    public string Authority { get; set; } = "";

    /// <summary>Public client_id registered on the host (PKCE-only, no secret).</summary>
    public string ClientId { get; set; } = "identity-web";

    /// <summary>Optional client secret (only set when the host treats the client as confidential).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Scopes requested in the authorization request.</summary>
    /// <remarks>
    /// B-3 (PHASE-2): <c>identity:account</c> is required for self-service grants
    /// (<c>GrantMyConsentAsync</c>, MeConsentsProcessor). Without it the BFF-issued
    /// access token would be rejected by the host's scope check on those endpoints.
    /// </remarks>
    public string[] Scopes { get; set; } = ["openid", "profile", "email", "roles", "offline_access", "identity:manage", "identity:account"];

    /// <summary>Public callback URL the host redirects to with <c>?code=...</c>.
    /// In the backchannel design this is never actually rendered in a browser — the
    /// BFF intercepts the redirect itself — but it must still be a registered redirect_uri
    /// on the host because OpenIddict validates it.</summary>
    public string RedirectUri { get; set; } = "https://localhost:7000/signin-oidc";

    /// <summary>How long the BFF keeps the in-flight PKCE state cached.</summary>
    public TimeSpan FlowTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>DEV ONLY. Accept ANY server certificate on the session HttpClients this class
    /// builds by hand (they bypass IHttpClientFactory, so the app-wide accept-any-cert default
    /// configured in Program.cs does NOT reach them). Mirrors Identity:AcceptAnyBackchannelCert;
    /// needed when the host presents the bundled self-signed dev cert on localhost.</summary>
    public bool AcceptAnyServerCert { get; set; }
}
