namespace redb.Identity.Contracts.Configuration;

/// <summary>
/// Configuration for a single federated authentication provider (OIDC, etc.).
/// </summary>
public class FederationProviderConfig
{
    /// <summary>Provider ID used as dictionary key in ExternalIdentities. E.g. "google", "azure-ad".</summary>
    public required string ProviderId { get; set; }

    /// <summary>
    /// H8: provider kind. <c>"oidc"</c> (default) uses
    /// <c>OidcFederatedAuthProvider</c> and requires a working
    /// <c>.well-known/openid-configuration</c> at <see cref="Authority"/>.
    /// <c>"github"</c> uses <c>GitHubFederatedAuthProvider</c> (OAuth2 + REST,
    /// not OIDC). For <c>github</c> the <see cref="Authority"/> field is ignored.
    /// </summary>
    public string Kind { get; set; } = "oidc";

    /// <summary>Display name shown on the login page button. E.g. "Google", "Azure AD".</summary>
    public required string DisplayName { get; set; }

    /// <summary>OIDC issuer / authority URI. E.g. "https://accounts.google.com". Ignored for <c>Kind=github</c>.</summary>
    public required string Authority { get; set; }

    /// <summary>OAuth2 client_id registered with the external IdP.</summary>
    public required string ClientId { get; set; }

    /// <summary>OAuth2 client_secret registered with the external IdP.</summary>
    public required string ClientSecret { get; set; }

    /// <summary>Scopes to request. Default: openid, profile, email.</summary>
    public string[] Scopes { get; set; } = ["openid", "profile", "email"];

    /// <summary>Create a local user on first federated login. Default: true.</summary>
    public bool AutoProvision { get; set; } = true;

    /// <summary>Display order on login page. Lower = shown first. Default: 100.</summary>
    public int Priority { get; set; } = 100;

    /// <summary>Optional claim mappings: external claim type → internal claim type.</summary>
    public Dictionary<string, string>? ClaimMappings { get; set; }

    /// <summary>
    /// Optional endpoint overrides for non-OIDC OAuth2 providers (e.g. GitHub Enterprise,
    /// Gitea, self-hosted mock servers for testing). When <see cref="Kind"/> = <c>github</c>:
    /// the provider falls back to the public github.com URLs when this is <c>null</c> OR
    /// any individual field is unset; setting them all repoints the entire flow at a
    /// custom host without touching the provider implementation. Ignored for
    /// <c>Kind=oidc</c> (those use the OIDC discovery document at <see cref="Authority"/>).
    /// </summary>
    public OAuth2EndpointOverrides? Endpoints { get; set; }
}

/// <summary>
/// Per-provider override of the well-known OAuth2 endpoints used by
/// <see cref="FederationProviderConfig.Kind"/> = <c>github</c> (and future non-OIDC OAuth2
/// kinds). When any field is null the provider falls back to its built-in default for
/// the public github.com host.
/// </summary>
public sealed class OAuth2EndpointOverrides
{
    /// <summary>Authorization endpoint. Default for github: <c>https://github.com/login/oauth/authorize</c>.</summary>
    public string? AuthorizeEndpoint { get; set; }

    /// <summary>Token endpoint. Default for github: <c>https://github.com/login/oauth/access_token</c>.</summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>User profile endpoint. Default for github: <c>https://api.github.com/user</c>.</summary>
    public string? UserEndpoint { get; set; }

    /// <summary>User emails endpoint (only used when profile email is private). Default for github: <c>https://api.github.com/user/emails</c>.</summary>
    public string? EmailsEndpoint { get; set; }
}
