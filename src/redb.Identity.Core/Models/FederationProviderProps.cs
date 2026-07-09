using redb.Core.Attributes;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Core.Models;

/// <summary>
/// H8 (v1.0 DoD §4 gap (e)): PROPS-stored configuration for a single federated authentication
/// provider. Mirrors <see cref="redb.Identity.Core.Configuration.FederationProviderConfig"/>
/// loaded from <c>appsettings.json</c>, but allows runtime CRUD via the admin API
/// (<c>/api/v1/identity/federation-providers</c>).
/// <para>
/// Storage:
/// <list type="bullet">
///   <item><c>RedbObject.value_string = ProviderId</c> — lowercase, UNIQUE per
///   <c>_id_scheme</c>. Enables O(1) lookup by provider id and rejects duplicates at the
///   DB level via the partial unique index.</item>
///   <item><see cref="ClientSecret"/> is stored encrypted via DataProtection
///   (<c>identity.federation-provider-secret</c> purpose) — admin API never returns the
///   plaintext, only metadata (`HasSecret: bool`).</item>
/// </list>
/// </para>
/// </summary>
[RedbScheme("identity.federation_provider")]
public class FederationProviderProps
{
    /// <summary>Provider id (slug). Mirrored to <c>RedbObject.value_string</c>. E.g. <c>google</c>.</summary>
    [RedbIgnore]
    public string ProviderId { get; set; } = string.Empty;

    /// <summary>Discriminates wire protocol so the registry can pick the right
    /// <see cref="redb.Identity.Core.Services.IFederatedAuthProvider"/> factory.
    /// One of: <c>oidc</c> (generic OIDC discovery), <c>github</c> (OAuth2 + email API),
    /// future custom slugs (<c>apple</c>, <c>vk</c>, ...).
    /// </summary>
    public string Kind { get; set; } = "oidc";

    /// <summary>Display name shown on the login page button.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>OIDC issuer / authority URI. Required for <c>Kind=oidc</c>; used as
    /// API base for non-OIDC providers (e.g. <c>https://api.github.com</c>).</summary>
    public string? Authority { get; set; }

    /// <summary>OAuth2 client_id.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>OAuth2 client_secret, ALWAYS encrypted at rest via
    /// <see cref="Microsoft.AspNetCore.DataProtection.IDataProtector"/>.</summary>
    public string? EncryptedClientSecret { get; set; }

    /// <summary>Scopes requested at challenge time. Default: <c>["openid","profile","email"]</c>
    /// for OIDC; provider-specific defaults for non-OIDC kinds.</summary>
    public string[] Scopes { get; set; } = ["openid", "profile", "email"];

    /// <summary>Create a local user on first federated login. Default: true.</summary>
    public bool AutoProvision { get; set; } = true;

    /// <summary>Whether this provider is available for end-user login. Allows soft-disable
    /// without deleting the PROPS row (preserves linked accounts).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Display order on login page. Lower = shown first.</summary>
    public int Priority { get; set; } = 100;

    /// <summary>Optional claim mappings: external claim type → internal claim type.
    /// Note: the H5 <see cref="ClaimMapperProps"/> system is the recommended way to do
    /// claim transformations; this is kept for back-compat with the existing
    /// <see cref="redb.Identity.Core.Configuration.FederationProviderConfig.ClaimMappings"/>
    /// field.</summary>
    public Dictionary<string, string>? ClaimMappings { get; set; }
}
