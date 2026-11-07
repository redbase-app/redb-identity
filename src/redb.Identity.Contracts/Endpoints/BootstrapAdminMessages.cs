namespace redb.Identity.Contracts.Endpoints;

/// <summary>
/// B1 — request DTO for <c>POST /internal/bootstrap-admin</c>
/// (<c>direct-vm://identity-bootstrap-admin</c>).
/// <para>
/// One-shot endpoint that atomically creates the very first admin user, the
/// <c>identity-admins</c> group, the <c>identity:admin</c> scope, the
/// canonical <c>identity-web</c> OIDC client and the
/// <c>SystemFlag(name=bootstrap_completed)</c> sentinel that gates further
/// invocations. Subsequent calls return <c>410 Gone</c>.
/// </para>
/// <para>
/// Authenticated by an out-of-band shared secret in the
/// <c>X-Bootstrap-Secret</c> header (compared with
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>).
/// </para>
/// </summary>
public sealed class BootstrapAdminRequest
{
    /// <summary>Login / email of the admin user to create. Required.</summary>
    public string? Email { get; set; }

    /// <summary>
    /// Initial password. Required. Must satisfy
    /// <see cref="redb.Identity.Core.Configuration.PasswordPolicyOptions"/>.
    /// The created user is flagged <c>RequiresPasswordChange=true</c> so a
    /// password rotation is forced on first interactive login.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Group name to create / find and add the new admin to. When null,
    /// defaults to <see cref="redb.Identity.Core.Configuration.BootstrapOptions.AdminGroupName"/>
    /// (<c>identity-admins</c>).
    /// </summary>
    public string? GroupName { get; set; }

    /// <summary>OIDC <c>redirect_uri</c> for the admin Web Console. Required.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>OIDC <c>post_logout_redirect_uri</c> for the admin Web Console. Required.</summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout endpoint of the Web Console. Stored as a
    /// custom <c>backchannel_logout_uri</c> property on the application
    /// (OpenID Connect Back-Channel Logout 1.0 §2.2).
    /// </summary>
    public string? BackchannelLogoutUri { get; set; }
}

/// <summary>
/// B1 — reply DTO for <c>POST /internal/bootstrap-admin</c>.
/// <para>
/// <see cref="ClientSecret"/> is returned <b>once and only once</b> — in plain
/// text on the very first successful invocation. After that the secret is
/// only stored as a hash inside OpenIddict and cannot be recovered.
/// </para>
/// </summary>
public sealed class BootstrapAdminResponse
{
    /// <summary>PROPS id of the freshly-created admin user.</summary>
    public long UserId { get; set; }

    /// <summary>PROPS id of the freshly-created (or found) admin group.</summary>
    public long GroupId { get; set; }

    /// <summary>OIDC <c>client_id</c> of the canonical admin Web Console (<c>identity-web</c>).</summary>
    public string ApplicationId { get; set; } = string.Empty;

    /// <summary>
    /// OIDC <c>client_secret</c> in plain — copy this out of the response and
    /// store it in your secret manager. The server only retains a hash.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>OAuth scope created / granted to the admin (<c>identity:admin</c>).</summary>
    public string ScopeName { get; set; } = string.Empty;
}
