namespace redb.Identity.Core.Configuration;

/// <summary>
/// Role-driven entitlement for administrative scopes.
/// <para>
/// OAuth checks a scope against the <b>client</b>: may this application ask for it? That answer says
/// nothing about the person signing in, so a console permitted to request <c>identity:manage</c> handed
/// the master management scope to every account that could log into it. This gate adds the missing half
/// for user-bound grants: an administrative scope survives only when the user's effective roles carry
/// it. The <c>client_credentials</c> grant is untouched — it has no user, and the application's
/// <c>scp:{scope}</c> permission remains its authoritative gate.
/// </para>
/// <para>
/// What counts as administrative is deliberately narrow and explicit: Identity's own management surface
/// (<c>identity:*</c>) and SCIM. An operator's own scopes are none of this gate's business unless they
/// are listed here. <c>identity:account</c> is exempt — it is the self-service scope every signed-in
/// user is meant to hold.
/// </para>
/// </summary>
public sealed class AdminScopeEntitlementOptions
{
    /// <summary>
    /// Master switch, on by default. Turning it off restores the pre-gate behaviour, where any account
    /// that can sign in to a console permitted to request <c>identity:manage</c> holds it. Present so a
    /// deployment that locks itself out can recover from configuration alone, without a rebuild.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Scope-name prefixes that require an entitling role. Default: <c>identity:</c>.</summary>
    public List<string> GatedPrefixes { get; set; } = new() { "identity:" };

    /// <summary>Individual scope names that require an entitling role. Default: <c>scim</c>.</summary>
    public List<string> GatedScopes { get; set; } = new() { "scim" };

    /// <summary>
    /// Scopes never gated even when a prefix matches. Default: <c>identity:account</c> — self-service
    /// over one's own profile, which every signed-in user is supposed to have.
    /// </summary>
    public List<string> Exempt { get; set; } = new() { "identity:account" };

    /// <summary>True when <paramref name="scope"/> may only be issued to a user whose roles carry it.</summary>
    public bool IsGated(string scope)
    {
        if (string.IsNullOrEmpty(scope)) return false;
        foreach (var exempt in Exempt)
        {
            if (string.Equals(scope, exempt, StringComparison.Ordinal)) return false;
        }
        foreach (var gated in GatedScopes)
        {
            if (string.Equals(scope, gated, StringComparison.Ordinal)) return true;
        }
        foreach (var prefix in GatedPrefixes)
        {
            if (!string.IsNullOrEmpty(prefix) && scope.StartsWith(prefix, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
