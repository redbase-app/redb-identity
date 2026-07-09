namespace redb.Identity.Core.Configuration;

/// <summary>
/// N-3 (sub-step N3-7): tunables + feature gate for the self-service account
/// registration flow (<c>direct-vm://identity-account-register</c> +
/// <c>POST /api/v1/identity/account/register</c>).
/// <para>
/// Disabled by default — opt-in for deployments that want public sign-up; corporate
/// identity deployments that provision users via admin / SCIM should leave this off.
/// </para>
/// </summary>
public sealed class RegistrationOptions
{
    /// <summary>Master switch. When <c>false</c> the route is not built and the facade returns 404.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// When <c>true</c> and <see cref="RedbIdentityOptions.EmailVerification"/> is also
    /// enabled, the processor automatically dispatches an e-mail verification link after
    /// account creation. The user's <c>EmailVerified</c> flag stays <c>false</c> until
    /// the link is consumed. Defaults to <c>true</c>.
    /// </summary>
    public bool SendVerifyEmail { get; set; } = true;

    /// <summary>
    /// When <c>true</c> (default) the processor enforces e-mail uniqueness alongside
    /// login uniqueness. Set to <c>false</c> only for deployments that explicitly allow
    /// the same e-mail to back multiple accounts.
    /// </summary>
    public bool RequireUniqueEmail { get; set; } = true;
}
