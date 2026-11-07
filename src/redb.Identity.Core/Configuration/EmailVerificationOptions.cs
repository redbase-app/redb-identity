using System;

namespace redb.Identity.Core.Configuration;

/// <summary>
/// N-4 (Session C, sub-step N4-6): tunables for the e-mail-verification flow
/// (<c>direct-vm://identity-me-email-verify-send</c> +
/// <c>direct-vm://identity-email-verify-confirm</c>).
/// <para>
/// Defaults follow common practice (Auth0=5d, Okta=7d, Cognito=24h, Microsoft Entra B2C=24h)
/// at the conservative end. A 24-hour TTL is long enough for a user to retrieve the e-mail
/// from spam folders / corporate quarantines but short enough to limit replay risk if the
/// inbox is later compromised.
/// </para>
/// <para>
/// The flow itself is feature-gated by <see cref="Enabled"/>: when <c>false</c>, neither
/// the send nor the confirm direct-vm route is registered and the HTTP facade returns 404.
/// Per-client URL whitelisting lives on <c>ApplicationProps.EmailVerifyUris</c> (mirror of
/// <c>PasswordResetUris</c>) so multi-tenant deployments can scope each BFF to its own
/// verify page.
/// </para>
/// </summary>
public sealed class EmailVerificationOptions
{
    /// <summary>
    /// Master switch. When <c>false</c> (default), the send + confirm direct-vm routes
    /// are not registered and Core does NOT automatically clear
    /// <c>UserProps.EmailVerified</c> on /me e-mail change. Opt-in until a host wires an
    /// <c>IEmailNotificationChannel</c> and configures per-client
    /// <c>ApplicationProps.EmailVerifyUris</c>.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Time-to-live for an issued single-use verification token. Recommended range:
    /// 1 hour – 7 days. Default: 24 hours.
    /// </summary>
    public TimeSpan TokenTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// When <c>true</c> (default) Core flips <c>UserProps.EmailVerified</c> to <c>false</c>
    /// as soon as a /me profile update changes the user's e-mail address. The BFF is then
    /// expected to call <c>POST /api/v1/identity/me/verify-email/send</c> to dispatch a
    /// fresh verification e-mail. When <c>false</c>, the flag is preserved across changes
    /// (legacy behaviour — only suitable for trusted-back-office deployments).
    /// </summary>
    public bool AutoResetOnChange { get; set; } = true;
}
