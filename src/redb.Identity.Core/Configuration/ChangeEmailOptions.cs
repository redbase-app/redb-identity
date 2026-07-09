using System;

namespace redb.Identity.Core.Configuration;

/// <summary>
/// N-4 (Session E, sub-step N4-7): tunables for the verify-then-commit change-of-e-mail
/// flow (<c>direct-vm://identity-me-change-email-request</c> +
/// <c>direct-vm://identity-change-email-confirm</c>).
/// <para>
/// Unlike the soft path on <c>/me/profile</c> (which overwrites the e-mail immediately
/// and lazily resets <c>EmailVerified=false</c>), the change-email flow defers the
/// commit until the user proves control of the new address: the confirmation link is
/// e-mailed to the <em>new</em> address; the current address remains the canonical login
/// until the link is clicked. On successful confirm the swap is atomic and
/// <c>EmailVerified</c> is set to <c>true</c> in the same transaction.
/// </para>
/// <para>
/// Feature-gated by <see cref="Enabled"/>: when <c>false</c> (default), neither route is
/// registered and the HTTP facade returns 404. Per-client URL whitelisting lives on
/// <c>ApplicationProps.ChangeEmailUris</c>.
/// </para>
/// </summary>
public sealed class ChangeEmailOptions
{
    /// <summary>
    /// Master switch. When <c>false</c> (default), the request + confirm direct-vm routes
    /// are not registered. Opt-in until a host wires an <c>IEmailNotificationChannel</c>
    /// and configures per-client <c>ApplicationProps.ChangeEmailUris</c>.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Time-to-live for an issued single-use change-of-e-mail token. Recommended range:
    /// 30 minutes – 24 hours. Default: 1 hour — short enough to limit the window during
    /// which a stolen link can hijack the address, long enough for a user to retrieve
    /// the e-mail from spam folders.
    /// </summary>
    public TimeSpan TokenTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// When <c>true</c> (default), issuing a new change-of-e-mail token marks any prior
    /// unconsumed tokens for the same user as <c>Consumed</c>. Prevents an attacker who
    /// previously coerced the user into requesting a change from racing the legitimate
    /// new request.
    /// </summary>
    public bool InvalidatePreviousTokensOnRequest { get; set; } = true;

    /// <summary>
    /// When <c>true</c>, <see cref="Processors.MeProfileProcessor"/> ignores the
    /// <c>email</c> field on inbound <c>MeUpdateProfileRequest</c> bodies so users
    /// cannot bypass verification by hitting the soft path. Default <c>false</c> keeps
    /// the soft path functional alongside the strict path (back-office deployments).
    /// </summary>
    public bool RejectSoftEmailChange { get; set; } = false;
}
