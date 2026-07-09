using System;

namespace redb.Identity.Core.Configuration;

/// <summary>
/// N-4 (Session C): tunables for the password-recovery flow
/// (<c>direct-vm://identity-password-forgot</c> +
/// <c>direct-vm://identity-password-reset</c>).
/// <para>
/// Defaults follow OWASP ASVS V6.1.3 ("reset token expires within 60 minutes") and the
/// industry midpoint (Auth0=60m, Okta=60m, Microsoft=15m, Cognito=60m) at the lower end
/// to minimise the window in which a leaked link is exploitable.
/// </para>
/// </summary>
public sealed class PasswordRecoveryOptions
{
    /// <summary>
    /// Time-to-live for an issued single-use reset token. Recommended range: 15–60 minutes.
    /// Default: 30 minutes.
    /// </summary>
    public TimeSpan TokenTtl { get; set; } = TimeSpan.FromMinutes(30);
}
