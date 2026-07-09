namespace redb.Identity.Core.Configuration;

/// <summary>
/// H10 — server-side password policy applied by management, self-service and SCIM
/// password mutations. All knobs are exposed via the standard Tsak 5-layer config
/// pipeline (see <c>redb.Identity.Core.config.json:Identity.PasswordPolicy</c>).
/// Defaults are STRICT (NIST SP 800-63B Draft + OWASP ASVS 4.0.3 §2.1) so a freshly
/// bootstrapped deployment is secure-by-default; tune per environment.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>Minimum number of characters required. Default 12.</summary>
    public int MinLength { get; set; } = 12;

    /// <summary>
    /// Maximum number of characters accepted. Acts as a DoS guard against pathologically
    /// long inputs reaching the Argon2id hasher. Default 512.
    /// </summary>
    public int MaxLength { get; set; } = 512;

    /// <summary>Require at least one ASCII digit (<c>0-9</c>). Default <c>true</c>.</summary>
    public bool RequireDigit { get; set; } = true;

    /// <summary>Require at least one ASCII uppercase letter (<c>A-Z</c>). Default <c>true</c>.</summary>
    public bool RequireUppercase { get; set; } = true;

    /// <summary>Require at least one ASCII lowercase letter (<c>a-z</c>). Default <c>true</c>.</summary>
    public bool RequireLowercase { get; set; } = true;

    /// <summary>
    /// Require at least one character from <see cref="SpecialChars"/>. Default <c>false</c>
    /// — modern guidance (NIST SP 800-63B §5.1.1.2) deprecates forced symbol classes in
    /// favour of length + breach screening.
    /// </summary>
    public bool RequireSpecial { get; set; } = false;

    /// <summary>
    /// Set of characters that count as "special" when <see cref="RequireSpecial"/> is on.
    /// Default covers the OWASP-recommended ASCII punctuation set.
    /// </summary>
    public string SpecialChars { get; set; } = "!@#$%^&*()-_=+[]{}|;:,.<>?/`~\"'\\";

    /// <summary>
    /// Number of recent password hashes (per user) to retain and reject on reuse. Set to
    /// <c>0</c> to disable history checks. Default <c>5</c>.
    /// </summary>
    public int HistoryCount { get; set; } = 5;

    /// <summary>
    /// Maximum age of a password before the user is forced to change it on next login.
    /// Use <see cref="System.TimeSpan.Zero"/> to disable expiration entirely. Default
    /// <c>90 days</c> (industry baseline; turn off in deployments using passkeys/MFA-only).
    /// </summary>
    public System.TimeSpan MaxAge { get; set; } = System.TimeSpan.FromDays(90);

    /// <summary>
    /// When <c>true</c>, the configured <c>IBreachedPasswordChecker</c> is consulted on
    /// every change/set. Default <c>false</c> — opt in by registering a checker
    /// implementation (e.g. <c>redb.Identity.PasswordPolicy.Hibp</c>). With no checker
    /// registered the flag is a no-op.
    /// </summary>
    public bool BreachCheckEnabled { get; set; } = false;
}
