namespace redb.Identity.Core.Configuration;

/// <summary>
/// N-4 (Session C): SMTP transport configuration consumed by the e-mail dispatch route
/// (<c>direct-vm://identity-email-send</c>) and the <c>SmtpEmailNotificationChannel</c>.
/// Empty / disabled by default — a host either enables SMTP here or registers an
/// alternative <c>IEmailNotificationChannel</c> implementation (e.g. SendGrid, in-memory
/// channel for tests, or a noop channel that drops messages).
/// </summary>
public sealed class SmtpOptions
{
    /// <summary>Master switch. When <c>false</c> the route is not built and no SMTP channel is registered.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>SMTP server host (e.g. <c>smtp.gmail.com</c>, <c>127.0.0.1</c>).</summary>
    public string? Host { get; set; }

    /// <summary>SMTP server port. Common values: 25 (plain), 465 (Ssl), 587 (StartTls), 3025 (greenmail no-auth).</summary>
    public int Port { get; set; } = 25;

    /// <summary>
    /// Security mode passed straight to the redb.Route.Mail builder
    /// (<c>None</c>, <c>StartTls</c>, <c>Ssl</c>, <c>Auto</c>). Defaults to <c>None</c>;
    /// production deployments should set <c>StartTls</c> or <c>Ssl</c>.
    /// </summary>
    public string Security { get; set; } = "None";

    /// <summary>Optional username (omit for unauthenticated greenmail-style relays).</summary>
    public string? Username { get; set; }

    /// <summary>Optional password (omit for unauthenticated greenmail-style relays).</summary>
    public string? Password { get; set; }

    /// <summary>Envelope From address used when the channel does not supply one per message.</summary>
    public string FromAddress { get; set; } = "noreply@redb.local";

    /// <summary>Skip TLS certificate validation. Test / dev only — never enable in production.</summary>
    public bool SkipCertificateValidation { get; set; } = false;
}
