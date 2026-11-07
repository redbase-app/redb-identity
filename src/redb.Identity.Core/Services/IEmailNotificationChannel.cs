using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Services;

/// <summary>
/// N-4 (Session C): SPI for delivering identity-system transactional e-mails
/// (password reset, account-verification, change-of-email confirmation, etc.) via the
/// host's mail infrastructure.
/// <para>
/// Mirrors the role <see cref="IMfaDeliveryChannel"/> plays for SMS/Email OTP delivery:
/// the Core defines only the contract; concrete implementations (SMTP, SendGrid, in-memory
/// test capture) are registered by the host application or by satellite packages.
/// </para>
/// <para>
/// Templates are referenced by a stable <c>templateId</c> string (e.g. <c>"password-reset"</c>);
/// the implementation resolves the localized body and the variable substitution. Core
/// passes the values as a flat dictionary keyed by template-variable names (e.g.
/// <c>userName</c>, <c>resetLink</c>, <c>ttlMinutes</c>).
/// </para>
/// </summary>
public interface IEmailNotificationChannel
{
    /// <summary>
    /// Renders <paramref name="templateId"/> with the supplied <paramref name="vars"/> and
    /// dispatches the resulting message to <paramref name="to"/>. The call MUST be safe
    /// to invoke concurrently and MUST NOT throw on transient errors that the host has
    /// chosen to absorb (logging is acceptable); fatal misconfiguration MAY throw so the
    /// caller can degrade gracefully.
    /// </summary>
    /// <param name="to">Recipient e-mail address.</param>
    /// <param name="templateId">Stable template identifier (e.g. <c>"password-reset"</c>).</param>
    /// <param name="vars">Variable substitutions for the template body.</param>
    Task SendTemplateAsync(
        string to,
        string templateId,
        IReadOnlyDictionary<string, string> vars,
        CancellationToken ct = default);
}

/// <summary>
/// N-4 (Session C): stable template identifiers consumed by
/// <see cref="IEmailNotificationChannel.SendTemplateAsync"/>. Centralized so processors
/// and template-implementation packages share a single source of truth.
/// </summary>
public static class IdentityEmailTemplates
{
    /// <summary>Password-reset link e-mail. Vars: <c>userName</c>, <c>resetLink</c>, <c>ttlMinutes</c>.</summary>
    public const string PasswordReset = "password-reset";

    /// <summary>N4-6: e-mail verification link. Vars: <c>userName</c>, <c>verifyLink</c>, <c>ttlHours</c>.</summary>
    public const string EmailVerification = "email-verification";

    /// <summary>N4-7: change-of-e-mail confirmation link delivered to the NEW address.
    /// Vars: <c>userName</c>, <c>oldEmail</c>, <c>newEmail</c>, <c>confirmLink</c>, <c>ttlHours</c>.</summary>
    public const string ChangeEmail = "change-email";
}
