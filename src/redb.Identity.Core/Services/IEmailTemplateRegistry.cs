using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Services;

/// <summary>
/// N-4 (Session C): rendered e-mail payload returned by an
/// <see cref="IEmailTemplateRegistry"/> lookup. Carries everything the
/// <see cref="IEmailNotificationChannel"/> needs to dispatch (subject line + HTML body
/// + optional text alternative). The default registry produces both an HTML and a
/// plain-text version so SMTP-side multipart/alternative messages render correctly in
/// clients that disable HTML.
/// </summary>
public sealed class RenderedEmailTemplate
{
    public required string Subject { get; init; }
    public required string HtmlBody { get; init; }
    public string? TextBody { get; init; }
}

/// <summary>
/// N-4 (Session C): renders identity-system e-mail templates by
/// <see cref="IdentityEmailTemplates"/> id + locale + variable substitutions.
/// Implementations MAY consult <c>UserProps.Locale</c> (when added) or fall back to a
/// default locale; the default <see cref="InlineEmailTemplateRegistry"/> ships with
/// English and Russian variants and falls back to English when the requested locale is
/// missing.
/// </summary>
public interface IEmailTemplateRegistry
{
    /// <summary>
    /// Resolves the template body. Throws <see cref="KeyNotFoundException"/> when
    /// <paramref name="templateId"/> is unknown; missing locales degrade silently to the
    /// default (English).
    /// </summary>
    ValueTask<RenderedEmailTemplate> RenderAsync(
        string templateId,
        string? locale,
        IReadOnlyDictionary<string, string> vars,
        CancellationToken ct = default);
}
