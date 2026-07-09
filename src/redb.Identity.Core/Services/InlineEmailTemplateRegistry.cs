using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Services;

/// <summary>
/// N-4 (Session C): default <see cref="IEmailTemplateRegistry"/> shipping inline
/// English + Russian copy for the identity-system transactional e-mails. Variable
/// substitution uses a simple <c>{name}</c> placeholder syntax — no Razor / Mustache
/// engine is dragged in. Hosts that need richer rendering replace this registry by
/// registering their own <see cref="IEmailTemplateRegistry"/> singleton before
/// <c>AddRedbIdentityServer</c>.
/// </summary>
public sealed class InlineEmailTemplateRegistry : IEmailTemplateRegistry
{
    public ValueTask<RenderedEmailTemplate> RenderAsync(
        string templateId,
        string? locale,
        IReadOnlyDictionary<string, string> vars,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(templateId))
            throw new ArgumentException("templateId is required", nameof(templateId));

        var key = (templateId, NormalizeLocale(locale));
        if (!_templates.TryGetValue(key, out var template)
            && !_templates.TryGetValue((templateId, "en"), out template))
        {
            throw new KeyNotFoundException(
                $"No e-mail template registered for templateId='{templateId}' (also tried fallback locale 'en').");
        }

        return new ValueTask<RenderedEmailTemplate>(new RenderedEmailTemplate
        {
            Subject = Substitute(template.Subject, vars),
            HtmlBody = Substitute(template.HtmlBody, vars),
            TextBody = template.TextBody is null ? null : Substitute(template.TextBody, vars),
        });
    }

    private static string NormalizeLocale(string? locale)
    {
        if (string.IsNullOrWhiteSpace(locale)) return "en";
        // Match "ru", "ru-RU", "RU" → "ru"; "en", "en-US" → "en".
        var dash = locale.IndexOf('-');
        var lang = (dash > 0 ? locale[..dash] : locale).ToLowerInvariant();
        return lang switch
        {
            "ru" => "ru",
            _ => "en",
        };
    }

    private static string Substitute(string template, IReadOnlyDictionary<string, string> vars)
    {
        // Simple {name} replacement — no recursion, no formatting. Sufficient for the
        // transactional e-mails we currently produce.
        if (vars.Count == 0 || template.IndexOf('{') < 0) return template;
        var sb = new StringBuilder(template.Length + 64);
        var i = 0;
        while (i < template.Length)
        {
            var open = template.IndexOf('{', i);
            if (open < 0) { sb.Append(template, i, template.Length - i); break; }
            var close = template.IndexOf('}', open + 1);
            if (close < 0) { sb.Append(template, i, template.Length - i); break; }
            sb.Append(template, i, open - i);
            var key = template.Substring(open + 1, close - open - 1);
            if (vars.TryGetValue(key, out var value)) sb.Append(value);
            else sb.Append(template, open, close - open + 1);
            i = close + 1;
        }
        return sb.ToString();
    }

    private sealed record Template(string Subject, string HtmlBody, string? TextBody);

    private static readonly Dictionary<(string templateId, string locale), Template> _templates =
        new()
        {
            // ── password-reset / en ──
            [(IdentityEmailTemplates.PasswordReset, "en")] = new(
                Subject: "Reset your password",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Hello {userName},</p>"
                    + "<p>We received a request to reset the password for your account. "
                    + "Click the link below to set a new password — it expires in {ttlMinutes} minutes "
                    + "and can be used only once.</p>"
                    + "<p><a href=\"{resetLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;\">Reset password</a></p>"
                    + "<p>If the button does not work, copy this link into your browser:<br>"
                    + "<code>{resetLink}</code></p>"
                    + "<p>If you did not request a password reset you can safely ignore this e-mail — "
                    + "your password will remain unchanged.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Hello {userName},\r\n\r\n"
                    + "We received a request to reset the password for your account. "
                    + "Open the following link to set a new password (expires in {ttlMinutes} minutes, single-use):\r\n\r\n"
                    + "{resetLink}\r\n\r\n"
                    + "If you did not request a password reset you can safely ignore this e-mail.\r\n\r\n"
                    + "— redb.Identity"),

            // ── password-reset / ru ──
            [(IdentityEmailTemplates.PasswordReset, "ru")] = new(
                Subject: "Сброс пароля",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Здравствуйте, {userName}!</p>"
                    + "<p>Мы получили запрос на сброс пароля вашей учётной записи. "
                    + "Нажмите на ссылку ниже, чтобы задать новый пароль — она действительна {ttlMinutes} минут "
                    + "и может быть использована только один раз.</p>"
                    + "<p><a href=\"{resetLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;\">Сбросить пароль</a></p>"
                    + "<p>Если кнопка не работает, скопируйте ссылку в адресную строку браузера:<br>"
                    + "<code>{resetLink}</code></p>"
                    + "<p>Если вы не запрашивали сброс — просто игнорируйте это письмо, ваш пароль не изменится.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Здравствуйте, {userName}!\r\n\r\n"
                    + "Мы получили запрос на сброс пароля. "
                    + "Откройте ссылку ниже, чтобы задать новый пароль (действует {ttlMinutes} минут, одноразовая):\r\n\r\n"
                    + "{resetLink}\r\n\r\n"
                    + "Если вы не запрашивали сброс — просто игнорируйте это письмо.\r\n\r\n"
                    + "— redb.Identity"),

            // ── email-verification / en ──
            [(IdentityEmailTemplates.EmailVerification, "en")] = new(
                Subject: "Verify your e-mail address",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Hello {userName},</p>"
                    + "<p>Please confirm that this is your e-mail address by clicking the button below. "
                    + "The link expires in {ttlHours} hours and can be used only once.</p>"
                    + "<p><a href=\"{verifyLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#16a34a;color:#ffffff;text-decoration:none;border-radius:6px;\">Verify e-mail</a></p>"
                    + "<p>If the button does not work, copy this link into your browser:<br>"
                    + "<code>{verifyLink}</code></p>"
                    + "<p>If you did not register or change your e-mail you can safely ignore this message.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Hello {userName},\r\n\r\n"
                    + "Please confirm your e-mail address by opening the following link "
                    + "(expires in {ttlHours} hours, single-use):\r\n\r\n"
                    + "{verifyLink}\r\n\r\n"
                    + "If you did not register or change your e-mail you can safely ignore this message.\r\n\r\n"
                    + "— redb.Identity"),

            // ── email-verification / ru ──
            [(IdentityEmailTemplates.EmailVerification, "ru")] = new(
                Subject: "Подтвердите адрес электронной почты",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Здравствуйте, {userName}!</p>"
                    + "<p>Пожалуйста, подтвердите, что этот адрес принадлежит вам — нажмите на кнопку ниже. "
                    + "Ссылка действительна {ttlHours} ч. и может быть использована только один раз.</p>"
                    + "<p><a href=\"{verifyLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#16a34a;color:#ffffff;text-decoration:none;border-radius:6px;\">Подтвердить e-mail</a></p>"
                    + "<p>Если кнопка не работает, скопируйте ссылку в адресную строку браузера:<br>"
                    + "<code>{verifyLink}</code></p>"
                    + "<p>Если вы не регистрировались и не меняли адрес — просто игнорируйте это письмо.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Здравствуйте, {userName}!\r\n\r\n"
                    + "Подтвердите ваш e-mail, открыв ссылку ниже "
                    + "(действует {ttlHours} ч., одноразовая):\r\n\r\n"
                    + "{verifyLink}\r\n\r\n"
                    + "Если вы не регистрировались и не меняли адрес — просто игнорируйте это письмо.\r\n\r\n"
                    + "— redb.Identity"),

            // ── change-email / en ──  (N4-7: confirmation delivered to the NEW address)
            [(IdentityEmailTemplates.ChangeEmail, "en")] = new(
                Subject: "Confirm your new e-mail address",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Hello {userName},</p>"
                    + "<p>We received a request to switch the e-mail address on your account from "
                    + "<strong>{oldEmail}</strong> to <strong>{newEmail}</strong>. "
                    + "Click the button below to confirm the change. The link expires in {ttlHours} hours and can be used only once.</p>"
                    + "<p><a href=\"{confirmLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;\">Confirm new e-mail</a></p>"
                    + "<p>If the button does not work, copy this link into your browser:<br>"
                    + "<code>{confirmLink}</code></p>"
                    + "<p>If you did not request this change you can safely ignore this message \u2014 your account e-mail will not be changed.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Hello {userName},\r\n\r\n"
                    + "We received a request to switch the e-mail address on your account "
                    + "from {oldEmail} to {newEmail}. Open the link below to confirm "
                    + "(expires in {ttlHours} hours, single-use):\r\n\r\n"
                    + "{confirmLink}\r\n\r\n"
                    + "If you did not request this change you can safely ignore this message.\r\n\r\n"
                    + "— redb.Identity"),

            // ── change-email / ru ──
            [(IdentityEmailTemplates.ChangeEmail, "ru")] = new(
                Subject: "Подтвердите новый адрес электронной почты",
                HtmlBody:
                    "<!DOCTYPE html><html><body style=\"font-family:Arial,sans-serif;color:#1f2937;\">"
                    + "<p>Здравствуйте, {userName}!</p>"
                    + "<p>Мы получили запрос на смену адреса вашей учётной записи "
                    + "с <strong>{oldEmail}</strong> на <strong>{newEmail}</strong>. "
                    + "Нажмите на кнопку ниже, чтобы подтвердить изменение. "
                    + "Ссылка действительна {ttlHours} ч. и может быть использована только один раз.</p>"
                    + "<p><a href=\"{confirmLink}\" style=\"display:inline-block;padding:10px 16px;"
                    + "background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;\">Подтвердить новый e-mail</a></p>"
                    + "<p>Если кнопка не работает, скопируйте ссылку в адресную строку браузера:<br>"
                    + "<code>{confirmLink}</code></p>"
                    + "<p>Если вы не запрашивали смену адреса — просто игнорируйте это письмо, ваш e-mail останется прежним.</p>"
                    + "<p style=\"color:#6b7280;font-size:12px;margin-top:24px;\">redb.Identity</p>"
                    + "</body></html>",
                TextBody:
                    "Здравствуйте, {userName}!\r\n\r\n"
                    + "Запрошена смена e-mail с {oldEmail} на {newEmail}. "
                    + "Откройте ссылку ниже, чтобы подтвердить "
                    + "(действует {ttlHours} ч., одноразовая):\r\n\r\n"
                    + "{confirmLink}\r\n\r\n"
                    + "Если вы не запрашивали смену адреса — просто игнорируйте это письмо.\r\n\r\n"
                    + "— redb.Identity"),
        };
}
