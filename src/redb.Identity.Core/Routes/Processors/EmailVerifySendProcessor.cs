using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.EmailVerification;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session C, sub-step N4-6): authenticated self-service e-mail-verification dispatch
/// backing <c>direct-vm://identity-me-email-verify-send</c>.
/// <para>
/// Caller user + target e-mail are derived from the access-token subject (via
/// <see cref="MeProcessorHelpers.TryGetCallerUserId"/>); the body only carries
/// <c>ClientId</c> + <c>CallerVerifyUrl</c>. The URL must match the client's
/// <c>ApplicationProps.EmailVerifyUris</c> whitelist exactly (string compare); a mismatch
/// or unknown client returns a generic 400 (no anti-enumeration concern — caller is
/// already authenticated).
/// </para>
/// <para>
/// The issued token is bound to the user's current e-mail snapshot via
/// <see cref="EmailVerificationTokenProps.Email"/> so the confirm step can detect a
/// double-change race (token issued for value A, e-mail moved to B before confirm).
/// </para>
/// </summary>
internal sealed class EmailVerifySendProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public EmailVerifySendProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as EmailVerifySendRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.ClientId)
            || string.IsNullOrWhiteSpace(request.CallerVerifyUrl))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error",
                "ClientId and CallerVerifyUrl are required.");
            return;
        }

        var callerUserId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerUserId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "unauthorized", "Caller subject missing or invalid.");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);
        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("EmailVerifySendProcessor");

        var user = await redb.UserProvider.GetUserByIdAsync(callerUserId.Value).ConfigureAwait(false);
        if (user is null || string.IsNullOrEmpty(user.Email))
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request", "Caller has no e-mail on file.");
            return;
        }

        // ── Gate: client whitelist ────────────────────────────────────────────────
        var app = await redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == request.ClientId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (app is null)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_client", "Unknown client_id.");
            return;
        }
        var whitelist = app.Props.EmailVerifyUris;
        if (whitelist is null || whitelist.Length == 0)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                "E-mail verification is not enabled for this client.");
            return;
        }
        var allowed = false;
        for (var i = 0; i < whitelist.Length; i++)
        {
            if (string.Equals(whitelist[i], request.CallerVerifyUrl, StringComparison.Ordinal))
            { allowed = true; break; }
        }
        if (!allowed)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                "CallerVerifyUrl is not whitelisted for this client.");
            return;
        }

        // ── Issue + dispatch ──────────────────────────────────────────────────────
        var store = _sp.GetRequiredService<IEmailVerificationTokenStore>();
        var emailChannel = _sp.GetService<IEmailNotificationChannel>();
        if (emailChannel is null)
        {
            logger?.LogError(
                "EmailVerify-send: no IEmailNotificationChannel registered \u2014 dropping (host misconfiguration)");
            MeProcessorHelpers.Reject(exchange, 503, "service_unavailable", "E-mail channel unavailable.");
            return;
        }

        var ttl = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value.EmailVerification.TokenTtl;
        var issued = await store.IssueAsync(user.Id, user.Email, request.CallerVerifyUrl, ttl, ct)
            .ConfigureAwait(false);

        var verifyLink = BuildVerifyLink(request.CallerVerifyUrl, issued.Jti, issued.PlaintextToken);
        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["userName"] = user.Name ?? user.Login,
            ["verifyLink"] = verifyLink,
            ["ttlHours"] = ((int)ttl.TotalHours).ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        try
        {
            await emailChannel.SendTemplateAsync(user.Email, IdentityEmailTemplates.EmailVerification, vars, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex,
                "EmailVerify-send: e-mail delivery failed for user {UserId}", user.Id);
            MeProcessorHelpers.Reject(exchange, 502, "delivery_failed", "Could not dispatch verification e-mail.");
            return;
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new EmailVerifySendResponse { Success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailVerificationSent;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = user.Id,
            Login = user.Login,
            ClientId = request.ClientId,
            Email = user.Email.ToLowerInvariant(),
            Jti = issued.Jti.ToString("N"),
            ExpiresAt = issued.ExpiresAt,
        };
    }

    private static string BuildVerifyLink(string callerVerifyUrl, Guid jti, string plaintextToken)
    {
        var sep = callerVerifyUrl.Contains('?') ? '&' : '?';
        var sb = new StringBuilder(callerVerifyUrl.Length + 128);
        sb.Append(callerVerifyUrl);
        sb.Append(sep);
        sb.Append("token=");
        sb.Append(Uri.EscapeDataString(plaintextToken));
        sb.Append("&jti=");
        sb.Append(jti.ToString("N"));
        return sb.ToString();
    }
}
