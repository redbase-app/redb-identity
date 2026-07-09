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
using redb.Identity.Core.ChangeEmail;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session E, sub-step N4-7): authenticated change-of-e-mail dispatch backing
/// <c>direct-vm://identity-me-change-email-request</c>.
/// <para>
/// Caller user is derived from the access-token subject (via
/// <see cref="MeProcessorHelpers.TryGetCallerUserId"/>); the body carries the requested
/// <c>NewEmail</c>, the BFF's <c>ClientId</c>, and the page that will host the confirm
/// form (<c>CallerConfirmUrl</c>). The URL must match the client's
/// <c>ApplicationProps.ChangeEmailUris</c> whitelist exactly (string compare).
/// </para>
/// <para>
/// The issued token is bound to BOTH the requested new address and a snapshot of the
/// current address — the confirm step swaps them atomically only when no other path
/// has mutated the e-mail in the meantime.
/// </para>
/// </summary>
internal sealed class ChangeEmailRequestProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public ChangeEmailRequestProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as ChangeEmailRequestRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.NewEmail)
            || string.IsNullOrWhiteSpace(request.ClientId)
            || string.IsNullOrWhiteSpace(request.CallerConfirmUrl))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error",
                "NewEmail, ClientId and CallerConfirmUrl are required.");
            return;
        }

        var emailErr = IdentityProcessorHelpers.ValidateEmail(request.NewEmail);
        if (emailErr is not null)
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", emailErr);
            return;
        }

        var callerUserId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerUserId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "unauthorized", "Caller subject missing or invalid.");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);
        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("ChangeEmailRequestProcessor");

        var user = await redb.UserProvider.GetUserByIdAsync(callerUserId.Value).ConfigureAwait(false);
        if (user is null || string.IsNullOrEmpty(user.Email))
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request", "Caller has no e-mail on file.");
            return;
        }

        var newEmail = request.NewEmail.Trim().ToLowerInvariant();
        var currentEmail = user.Email.Trim().ToLowerInvariant();

        // No-op request: the user already has the address they're asking for.
        if (string.Equals(newEmail, currentEmail, StringComparison.Ordinal))
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                "The new address is identical to the current one.");
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
        var whitelist = app.Props.ChangeEmailUris;
        if (whitelist is null || whitelist.Length == 0)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                "Change-of-e-mail is not enabled for this client.");
            return;
        }
        var allowed = false;
        for (var i = 0; i < whitelist.Length; i++)
        {
            if (string.Equals(whitelist[i], request.CallerConfirmUrl, StringComparison.Ordinal))
            { allowed = true; break; }
        }
        if (!allowed)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                "CallerConfirmUrl is not whitelisted for this client.");
            return;
        }

        // ── Uniqueness pre-check ──────────────────────────────────────────────────
        // The address-must-be-unique guard also runs at commit time (see confirm); doing
        // it here keeps the UX honest by failing fast before we send a confirmation
        // e-mail that would never be redeemable.
        var existingUsers = await redb.UserProvider.GetUsersAsync(new redb.Core.Models.Users.UserSearchCriteria
        {
            EmailExact = newEmail,
        }).ConfigureAwait(false);
        if (existingUsers.Count > 0 && existingUsers[0].Id != user.Id)
        {
            MeProcessorHelpers.Reject(exchange, 409, "email_taken",
                "Another account already uses this e-mail address.");
            return;
        }

        // ── Issue + dispatch ──────────────────────────────────────────────────────
        var store = _sp.GetRequiredService<IChangeEmailTokenStore>();
        var emailChannel = _sp.GetService<IEmailNotificationChannel>();
        if (emailChannel is null)
        {
            logger?.LogError(
                "ChangeEmail-request: no IEmailNotificationChannel registered \u2014 dropping (host misconfiguration)");
            MeProcessorHelpers.Reject(exchange, 503, "service_unavailable", "E-mail channel unavailable.");
            return;
        }

        var opts = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value.ChangeEmail;
        var ttl = opts.TokenTtl;
        var issued = await store.IssueAsync(
                user.Id, newEmail, currentEmail, request.CallerConfirmUrl,
                ttl, opts.InvalidatePreviousTokensOnRequest, ct)
            .ConfigureAwait(false);

        var confirmLink = BuildConfirmLink(request.CallerConfirmUrl, issued.Jti, issued.PlaintextToken);
        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["userName"] = user.Name ?? user.Login,
            ["oldEmail"] = currentEmail,
            ["newEmail"] = newEmail,
            ["confirmLink"] = confirmLink,
            ["ttlHours"] = ((int)ttl.TotalHours).ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        try
        {
            // The confirmation link MUST be delivered to the NEW address — the whole
            // point of verify-then-commit is that we will not trust the new address
            // until the user proves control of it.
            await emailChannel.SendTemplateAsync(newEmail, IdentityEmailTemplates.ChangeEmail, vars, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex,
                "ChangeEmail-request: e-mail delivery failed for user {UserId}", user.Id);
            MeProcessorHelpers.Reject(exchange, 502, "delivery_failed", "Could not dispatch confirmation e-mail.");
            return;
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new ChangeEmailRequestResponse { Success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailChangeRequested;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = user.Id,
            Login = user.Login,
            ClientId = request.ClientId,
            OldEmail = currentEmail,
            NewEmail = newEmail,
            Jti = issued.Jti.ToString("N"),
            ExpiresAt = issued.ExpiresAt,
        };
    }

    private static string BuildConfirmLink(string callerConfirmUrl, Guid jti, string plaintextToken)
    {
        var sep = callerConfirmUrl.Contains('?') ? '&' : '?';
        var sb = new StringBuilder(callerConfirmUrl.Length + 128);
        sb.Append(callerConfirmUrl);
        sb.Append(sep);
        sb.Append("token=");
        sb.Append(Uri.EscapeDataString(plaintextToken));
        sb.Append("&jti=");
        sb.Append(jti.ToString("N"));
        return sb.ToString();
    }
}
