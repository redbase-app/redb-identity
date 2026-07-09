using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.ChangeEmail;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

using CoreUpdateUserRequest = redb.Core.Models.Users.UpdateUserRequest;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session E, sub-step N4-7): anonymous change-of-e-mail confirmation backing
/// <c>direct-vm://identity-change-email-confirm</c>.
/// <para>
/// Verifies + atomically consumes the single-use token via
/// <see cref="IChangeEmailTokenStore.VerifyAndConsumeAsync"/>. On success it loads the
/// user, enforces the race-guard (current e-mail still matches the snapshot captured at
/// issue time), re-checks uniqueness of the new address, then in one logical step
/// updates <c>_users.email</c> to the new value AND flips
/// <see cref="UserProps.EmailVerified"/> to <c>true</c>.
/// </para>
/// <para>
/// All failure modes return the generic OAuth-style <c>invalid_token</c> error; the
/// granular reason is only persisted to audit
/// (<see cref="IdentityAuditEventIds.EmailChangeFailed"/>) so an anonymous caller cannot
/// enumerate which jti values exist.
/// </para>
/// </summary>
internal sealed class ChangeEmailConfirmProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public ChangeEmailConfirmProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as ChangeEmailConfirmRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.Jti)
            || string.IsNullOrWhiteSpace(request.Token))
        {
            Reject(exchange, 400, "validation_error", "Jti and Token are required.");
            return;
        }

        if (!Guid.TryParseExact(request.Jti, "N", out var jti)
            && !Guid.TryParse(request.Jti, out jti))
        {
            EmitFailureAudit(exchange, "bad_jti_format", userId: 0);
            Reject(exchange, 400, "invalid_token", "The confirmation token is invalid or has expired.");
            return;
        }

        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("ChangeEmailConfirmProcessor");
        var store = _sp.GetRequiredService<IChangeEmailTokenStore>();

        var verify = await store.VerifyAndConsumeAsync(jti, request.Token, ct).ConfigureAwait(false);
        if (!verify.Success)
        {
            EmitFailureAudit(exchange, verify.Reason, verify.UserId);
            Reject(exchange, 400, "invalid_token", "The confirmation token is invalid or has expired.");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);

        var user = await redb.UserProvider.GetUserByIdAsync(verify.UserId).ConfigureAwait(false);
        if (user is null)
        {
            EmitFailureAudit(exchange, "user_not_found", verify.UserId);
            Reject(exchange, 400, "invalid_token", "The confirmation token is invalid or has expired.");
            return;
        }

        // ── Race-guard: e-mail must not have changed since the token was issued ──
        var currentEmail = (user.Email ?? string.Empty).Trim().ToLowerInvariant();
        if (!string.Equals(currentEmail, verify.CurrentEmail, StringComparison.Ordinal))
        {
            EmitFailureAudit(exchange, "current_email_changed", user.Id);
            Reject(exchange, 400, "invalid_token", "The confirmation token is invalid or has expired.");
            return;
        }

        // ── Uniqueness re-check at commit time ──
        var existingUsers = await redb.UserProvider.GetUsersAsync(new redb.Core.Models.Users.UserSearchCriteria
        {
            EmailExact = verify.NewEmail,
        }).ConfigureAwait(false);
        if (existingUsers.Count > 0 && existingUsers[0].Id != user.Id)
        {
            EmitFailureAudit(exchange, "email_taken", user.Id);
            Reject(exchange, 400, "invalid_token", "The confirmation token is invalid or has expired.");
            return;
        }

        // ── Commit: swap address AND mark verified atomically ──
        var updated = await redb.UserProvider.UpdateUserAsync(user, new CoreUpdateUserRequest
        {
            Email = verify.NewEmail,
        }).ConfigureAwait(false);

        var oidcObj = await MeProcessorHelpers.LoadOidcProps(redb, user.Id).ConfigureAwait(false);
        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps { EmailVerified = true });
            oidcObj.name = updated.Login;
            oidcObj.key = updated.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }
        else
        {
            oidcObj.Props.EmailVerified = true;
        }
        await redb.SaveAsync(oidcObj).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = new ChangeEmailConfirmResponse { Success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailChangeCompleted;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = updated.Id,
            Login = updated.Login,
            OldEmail = verify.CurrentEmail,
            NewEmail = verify.NewEmail,
            Jti = jti.ToString("N"),
        };
    }

    private static void EmitFailureAudit(IExchange exchange, string reason, long userId)
    {
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailChangeFailed;
        exchange.Properties["identity-event-data"] = new { Reason = reason, UserId = userId };
    }

    private static void Reject(IExchange exchange, int status, string error, string description)
    {
        exchange.Out ??= new Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = status;
        exchange.Out.Body = new ChangeEmailConfirmResponse
        {
            Success = false,
            Error = error,
            ErrorDescription = description,
        };
    }
}
