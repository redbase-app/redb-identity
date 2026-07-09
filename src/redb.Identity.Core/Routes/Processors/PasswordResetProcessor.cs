using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.PasswordReset;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session C): anonymous password-recovery completion backing
/// <c>direct-vm://identity-password-reset</c>.
/// <para>
/// Verifies + atomically consumes the single-use reset token via
/// <see cref="IPasswordResetTokenStore.VerifyAndConsumeAsync"/>, validates the new
/// password against the policy, persists it through
/// <see cref="Core.Providers.IUserProvider.SetPasswordAsync"/> (which bypasses the
/// old-password check), records the change in password history, and revokes every
/// active session for the user (OWASP Session Management C7).
/// </para>
/// <para>
/// Error responses are intentionally generic (<c>invalid_token</c> /
/// <c>validation_error</c>) — the granular <c>Reason</c> from the store is recorded only
/// in the audit log (<see cref="IdentityAuditEventIds.PasswordResetFailed"/>) so an
/// online attacker cannot tell "bad token" from "expired" from "already consumed".
/// </para>
/// </summary>
internal sealed class PasswordResetProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public PasswordResetProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as PasswordResetRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.Jti)
            || string.IsNullOrWhiteSpace(request.Token)
            || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            Reject(exchange, 400, "validation_error",
                "Jti, Token and NewPassword are required.");
            return;
        }

        if (!Guid.TryParseExact(request.Jti, "N", out var jti)
            && !Guid.TryParse(request.Jti, out jti))
        {
            // Malformed jti — treat as bad token (audit + generic response).
            await EmitFailureAuditAsync(exchange, "bad_jti_format", userId: 0).ConfigureAwait(false);
            Reject(exchange, 400, "invalid_token", "The reset token is invalid or has expired.");
            return;
        }

        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("PasswordResetProcessor");
        var store = _sp.GetRequiredService<IPasswordResetTokenStore>();

        var verify = await store.VerifyAndConsumeAsync(jti, request.Token, ct).ConfigureAwait(false);
        if (!verify.Success)
        {
            await EmitFailureAuditAsync(exchange, verify.Reason, userId: verify.UserId).ConfigureAwait(false);
            Reject(exchange, 400, "invalid_token", "The reset token is invalid or has expired.");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);

        var user = await redb.UserProvider.GetUserByIdAsync(verify.UserId).ConfigureAwait(false);
        if (user is null)
        {
            // Token consumed but user vanished — extremely rare race (admin delete between
            // issue + reset). Treat as failure; the consumed token is already non-replayable.
            await EmitFailureAuditAsync(exchange, "user_not_found", verify.UserId).ConfigureAwait(false);
            Reject(exchange, 400, "invalid_token", "The reset token is invalid or has expired.");
            return;
        }

        // Validate new password against the registered policy (length, history, etc.).
        var err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request.NewPassword, user.Id, "NewPassword", ct).ConfigureAwait(false);
        if (err is not null)
        {
            await EmitFailureAuditAsync(exchange, "policy_violation", user.Id).ConfigureAwait(false);
            Reject(exchange, 400, "validation_error", err);
            return;
        }

        // SetPasswordAsync bypasses the old-password check (admin/reset path).
        var ok = await redb.UserProvider.SetPasswordAsync(user, request.NewPassword).ConfigureAwait(false);
        if (!ok)
        {
            logger?.LogError(
                "Password reset: SetPasswordAsync returned false for user {UserId} — unexpected after policy check passed",
                user.Id);
            await EmitFailureAuditAsync(exchange, "set_password_failed", user.Id).ConfigureAwait(false);
            Reject(exchange, 500, "server_error", "Failed to persist the new password.");
            return;
        }

        // H10 — record in history so future change attempts can reject reuse.
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, redb, user.Id, request.NewPassword, ct).ConfigureAwait(false);

        // C7 (OWASP Session Management): every active session must be invalidated, since
        // the user may not even be the legitimate one who initiated recovery.
        var sessionsRevoked = await new SessionService(redb).LogoutAsync(user.Id, ct).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = new PasswordResetResponse
        {
            Success = true,
            SessionsRevoked = sessionsRevoked,
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordResetCompleted;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = user.Id,
            Login = user.Login,
            Jti = jti.ToString("N"),
            SessionsRevoked = sessionsRevoked,
        };
    }

    private static Task EmitFailureAuditAsync(IExchange exchange, string reason, long userId)
    {
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordResetFailed;
        exchange.Properties["identity-event-data"] = new
        {
            Reason = reason,
            UserId = userId,
        };
        return Task.CompletedTask;
    }

    private static void Reject(IExchange exchange, int status, string error, string description)
    {
        exchange.Out ??= new Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = status;
        exchange.Out.Body = new PasswordResetResponse
        {
            Success = false,
            Error = error,
            ErrorDescription = description,
        };
    }
}
