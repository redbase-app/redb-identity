using redb.Core;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H3 (v1.0 DoD §6): self-service password change backing <c>PUT /me/password</c>.
/// Caller id is derived from the access-token subject — the request body is the
/// old+new password pair, no <c>Id</c> field. Enforces the same password policy as
/// <see cref="UserManagementProcessor.ChangePassword"/> and revokes ALL of the
/// caller's sessions on success (OWASP Session Management C7). Returns
/// <c>invalid_password</c> (400) when the old password does not match — no lockout
/// of its own; per-IP login-failure rate-limit covers brute-force attempts upstream.
/// </summary>
internal sealed class MePasswordProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public MePasswordProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var callerId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "invalid_token",
                $"The access token does not carry a numeric subject claim required for self-service APIs (got subject={MeProcessorHelpers.GetRawCallerSubject(exchange) ?? "<null>"}).");
            return;
        }

        var request = exchange.In.Body as MeChangePasswordRequest;
        if (request is null)
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error",
                "Body must be a MeChangePasswordRequest.");
            return;
        }
        if (string.IsNullOrEmpty(request.OldPassword))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "OldPassword is required");
            return;
        }

        var err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request.NewPassword, callerId.Value, "NewPassword", ct);
        if (err != null) { MeProcessorHelpers.Reject(exchange, 400, "validation_error", err); return; }

        if (request.OldPassword == request.NewPassword)
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error",
                "NewPassword must differ from OldPassword");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);
        var coreUser = await redb.UserProvider.GetUserByIdAsync(callerId.Value);
        if (coreUser is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found", "User not found.");
            return;
        }

        bool changed;
        try
        {
            changed = await redb.UserProvider.ChangePasswordAsync(
                coreUser, request.OldPassword, request.NewPassword);
        }
        catch (UnauthorizedAccessException)
        {
            // The core UserProvider raises this for wrong-old-password instead of
            // returning false. Honour the documented processor contract (400 invalid_password)
            // so the rejection lands in the same shape regardless of which provider
            // (in-memory test fixture vs redb-pg) is in use.
            MeProcessorHelpers.Reject(exchange, 400, "invalid_password", "Old password is incorrect");
            return;
        }
        if (!changed)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_password", "Old password is incorrect");
            return;
        }

        // H10 — record the new password in history (post-success).
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, redb, coreUser.Id, request.NewPassword, ct);

        // C7 (OWASP Session Management): invalidate every session authenticated with the
        // old password, including the caller's current session. User must re-auth.
        var sessionsRevoked = await new SessionService(redb).LogoutAsync(coreUser.Id, ct);

        exchange.Out ??= new Message();
        exchange.Out.Body = new { success = true, sessionsRevoked };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordChanged;
        exchange.Properties["identity-event-data"] = new
        {
            Login = coreUser.Login,
            SessionsRevoked = sessionsRevoked,
            SelfService = true
        };
    }
}
