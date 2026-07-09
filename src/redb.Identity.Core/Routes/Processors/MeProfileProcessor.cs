using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using CoreUpdateUserRequest = redb.Core.Models.Users.UpdateUserRequest;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H3 (v1.0 DoD §6): self-service profile endpoint backing <c>GET /me</c> and
/// <c>PUT /me</c>. Caller identity is derived from the authenticated access-token
/// subject (<c>identity:management-subject</c>) — the request body has no <c>Id</c>
/// field and admin-only properties (<c>Status</c>, <c>EmailVerified</c>,
/// <c>PhoneNumberVerified</c>) are intentionally absent from
/// <see cref="MeUpdateProfileRequest"/>. Users cannot grant themselves verified flags
/// or flip their own account status; those changes remain admin-only via
/// <see cref="UserManagementProcessor"/>.
/// </summary>
internal sealed class MeProfileProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public MeProfileProcessor(IRouteContext context, string? redbName = null)
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

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        var redb = _context.GetRedbService(_redbName, exchange);

        switch (operation)
        {
            case "read":
                await Read(redb, exchange, callerId.Value);
                break;
            case "update":
                await Update(redb, exchange, callerId.Value);
                break;
            case "delete":
                await Delete(redb, exchange, callerId.Value, ct);
                break;
            default:
                MeProcessorHelpers.Reject(exchange, 400, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    /// <summary>
    /// Self-service account deletion. Follows the exact same cascade as the admin
    /// <see cref="UserManagementProcessor"/>.Delete path: revoke all sessions (kills
    /// OpenIddict authorizations and the access/refresh tokens linked to them),
    /// soft-delete the <c>_users</c> row (login STAYS as-is — immutable per the
    /// <c>protect_system_users</c> trigger; name is tombstoned), then soft-delete the
    /// OIDC props object via <see cref="IdentityDeletionHelper"/> so it disappears
    /// from queries. Re-registration with the same login is blocked while the
    /// soft-deleted row exists.
    /// </summary>
    private async Task Delete(IRedbService redb, IExchange exchange, long callerId, CancellationToken ct)
    {
        var coreUser = await redb.UserProvider.GetUserByIdAsync(callerId);
        if (coreUser is null)
        {
            // Token said the subject existed but the underlying row is gone — treat as
            // already-deleted (idempotent self-service). Don't surface as 404 because
            // the caller's view of "deleted" already matches.
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { success = true, alreadyAbsent = true };
            return;
        }

        var sessionsRevoked = await new redb.Identity.Core.Services.SessionService(redb).LogoutAsync(coreUser.Id, ct);
        await redb.UserProvider.DeleteUserAsync(coreUser);

        var oidcObj = await MeProcessorHelpers.LoadOidcProps(redb, callerId);
        if (oidcObj is not null)
        {
            var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
            await IdentityDeletionHelper.DeleteAsync(redb, bg, oidcObj.id);
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, sessionsRevoked };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserDeleted;
        exchange.Properties["identity-event-data"] = new { Id = callerId, SessionsRevoked = sessionsRevoked, SelfService = true };
    }

    /// <summary>
    /// N4-6: returns <c>true</c> when <c>RedbIdentityOptions.EmailVerification.AutoResetOnChange</c>
    /// is set (default). Caller flips <c>UserProps.EmailVerified</c> back to <c>false</c> after
    /// any /me e-mail change so a stale-verified flag never vouches for a fresh address.
    /// </summary>
    private bool ShouldResetEmailVerifiedOnChange(IExchange exchange)
    {
        var opts = _context.GetIdentityServiceOrDefault<IOptions<RedbIdentityOptions>>(exchange)?.Value;
        return opts?.EmailVerification.AutoResetOnChange ?? true;
    }

    /// <summary>
    /// N-4 (N4-7): returns <c>true</c> when <c>RedbIdentityOptions.ChangeEmail.RejectSoftEmailChange</c>
    /// is set. When enabled, <c>/me/profile</c> refuses any e-mail mutation so the only
    /// path to change an address is the strict verify-then-commit flow exposed by
    /// <c>ChangeEmailRequestProcessor</c> / <c>ChangeEmailConfirmProcessor</c>.
    /// </summary>
    private bool RejectSoftEmailChange(IExchange exchange)
    {
        var opts = _context.GetIdentityServiceOrDefault<IOptions<RedbIdentityOptions>>(exchange)?.Value;
        return opts?.ChangeEmail.RejectSoftEmailChange ?? false;
    }

    private static async Task Read(IRedbService redb, IExchange exchange, long callerId)
    {
        var coreUser = await redb.UserProvider.GetUserByIdAsync(callerId);
        if (coreUser is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found", "User not found.");
            return;
        }

        var oidcObj = await MeProcessorHelpers.LoadOidcProps(redb, callerId);

        exchange.Out ??= new Message();
        exchange.Out.Body = MeProcessorHelpers.MapToResponse(
            coreUser, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify);
    }

    private async Task Update(IRedbService redb, IExchange exchange, long callerId)
    {
        var request = exchange.In.Body as MeUpdateProfileRequest;
        if (request is null)
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error",
                "Body must be a MeUpdateProfileRequest.");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(callerId);
        if (coreUser is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found", "User not found.");
            return;
        }

        // --- Update _users fields via Core (same validation rules as admin route) ---
        var coreUpdate = new CoreUpdateUserRequest();
        bool coreChanged = false;
        bool emailChanged = false;

        if (request.DisplayName != null)
        {
            var err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
            if (err != null) { MeProcessorHelpers.Reject(exchange, 400, "validation_error", err); return; }
            coreUpdate.Name = request.DisplayName;
            coreChanged = true;
        }
        if (request.Email != null)
        {
            var err = IdentityProcessorHelpers.ValidateEmail(request.Email);
            if (err != null) { MeProcessorHelpers.Reject(exchange, 400, "validation_error", err); return; }
            // N4-6: detect actual value change (case-insensitive) so we can clear the
            // OIDC EmailVerified flag below — a stale-verified flag must never vouch
            // for a freshly adopted address.
            emailChanged = !string.Equals(coreUser.Email, request.Email, StringComparison.OrdinalIgnoreCase);

            // N-4 (N4-7): when the host enables strict change-email, reject any soft
            // mutation of the e-mail through /me/profile so every address change flows
            // through the verify-then-commit pipeline (IChangeEmailTokenStore +
            // ChangeEmailConfirmProcessor) — otherwise an attacker who hijacks a session
            // could silently rebind the account to an inbox they own.
            if (emailChanged && RejectSoftEmailChange(exchange))
            {
                MeProcessorHelpers.Reject(exchange, 400, "use_change_email_flow",
                    "Direct e-mail change via /me/profile is disabled by host policy. Use /me/change-email/request to start the strict verification flow.");
                return;
            }
            coreUpdate.Email = request.Email;
            coreChanged = true;
        }
        if (request.PhoneNumber != null)
        {
            var err = IdentityProcessorHelpers.ValidatePhoneNumber(request.PhoneNumber);
            if (err != null) { MeProcessorHelpers.Reject(exchange, 400, "validation_error", err); return; }
            coreUpdate.Phone = request.PhoneNumber;
            coreChanged = true;
        }

        if (coreChanged)
            coreUser = await redb.UserProvider.UpdateUserAsync(coreUser, coreUpdate);

        // --- Update OIDC extension ---
        var oidcObj = await MeProcessorHelpers.LoadOidcProps(redb, callerId);
        bool oidcChanged = false;

        // N4-6: lazily materialize the OIDC row when we need to flip EmailVerified=false
        // on an e-mail change, even if the request carried no other OIDC fields.
        var resetEmailVerified = emailChanged && ShouldResetEmailVerifiedOnChange(exchange);

        if (oidcObj is null && (resetEmailVerified || request.GivenName != null || request.FamilyName != null
            || request.Picture != null || request.Address != null
            || request.CustomClaims is { Count: > 0 }))
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = coreUser.Login;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }

        if (oidcObj is not null)
        {
            if (resetEmailVerified && oidcObj.Props.EmailVerified)
            {
                oidcObj.Props.EmailVerified = false;
                oidcChanged = true;
            }
            if (request.GivenName != null) { oidcObj.Props.GivenName = request.GivenName; oidcChanged = true; }
            if (request.FamilyName != null) { oidcObj.Props.FamilyName = request.FamilyName; oidcChanged = true; }
            if (request.Picture != null) { oidcObj.Props.Picture = request.Picture; oidcChanged = true; }
            if (request.Address != null)
            {
                oidcObj.Props.Address = new AddressClaim
                {
                    StreetAddress = request.Address.StreetAddress,
                    Locality = request.Address.Locality,
                    Region = request.Address.Region,
                    PostalCode = request.Address.PostalCode,
                    Country = request.Address.Country,
                    Formatted = request.Address.Formatted
                };
                oidcChanged = true;
            }
            if (request.CustomClaims is { Count: > 0 })
            {
                oidcObj.Props.CustomClaims ??= new Dictionary<string, string>();
                foreach (var (key, value) in request.CustomClaims)
                    oidcObj.Props.CustomClaims[key] = value;
                oidcChanged = true;
            }

            if (oidcChanged)
                await redb.SaveAsync(oidcObj);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = MeProcessorHelpers.MapToResponse(
            coreUser, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserUpdated;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = coreUser.Login, SelfService = true };
    }
}
