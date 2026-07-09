using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using CoreCreateUserRequest = redb.Core.Models.Users.CreateUserRequest;
using CoreUpdateUserRequest = redb.Core.Models.Users.UpdateUserRequest;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// CRUD management processor for identity users.
/// Users live in the relational <c>_users</c> table (via <see cref="redb.Core.Providers.IUserProvider"/>).
/// OIDC profile extensions live in PROPS (<see cref="UserProps"/>) linked via <c>RedbObject.Key = _users._id</c>.
/// Dispatches on the "operation" header: create, read, update, delete, list, search, change-password.
/// </summary>
internal sealed class UserManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public UserManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "create":
                await Create(redb, exchange, ct);
                break;
            case "read":
                await Read(redb, exchange, ct);
                break;
            case "update":
                await Update(redb, exchange, ct);
                break;
            case "delete":
                await Delete(redb, exchange, ct);
                break;
            case "list":
                await List(redb, exchange, ct);
                break;
            case "search":
                await Search(redb, exchange, ct);
                break;
            case "change-password":
                await ChangePassword(redb, exchange, ct);
                break;
            case "admin-reset-password":
                await AdminResetPassword(redb, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private async Task Create(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as CreateUserRequest;

        // Validate Login
        var err = IdentityProcessorHelpers.ValidateIdentifier(request?.Login, "Login");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        // Validate Password (H10 — full policy: length + composition + history + breach)
        err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request!.Password, userId: null, "Password", ct);
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        // Validate optional fields
        err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateEmail(request.Email);
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidatePhoneNumber(request.PhoneNumber);
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        // Create user in _users table via Core
        IRedbUser coreUser;
        try
        {
            coreUser = await redb.UserProvider.CreateUserAsync(new CoreCreateUserRequest
            {
                Login = request.Login,
                Password = request.Password,
                Name = request.DisplayName ?? request.Login,
                Email = request.Email,
                Phone = request.PhoneNumber,
                Enabled = true
            });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already taken"))
        {
            SetError(exchange, "duplicate", $"Login '{request.Login}' already exists");
            return;
        }

        // S2.3 — enforce global claim schema on create. Operator may supply
        // CustomClaims in the request to satisfy required definitions; the
        // helper fills in DefaultValues for required claims without one set
        // and rejects when a required claim has neither value nor default.
        var (defaultClaims, schemaErr) = await Services.ClaimSchemaValidator.EnforceGlobalAsync(redb, request.CustomClaims, ct);
        if (schemaErr is not null)
        {
            SetError(exchange, "validation_error", schemaErr);
            return;
        }

        // Save OIDC profile extension linked via key = _users._id.
        // value_guid: stable, instance-unique public identity used as the OIDC `sub` claim
        // (avoids cross-Identity-instance bigint collisions on _users._id sequences).
        var oidcObj = new RedbObject<UserProps>(new UserProps
        {
            GivenName = request.GivenName,
            FamilyName = request.FamilyName,
            Picture = request.Picture,
            CustomClaims = defaultClaims is { Count: > 0 } ? defaultClaims : null,
        });
        oidcObj.name = coreUser.Login;
        oidcObj.key = coreUser.Id;
        oidcObj.value_guid = Guid.NewGuid();
        await redb.SaveAsync(oidcObj);

        // H10 — record initial password in history so the user cannot immediately
        // "change" back to the bootstrap password. PERF: pass the in-tx redb so the
        // write reuses the same connection (avoids a 30 s deadlock against the open tx).
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, redb, coreUser.Id, request.Password, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(coreUser, oidcObj.Props, oidcObj.DateCreate, oidcObj.DateModify, oidcObj.value_guid);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserCreated;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = request.Login };
    }

    private async Task Read(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        IRedbUser? coreUser = null;

        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("id", out var idVal) && idVal != null
                && long.TryParse(idVal.ToString(), out var id) && id > 0)
                coreUser = await redb.UserProvider.GetUserByIdAsync(id);
            else if (dict.TryGetValue("login", out var loginVal) && loginVal is string login
                     && !string.IsNullOrEmpty(login))
                coreUser = await redb.UserProvider.GetUserByLoginAsync(login);
            else
                throw new InvalidOperationException("Either 'id' or 'login' required");
        }
        else
        {
            throw new InvalidOperationException("Expected body with 'id' or 'login'");
        }

        if (coreUser is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = "User not found" };
            return;
        }

        var oidcObj = await LoadOidcProps(redb, coreUser.Id);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(coreUser, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify, oidcObj?.value_guid);
    }

    private async Task Update(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as UpdateUserRequest;
        if (request is null || request.Id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(request.Id);
        if (coreUser is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"User {request.Id} not found" };
            return;
        }

        // Update _users fields via Core
        var coreUpdate = new CoreUpdateUserRequest();
        bool coreChanged = false;

        if (request.DisplayName != null)
        {
            var err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
            if (err != null) { SetError(exchange, "validation_error", err); return; }
            coreUpdate.Name = request.DisplayName;
            coreChanged = true;
        }
        if (request.Status != null)
        {
            if (request.Status is not ("active" or "blocked" or "pending"))
            {
                SetError(exchange, "validation_error", "Status must be 'active', 'blocked', or 'pending'");
                return;
            }
            coreUpdate.Enabled = request.Status == "active";
            coreChanged = true;
        }
        if (request.Email != null)
        {
            var err = IdentityProcessorHelpers.ValidateEmail(request.Email);
            if (err != null) { SetError(exchange, "validation_error", err); return; }
            coreUpdate.Email = request.Email;
            coreChanged = true;
        }
        if (request.PhoneNumber != null)
        {
            var err = IdentityProcessorHelpers.ValidatePhoneNumber(request.PhoneNumber);
            if (err != null) { SetError(exchange, "validation_error", err); return; }
            coreUpdate.Phone = request.PhoneNumber;
            coreChanged = true;
        }

        if (coreChanged)
            coreUser = await redb.UserProvider.UpdateUserAsync(coreUser, coreUpdate);

        // Update OIDC extension props
        var oidcObj = await LoadOidcProps(redb, coreUser.Id);
        bool oidcChanged = false;

        if (oidcObj is null && (request.EmailVerified.HasValue || request.PhoneNumberVerified.HasValue
            || request.GivenName != null || request.FamilyName != null || request.Picture != null
            || request.Address != null || request.CustomClaims is { Count: > 0 }))
        {
            // Create OIDC props on first OIDC field update
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = coreUser.Login;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }

        if (oidcObj is not null)
        {
            if (request.EmailVerified.HasValue) { oidcObj.Props.EmailVerified = request.EmailVerified.Value; oidcChanged = true; }
            if (request.PhoneNumberVerified.HasValue) { oidcObj.Props.PhoneNumberVerified = request.PhoneNumberVerified.Value; oidcChanged = true; }
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
            // S2.3 — claim-schema enforcement. We validate the EFFECTIVE
            // post-update CustomClaims dict (existing ∪ incoming) against
            // every global ClaimDefinition. Required-but-missing without a
            // DefaultValue → 400 validation_error; required-but-missing
            // WITH a DefaultValue → fill it in; present values → type +
            // regex check.
            if (request.CustomClaims is not null || oidcObj.Props.CustomClaims is { Count: > 0 })
            {
                var effective = new Dictionary<string, string>(oidcObj.Props.CustomClaims ?? new(), StringComparer.Ordinal);
                if (request.CustomClaims is not null)
                {
                    foreach (var (k, v) in request.CustomClaims) effective[k] = v;
                }

                var (normalized, claimErr) = await Services.ClaimSchemaValidator.EnforceGlobalAsync(redb, effective, ct);
                if (claimErr is not null)
                {
                    SetError(exchange, "validation_error", claimErr);
                    return;
                }

                // Replace the stored dict with the normalized result (defaults
                // applied + types verified). Empty dict clears CustomClaims.
                if (normalized is null || normalized.Count == 0)
                {
                    if (oidcObj.Props.CustomClaims is { Count: > 0 })
                    {
                        oidcObj.Props.CustomClaims = null;
                        oidcChanged = true;
                    }
                }
                else
                {
                    oidcObj.Props.CustomClaims = normalized;
                    oidcChanged = true;
                }
            }

            if (oidcChanged)
                await redb.SaveAsync(oidcObj);
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(coreUser, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify, oidcObj?.value_guid);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserUpdated;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = coreUser.Login };
    }

    private async Task Delete(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(id);
        if (coreUser is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { success = true, alreadyAbsent = true };
            return;
        }

        // Cascade revoke BEFORE soft-deleting the user row. SessionService.LogoutAsync
        // kills every session for this user AND every OpenIddict authorization linked
        // to those sessions — that in turn invalidates all access/refresh tokens.
        // Same shape as the post-password-change revocation flow (UserManagementProcessor
        // .ChangePassword), so the cascade story stays uniform.
        var sessionsRevoked = await new SessionService(redb).LogoutAsync(coreUser.Id, ct);

        // Soft-delete the user row — _enabled=false + _date_dismiss now, _name suffixed
        // for tombstoning. Login STAYS as-is (immutable per protect_system_users trigger).
        await redb.UserProvider.DeleteUserAsync(coreUser);

        // Delete OIDC extension if it exists — re-parents under the trash scheme so it
        // vanishes from regular queries; background-deletion service handles the
        // physical purge of dependent _values rows on its own connection.
        var oidcObj = await LoadOidcProps(redb, id);
        if (oidcObj is not null)
        {
            var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
            await IdentityDeletionHelper.DeleteAsync(redb, bg, oidcObj.id);
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, sessionsRevoked };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserDeleted;
        exchange.Properties["identity-event-data"] = new { UserId = id.ToString(), Id = id, SessionsRevoked = sessionsRevoked };
    }

    private async Task List(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();
        var count = Math.Min(request.Count, 100);

        var criteria = new redb.Core.Models.Users.UserSearchCriteria
        {
            ExcludeSystemUsers = true,
            Limit = count,
            Offset = request.Offset
        };
        var users = await redb.UserProvider.GetUsersAsync(criteria);
        var total = await redb.UserProvider.GetUserCountAsync();

        // Batch-load OIDC extensions for all users (one query, not N).
        var oidcByUserId = await LoadOidcPropsBatchAsync(redb, users.Select(u => u.Id).ToList()).ConfigureAwait(false);
        var responses = new List<UserResponse>(users.Count);
        foreach (var u in users)
        {
            oidcByUserId.TryGetValue(u.Id, out var oidcObj);
            responses.Add(MapToResponse(u, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify, oidcObj?.value_guid));
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<UserResponse>
        {
            Items = responses,
            Total = total,
            Offset = request.Offset,
            Count = request.Count
        };
    }

    private async Task Search(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("query", out var qVal) || qVal is not string searchQuery
            || string.IsNullOrEmpty(searchQuery))
        {
            SetError(exchange, "validation_error", "Search 'query' is required");
            return;
        }

        // Paginated search — replaces the legacy hard-cap @ 50. Operator can
        // walk past page 1 when a noisy tenant has lots of admin_probe_*
        // residue ahead of the real target.
        var offset = 0;
        if (dict.TryGetValue("offset", out var oVal) && oVal is not null && int.TryParse(oVal.ToString(), out var parsedOffset))
            offset = Math.Max(0, parsedOffset);
        var count = 25;
        if (dict.TryGetValue("count", out var cVal) && cVal is not null && int.TryParse(cVal.ToString(), out var parsedCount))
            count = Math.Clamp(parsedCount, 1, 200);

        var criteria = new redb.Core.Models.Users.UserSearchCriteria
        {
            LoginPattern = searchQuery,
            ExcludeSystemUsers = true,
            Limit = count,
            Offset = offset
        };

        var users = await redb.UserProvider.GetUsersAsync(criteria);
        var total = await redb.UserProvider.CountUsersAsync(new redb.Core.Models.Users.UserSearchCriteria
        {
            LoginPattern = searchQuery,
            ExcludeSystemUsers = true,
        });

        var oidcByUserId = await LoadOidcPropsBatchAsync(redb, users.Select(u => u.Id).ToList()).ConfigureAwait(false);
        var responses = new List<UserResponse>(users.Count);
        foreach (var u in users)
        {
            oidcByUserId.TryGetValue(u.Id, out var oidcObj);
            responses.Add(MapToResponse(u, oidcObj?.Props, oidcObj?.DateCreate, oidcObj?.DateModify, oidcObj?.value_guid));
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<UserResponse>
        {
            Items = responses,
            Total = total,
            Offset = offset,
            Count = count
        };
    }

    private async Task ChangePassword(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ChangePasswordRequest;
        if (request is null || request.Id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }
        if (string.IsNullOrEmpty(request.OldPassword))
        {
            SetError(exchange, "validation_error", "OldPassword is required");
            return;
        }

        var err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request.NewPassword, request.Id, "NewPassword", ct);
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        if (request.OldPassword == request.NewPassword)
        {
            SetError(exchange, "validation_error", "NewPassword must differ from OldPassword");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(request.Id);
        if (coreUser is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"User {request.Id} not found" };
            return;
        }

        var changed = await redb.UserProvider.ChangePasswordAsync(coreUser, request.OldPassword, request.NewPassword);
        if (!changed)
        {
            SetError(exchange, "invalid_password", "Old password is incorrect");
            return;
        }

        // H10 — record the new password in history (post-success).
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, coreUser.Id, request.NewPassword, ct);

        // C7 (OWASP Session Management): when a user's password changes, every session
        // that was authenticated with the old password must be invalidated. This also
        // revokes all OpenIddict authorizations linked to those sessions, which in turn
        // invalidates any access/refresh tokens issued from them. The user must
        // re-authenticate with the new password.
        var sessionsRevoked = await new SessionService(redb).LogoutAsync(coreUser.Id, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordChanged;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = coreUser.Login, SessionsRevoked = sessionsRevoked };
    }

    /// <summary>
    /// Admin-side password reset. Bypasses the OldPassword challenge that the
    /// user-self change-password flow requires. Same post-success side effects
    /// as <see cref="ChangePassword"/>: password history, session revocation,
    /// audit event (with explicit <c>AdminReset = true</c> marker so the
    /// timeline distinguishes operator-initiated resets from user-initiated
    /// changes).
    /// </summary>
    private async Task AdminResetPassword(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as AdminResetPasswordRequest;
        if (request is null || request.Id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }
        if (string.IsNullOrEmpty(request.NewPassword))
        {
            SetError(exchange, "validation_error", "NewPassword is required");
            return;
        }

        var err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request.NewPassword, request.Id, "NewPassword", ct);
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(request.Id);
        if (coreUser is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"User {request.Id} not found" };
            return;
        }

        var ok = await redb.UserProvider.SetPasswordAsync(coreUser, request.NewPassword);
        if (!ok)
        {
            SetError(exchange, "internal_error", "Failed to set password");
            return;
        }

        // H10 — record the new password in history (post-success).
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, coreUser.Id, request.NewPassword, ct);

        // Same session-revocation semantics as user-initiated change-password
        // (C7 / OWASP Session Management) — every existing session must die so
        // the user can't keep an active workspace tied to the previous secret.
        var sessionsRevoked = await new SessionService(redb).LogoutAsync(coreUser.Id, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, sessionsRevoked };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordChanged;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = coreUser.Id.ToString(),
            Login = coreUser.Login,
            SessionsRevoked = sessionsRevoked,
            AdminReset = true,
        };
    }

    // --- Helpers ---

    private static async Task<RedbObject<UserProps>?> LoadOidcProps(IRedbService redb, long userId)
    {
        return await redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// Batch-load the OIDC props row for every supplied <paramref name="userIds"/> in a
    /// single round-trip. Returns a dictionary keyed by <c>RedbObject.key</c> (which equals
    /// <c>_users._id</c>); missing keys mean the user has no OIDC props row yet (legacy
    /// users — caller handles as <c>null</c>). The list endpoints used to fire one
    /// <see cref="LoadOidcProps"/> per user (rule #3 in PERF_RULES.md — silent N+1) which
    /// scaled as <c>O(users) × DB round-trip</c>; this collapses it to one query.
    /// </summary>
    private static async Task<Dictionary<long, RedbObject<UserProps>>> LoadOidcPropsBatchAsync(
        IRedbService redb, IReadOnlyList<long> userIds)
    {
        if (userIds.Count == 0) return new Dictionary<long, RedbObject<UserProps>>(0);
        var keys = userIds.Select(id => (long?)id).ToList();
        var props = await redb.Query<UserProps>()
            .WhereRedb(o => keys.Contains(o.Key))
            .ToListAsync()
            .ConfigureAwait(false);
        var map = new Dictionary<long, RedbObject<UserProps>>(props.Count);
        foreach (var p in props)
        {
            if (p.key is { } k) map[k] = p;
        }
        return map;
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static UserResponse MapToResponse(
        IRedbUser user, UserProps? oidc,
        DateTimeOffset? createdAt, DateTimeOffset? modifiedAt,
        Guid? subjectGuid = null) => new()
    {
        Id = user.Id,
        SubjectGuid = subjectGuid is { } g && g != Guid.Empty ? g : null,
        Login = user.Login,
        DisplayName = user.Name,
        Status = user.Enabled ? "active" : "blocked",
        Email = user.Email,
        EmailVerified = oidc?.EmailVerified ?? false,
        PhoneNumber = user.Phone,
        PhoneNumberVerified = oidc?.PhoneNumberVerified ?? false,
        GivenName = oidc?.GivenName,
        FamilyName = oidc?.FamilyName,
        Picture = oidc?.Picture,
        Address = oidc?.Address is { } addr ? new Contracts.Users.AddressDto
        {
            StreetAddress = addr.StreetAddress,
            Locality = addr.Locality,
            Region = addr.Region,
            PostalCode = addr.PostalCode,
            Country = addr.Country,
            Formatted = addr.Formatted
        } : null,
        CustomClaims = oidc?.CustomClaims,
        ExternalIdentities = oidc?.ExternalIdentities is { Count: > 0 } extIds
            ? extIds.ToDictionary(
                kvp => kvp.Key,
                kvp => new Contracts.Users.ExternalIdentityDto
                {
                    Sub = kvp.Value.Sub,
                    LinkedAt = kvp.Value.LinkedAt
                })
            : null,
        CreatedAt = createdAt ?? user.DateRegister,
        ModifiedAt = modifiedAt ?? user.DateRegister
    };
}
