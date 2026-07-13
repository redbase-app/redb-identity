using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Contracts.Scim;
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
/// SCIM 2.0 Users endpoint processor (RFC 7644 §3.2–3.5).
/// Dispatches on "operation" header: list, read, create, replace, patch, delete.
/// Maps SCIM User resources to core <c>_users</c> table + PROPS <see cref="UserProps"/>.
/// </summary>
internal sealed class ScimUserProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ScimUserProcessor(IRouteContext context, string? redbName = null)
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
            case "list":    await List(redb, exchange, ct); break;
            case "read":    await Read(redb, exchange, ct); break;
            case "create":  await Create(redb, exchange, ct); break;
            case "replace": await Replace(redb, exchange, ct); break;
            case "patch":   await Patch(redb, exchange, ct); break;
            case "delete":  await Delete(redb, exchange, ct); break;
            default:
                SetScimError(exchange, 400, null, $"Unknown SCIM operation: {operation}");
                break;
        }
    }

    private static string GetBaseUrl(IExchange exchange)
        => exchange.In.GetHeader<string>("scim.BaseUrl") ?? string.Empty;

    // ── List (GET /Users) ───────────────────────────────────────

    private async Task List(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var baseUrl = GetBaseUrl(exchange);
        var dict = exchange.In.Body as Dictionary<string, object?> ?? new();
        var startIndex = GetInt(dict, "startIndex", 1);
        var count = Math.Min(GetInt(dict, "count", 25), 100);
        var filterStr = dict.GetValueOrDefault("filter")?.ToString();
        var sortBy = dict.GetValueOrDefault("sortBy")?.ToString();
        var sortOrder = dict.GetValueOrDefault("sortOrder")?.ToString();

        var filter = ScimFilterParser.Parse(filterStr);

        // ── Filtered queries ──

        if (filter is not null)
        {
            // userName eq → direct login lookup (fast path)
            if (filter is { Attribute: "username", Operator: "eq" })
            {
                var user = await redb.UserProvider.GetUserByLoginAsync(filter.Value);
                if (user is null || !user.Enabled)
                {
                    SetResult(exchange, EmptyList(startIndex));
                    return;
                }
                var oidc = await LoadOidcProps(redb, user.Id);
                SetResult(exchange, new ScimListResponse<ScimUser>
                {
                    TotalResults = 1, StartIndex = startIndex, ItemsPerPage = 1,
                    Resources = [MapToScimUser(user, oidc, baseUrl: baseUrl,
                        managerNames: await ResolveManagerNamesAsync(redb, [oidc?.Props]))]
                });
                return;
            }

            // externalId eq → PROPS query on UserProps.ScimExternalId
            if (filter is { Attribute: "externalid", Operator: "eq" })
            {
                var oidcObj = await redb.Query<UserProps>()
                    .Where(p => p.ScimExternalId == filter.Value)
                    .FirstOrDefaultAsync();

                if (oidcObj?.key is null)
                {
                    SetResult(exchange, EmptyList(startIndex));
                    return;
                }
                var user = await redb.UserProvider.GetUserByIdAsync(oidcObj.key.Value);
                if (user is null || !user.Enabled)
                {
                    SetResult(exchange, EmptyList(startIndex));
                    return;
                }
                SetResult(exchange, new ScimListResponse<ScimUser>
                {
                    TotalResults = 1, StartIndex = startIndex, ItemsPerPage = 1,
                    Resources = [MapToScimUser(user, oidcObj, baseUrl: baseUrl,
                        managerNames: await ResolveManagerNamesAsync(redb, [oidcObj?.Props]))]
                });
                return;
            }

            // Build UserSearchCriteria from SCIM filter for userName/displayName/emails.value
            var criteria = BuildUserCriteria(filter);
            if (criteria is not null)
            {
                criteria.ExcludeSystemUsers = true;
                criteria.Enabled = true;
                criteria.Limit = count;
                criteria.Offset = Math.Max(startIndex - 1, 0);
                ApplySortToCriteria(criteria, sortBy, sortOrder);

                // Count with same filters but no LIMIT/OFFSET
                var countCrit = BuildUserCriteria(filter)!;
                countCrit.ExcludeSystemUsers = true;
                countCrit.Enabled = true;
                var filteredTotal = await redb.UserProvider.CountUsersAsync(countCrit);

                var matched = await redb.UserProvider.GetUsersAsync(criteria);
                var resources = await BatchMapUsers(redb, matched, baseUrl);
                SetResult(exchange, new ScimListResponse<ScimUser>
                {
                    TotalResults = filteredTotal, StartIndex = startIndex,
                    ItemsPerPage = resources.Count, Resources = resources
                });
                return;
            }

            // Unsupported filter → error
            SetScimError(exchange, 400, "invalidFilter",
                $"Unsupported filter: {filter.Attribute} {filter.Operator}. " +
                "Supported attributes: userName, displayName, emails.value, externalId. " +
                "Supported operators: eq, sw, co, pr");
            return;
        }

        // ── No filter → paginated list ──

        var offset = Math.Max(startIndex - 1, 0); // SCIM 1-based → 0-based
        var searchCriteria = new redb.Core.Models.Users.UserSearchCriteria
        {
            ExcludeSystemUsers = true,
            Enabled = true,
            Limit = count,
            Offset = offset
        };
        ApplySortToCriteria(searchCriteria, sortBy, sortOrder);

        var pageUsers = await redb.UserProvider.GetUsersAsync(searchCriteria);

        // Count with same filters but no LIMIT/OFFSET — lightweight SELECT COUNT(*)
        var countCriteria = new redb.Core.Models.Users.UserSearchCriteria
        {
            ExcludeSystemUsers = true,
            Enabled = true
        };
        var total = await redb.UserProvider.CountUsersAsync(countCriteria);

        // Batch-load PROPS props for the page in a single query
        var userIds = pageUsers.Select(u => (long?)u.Id).ToList();
        var oidcObjects = userIds.Count > 0
            ? await redb.Query<UserProps>()
                .WhereRedb(o => userIds.Contains(o.Key))
                .ToListAsync()
            : new List<RedbObject<UserProps>>();
        var oidcDict = oidcObjects
            .Where(o => o.key.HasValue)
            .ToDictionary(o => o.key!.Value);

        var scimUsers = new List<ScimUser>(pageUsers.Count);
        // One resolve for the whole page — not one per row.
        var pageManagers = await ResolveManagerNamesAsync(redb, oidcDict.Values.Select(o => o?.Props));
        foreach (var u in pageUsers)
        {
            oidcDict.TryGetValue(u.Id, out var oidc);
            scimUsers.Add(MapToScimUser(u, oidc, baseUrl: baseUrl, managerNames: pageManagers));
        }

        SetResult(exchange, new ScimListResponse<ScimUser>
        {
            TotalResults = total,
            StartIndex = startIndex,
            ItemsPerPage = scimUsers.Count,
            Resources = scimUsers
        });
    }

    // ── Read (GET /Users/{id}) ──────────────────────────────────

    private async Task Read(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractResourceId(exchange);
        if (id is null) { SetScimError(exchange, 400, null, "Resource id is required"); return; }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(id.Value);
        if (coreUser is null || !coreUser.Enabled)
        {
            SetScimError(exchange, 404, null, $"User {id} not found");
            return;
        }

        var oidc = await LoadOidcProps(redb, coreUser.Id);
        var groups = await LoadUserGroups(redb, coreUser.Id);

        SetResult(exchange, MapToScimUser(coreUser, oidc, groups, GetBaseUrl(exchange),
            managerNames: await ResolveManagerNamesAsync(redb, [oidc?.Props])));
        SetETagHeader(exchange, coreUser.Hash);
    }

    // ── Create (POST /Users) ────────────────────────────────────

    private async Task Create(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var scimUser = exchange.In.Body as ScimUser;
        if (scimUser is null || string.IsNullOrEmpty(scimUser.UserName))
        {
            SetScimError(exchange, 400, null, "userName is required");
            return;
        }

        // C4: Validate userName
        var userName = scimUser.UserName.Trim();
        if (userName.Length == 0)
        {
            SetScimError(exchange, 400, null, "userName cannot be empty");
            return;
        }
        if (userName.Length < 3 || userName.Length > 200)
        {
            SetScimError(exchange, 400, null, "userName must be between 3 and 200 characters");
            return;
        }
        scimUser.UserName = userName;

        // I5: Generate a strong password if not provided.
        // H10: when the SCIM client supplies a password, run it through the full policy
        // gate (length + composition + history + breach). Auto-generated 24-char secrets
        // skip validation — they are produced by GeneratePassword() which already meets
        // every reasonable rule and is never seen by a human.
        string password;
        if (scimUser.Password is { Length: > 0 })
        {
            var pwErr = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
                exchange, _context, scimUser.Password, userId: null, "password", ct);
            if (pwErr != null) { SetScimError(exchange, 400, "invalidValue", pwErr); return; }
            password = scimUser.Password;
        }
        else
        {
            password = GeneratePassword(24);
        }
        var primaryEmail = GetPrimaryEmail(scimUser);
        var primaryPhone = GetPrimaryPhone(scimUser);

        // C5: Create directly, rely on DB constraint for uniqueness
        IRedbUser coreUser;
        try
        {
            coreUser = await redb.UserProvider.CreateUserAsync(new CoreCreateUserRequest
            {
                Login = scimUser.UserName,
                Password = password,
                Name = scimUser.DisplayName ?? scimUser.UserName,
                Email = primaryEmail,
                Phone = primaryPhone,
                Enabled = scimUser.Active
            });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already taken"))
        {
            SetScimError(exchange, 409, "uniqueness", $"userName '{scimUser.UserName}' already exists");
            return;
        }
        catch (Exception ex) when (ex.Message.Contains("duplicate") || ex.Message.Contains("unique")
                                   || ex.Message.Contains("_users__login_key")
                                   || ex.Message.Contains("already exists"))
        {
            SetScimError(exchange, 409, "uniqueness", $"userName '{scimUser.UserName}' already exists");
            return;
        }

        // PROPS OIDC extension. value_guid: stable, instance-unique public identity used
        // as the OIDC `sub` claim.
        var oidcObj = new RedbObject<UserProps>(new UserProps
        {
            GivenName = scimUser.Name?.GivenName,
            FamilyName = scimUser.Name?.FamilyName,
            Picture = scimUser.Photos?.FirstOrDefault()?.Value,
            ScimExternalId = scimUser.ExternalId,
            Address = MapScimAddress(scimUser.Addresses?.FirstOrDefault())
        });
        ApplyEnterprise(scimUser.Enterprise, oidcObj.Props);
        oidcObj.name = coreUser.Login;
        oidcObj.key = coreUser.Id;
        oidcObj.value_guid = Guid.NewGuid();
        await redb.SaveAsync(oidcObj);

        // H10 — record initial password in history (covers both client-supplied and
        // auto-generated passwords; reuse blocked on subsequent admin rotation).
        await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
            exchange, _context, redb, coreUser.Id, password, ct);

        // I1: RFC 7644 §3.3 — return 201 Created with Location + ETag headers.
        // RFC 7644 §3.14 requires the version (ETag) to be included on every resource
        // representation when versioning is advertised in ServiceProviderConfig; without
        // it the client cannot acquire the initial ETag for subsequent If-Match writes.
        SetResult(exchange, MapToScimUser(coreUser, oidcObj, baseUrl: GetBaseUrl(exchange),
            managerNames: await ResolveManagerNamesAsync(redb, [oidcObj.Props])));
        exchange.Out!.Headers["scim.ResponseCode"] = 201;
        exchange.Out!.Headers["scim.Location"] = $"/scim/v2/Users/{coreUser.Id}";
        SetETagHeader(exchange, coreUser.Hash);
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimUserCreated;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = scimUser.UserName };
    }

    // ── Replace (PUT /Users/{id}) ───────────────────────────────

    private async Task Replace(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var scimUser = exchange.In.Body as ScimUser;
        if (scimUser is null || string.IsNullOrEmpty(scimUser.Id))
        {
            SetScimError(exchange, 400, null, "Resource id and body are required");
            return;
        }

        if (!long.TryParse(scimUser.Id, out var id) || id <= 0)
        {
            SetScimError(exchange, 400, null, "Invalid resource id");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(id);
        if (coreUser is null || !coreUser.Enabled)
        {
            SetScimError(exchange, 404, null, $"User {id} not found");
            return;
        }

        // ETag precondition check
        if (!CheckIfMatch(exchange, coreUser.Hash)) return;

        var primaryEmail = GetPrimaryEmail(scimUser);
        var primaryPhone = GetPrimaryPhone(scimUser);

        // userName (_login) is immutable — compare case-insensitively since logins are stored lowercase
        if (!string.IsNullOrEmpty(scimUser.UserName)
            && !string.Equals(scimUser.UserName, coreUser.Login, StringComparison.OrdinalIgnoreCase))
        {
            SetScimError(exchange, 400, "mutability",
                "Attribute 'userName' is immutable and cannot be changed after creation");
            return;
        }

        var updateReq = new CoreUpdateUserRequest
        {
            Name = scimUser.DisplayName ?? scimUser.UserName,
            Email = primaryEmail,
            Phone = primaryPhone,
            Enabled = scimUser.Active
        };

        coreUser = await redb.UserProvider.UpdateUserAsync(coreUser, updateReq);

        // Full replace of PROPS extension
        var oidcObj = await LoadOidcProps(redb, id)
            ?? new RedbObject<UserProps>(new UserProps()) { value_guid = Guid.NewGuid() };
        oidcObj.name = coreUser.Login;
        oidcObj.key = coreUser.Id;
        oidcObj.Props = new UserProps
        {
            GivenName = scimUser.Name?.GivenName,
            FamilyName = scimUser.Name?.FamilyName,
            Picture = scimUser.Photos?.FirstOrDefault()?.Value,
            ScimExternalId = scimUser.ExternalId,
            Address = MapScimAddress(scimUser.Addresses?.FirstOrDefault())
        };
        // PUT is a full replace (RFC 7644 §3.5.1): an absent extension means "the user has none",
        // so ApplyEnterprise writing nulls into a fresh UserProps is the correct outcome, not a bug.
        ApplyEnterprise(scimUser.Enterprise, oidcObj.Props);
        await redb.SaveAsync(oidcObj);

        SetResult(exchange, MapToScimUser(coreUser, oidcObj,
            baseUrl: GetBaseUrl(exchange),
            managerNames: await ResolveManagerNamesAsync(redb, [oidcObj.Props])));
        SetETagHeader(exchange, coreUser.Hash);
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimUserReplaced;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = coreUser.Login };
    }

    // ── Patch (PATCH /Users/{id}) ───────────────────────────────

    private async Task Patch(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
        {
            SetScimError(exchange, 400, null, "Invalid patch request");
            return;
        }

        var idStr = dict.GetValueOrDefault("id")?.ToString();
        if (!long.TryParse(idStr, out var id) || id <= 0)
        {
            SetScimError(exchange, 400, null, "Resource id is required");
            return;
        }

        var patch = dict.GetValueOrDefault("patch") as ScimPatchRequest;
        if (patch is null || patch.Operations.Count == 0)
        {
            SetScimError(exchange, 400, null, "PatchOp request with Operations is required");
            return;
        }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(id);
        if (coreUser is null || !coreUser.Enabled)
        {
            SetScimError(exchange, 404, null, $"User {id} not found");
            return;
        }

        // ETag precondition check
        if (!CheckIfMatch(exchange, coreUser.Hash)) return;

        var oidcObj = await LoadOidcProps(redb, id);
        var oidcCreated = false;
        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = coreUser.Login;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
            oidcCreated = true;
        }

        var coreUpdate = new CoreUpdateUserRequest();
        bool coreChanged = false;
        bool oidcChanged = false;
        string? newPassword = null;

        foreach (var op in patch.Operations)
        {
            var normalizedOp = op.Op?.ToLowerInvariant();
            var path = op.Path?.ToLowerInvariant();

            // RFC 7644 §3.5.2 — an extension attribute is addressed by its fully-qualified URN, e.g.
            //   "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
            // Strip the namespace and fall through to the plain attribute name. We also accept the
            // bare name ("department"): it is what several provisioning clients send in practice, and
            // it is unambiguous here because no core User attribute carries any of these names.
            const string enterprisePrefix = ScimConstants.EnterpriseUserSchema + ":";
            if (path is not null && path.StartsWith(
                    enterprisePrefix, StringComparison.OrdinalIgnoreCase))
            {
                path = path[enterprisePrefix.Length..];
            }

            switch (path)
            {
                case "employeenumber":
                    oidcObj.Props.EmployeeNumber = normalizedOp is "remove" ? null : GetStringValue(op.Value);
                    oidcChanged = true;
                    break;

                case "costcenter":
                    oidcObj.Props.CostCenter = normalizedOp is "remove" ? null : GetStringValue(op.Value);
                    oidcChanged = true;
                    break;

                case "organization":
                    oidcObj.Props.Organization = normalizedOp is "remove" ? null : GetStringValue(op.Value);
                    oidcChanged = true;
                    break;

                case "division":
                    oidcObj.Props.Division = normalizedOp is "remove" ? null : GetStringValue(op.Value);
                    oidcChanged = true;
                    break;

                case "department":
                    oidcObj.Props.Department = normalizedOp is "remove" ? null : GetStringValue(op.Value);
                    oidcChanged = true;
                    break;

                // `manager` is complex (§4.3): clients patch either the whole object or manager.value.
                // Both land on the same stored id — $ref and displayName are derived on read.
                case "manager":
                case "manager.value":
                    oidcObj.Props.ManagerId = normalizedOp is "remove"
                        ? null
                        : GetManagerId(op.Value);
                    oidcChanged = true;
                    break;

                case "username":
                    // userName (_login) is immutable at DB level (protect_system_users trigger)
                    if (normalizedOp is "add" or "replace")
                    {
                        var newLogin = GetStringValue(op.Value);
                        if (!string.Equals(newLogin, coreUser.Login, StringComparison.Ordinal))
                        {
                            SetScimError(exchange, 400, "mutability",
                                "Attribute 'userName' is immutable and cannot be changed after creation");
                            return;
                        }
                    }
                    break;

                case "displayname":
                    if (normalizedOp is "add" or "replace")
                    {
                        coreUpdate.Name = GetStringValue(op.Value);
                        coreChanged = true;
                    }
                    break;

                case "active":
                    if (normalizedOp is "add" or "replace")
                    {
                        coreUpdate.Enabled = GetBoolValue(op.Value) ?? true;
                        coreChanged = true;
                    }
                    break;

                // I9: PATCH password support (write-only)
                case "password":
                    if (normalizedOp is "add" or "replace")
                        newPassword = GetStringValue(op.Value);
                    break;

                case "name.givenname":
                    if (normalizedOp is "add" or "replace")
                    { oidcObj.Props.GivenName = GetStringValue(op.Value); oidcChanged = true; }
                    else if (normalizedOp is "remove")
                    { oidcObj.Props.GivenName = null; oidcChanged = true; }
                    break;

                case "name.familyname":
                    if (normalizedOp is "add" or "replace")
                    { oidcObj.Props.FamilyName = GetStringValue(op.Value); oidcChanged = true; }
                    else if (normalizedOp is "remove")
                    { oidcObj.Props.FamilyName = null; oidcChanged = true; }
                    break;

                case "externalid":
                    if (normalizedOp is "add" or "replace")
                    { oidcObj.Props.ScimExternalId = GetStringValue(op.Value); oidcChanged = true; }
                    else if (normalizedOp is "remove")
                    { oidcObj.Props.ScimExternalId = null; oidcChanged = true; }
                    break;

                case "emails":
                    if (normalizedOp is "add" or "replace")
                    {
                        var email = GetPrimaryMultiValue(op.Value);
                        if (email is not null) { coreUpdate.Email = email; coreChanged = true; }
                    }
                    break;

                case "phonenumbers":
                    if (normalizedOp is "add" or "replace")
                    {
                        var phone = GetPrimaryMultiValue(op.Value);
                        if (phone is not null) { coreUpdate.Phone = phone; coreChanged = true; }
                    }
                    break;

                case null when normalizedOp is "add" or "replace":
                    // No path → value is a partial resource (Azure Entra pattern)
                    ApplyPartialResource(op.Value, coreUpdate, oidcObj.Props,
                        ref coreChanged, ref oidcChanged);
                    break;
            }
        }

        if (coreChanged)
            coreUser = await redb.UserProvider.UpdateUserAsync(coreUser, coreUpdate);

        // I9: Set password if patched (H10 — validate against policy first).
        var passwordChanged = !string.IsNullOrEmpty(newPassword);
        if (passwordChanged)
        {
            var pwErr = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
                exchange, _context, newPassword, coreUser.Id, "password", ct);
            if (pwErr != null) { SetScimError(exchange, 400, "invalidValue", pwErr); return; }
            await redb.UserProvider.SetPasswordAsync(coreUser, newPassword!);
            await IdentityProcessorHelpers.RecordPasswordHistoryAsync(
                exchange, _context, redb, coreUser.Id, newPassword!, ct);
        }

        if (oidcChanged || oidcCreated)
            await redb.SaveAsync(oidcObj);

        // C7: SCIM-driven password change must invalidate every existing session and
        // authorization for the user (same rule as the user-driven /change-password).
        // The user must re-authenticate with the new password.
        long sessionsRevoked = 0;
        if (passwordChanged)
            sessionsRevoked = await new SessionService(redb).LogoutAsync(coreUser.Id, ct);

        SetResult(exchange, MapToScimUser(coreUser, oidcObj, baseUrl: GetBaseUrl(exchange),
            managerNames: await ResolveManagerNamesAsync(redb, [oidcObj.Props])));
        SetETagHeader(exchange, coreUser.Hash);
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimUserPatched;
        exchange.Properties["identity-event-data"] = new { UserId = coreUser.Id.ToString(), Login = coreUser.Login, PasswordChanged = passwordChanged, SessionsRevoked = sessionsRevoked };
    }

    // ── Delete (DELETE /Users/{id}) ─────────────────────────────

    private async Task Delete(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractResourceId(exchange);
        if (id is null) { SetScimError(exchange, 400, null, "Resource id is required"); return; }

        var coreUser = await redb.UserProvider.GetUserByIdAsync(id.Value);
        if (coreUser is null) { SetScimError(exchange, 404, null, $"User {id} not found"); return; }

        // ETag precondition check
        if (!CheckIfMatch(exchange, coreUser.Hash)) return;

        // Delete PROPS extension first
        var oidcObj = await LoadOidcProps(redb, id.Value);
        if (oidcObj is not null)
        {
            var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
            await IdentityDeletionHelper.DeleteAsync(redb, bg, oidcObj.id);
        }

        // Soft-delete: disable user. UserProvider.DeleteUserAsync renames _login which is
        // blocked by the protect_system_users trigger ("Cannot change user login").
        // Disabling achieves the same SCIM semantics: user is gone from active queries.
        await redb.UserProvider.UpdateUserAsync(coreUser, new CoreUpdateUserRequest
        {
            Enabled = false
        });

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = null;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimUserDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id.Value };
    }

    // ── Data access helpers ─────────────────────────────────────

    private static long? ExtractResourceId(IExchange exchange)
    {
        if (exchange.In.Body is Dictionary<string, object?> dict
            && dict.TryGetValue("id", out var idVal) && idVal is not null
            && long.TryParse(idVal.ToString(), out var id) && id > 0)
            return id;
        return null;
    }

    private static async Task<List<ScimUser>> BatchMapUsers(
        IRedbService redb, List<IRedbUser> users, string? baseUrl)
    {
        if (users.Count == 0)
            return new List<ScimUser>();

        var userIds = users.Select(u => (long?)u.Id).ToList();
        var oidcObjects = await redb.Query<UserProps>()
            .WhereRedb(o => userIds.Contains(o.Key))
            .ToListAsync();
        var oidcDict = oidcObjects
            .Where(o => o.key.HasValue)
            .ToDictionary(o => o.key!.Value);

        var result = new List<ScimUser>(users.Count);
        var bulkManagers = await ResolveManagerNamesAsync(redb, oidcDict.Values.Select(o => o?.Props));
        foreach (var u in users)
        {
            oidcDict.TryGetValue(u.Id, out var oidc);
            result.Add(MapToScimUser(u, oidc, baseUrl: baseUrl, managerNames: bulkManagers));
        }
        return result;
    }

    private static async Task<RedbObject<UserProps>?> LoadOidcProps(IRedbService redb, long userId)
    {
        return await redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
    }

    private static async Task<List<IGroupService.UserGroupInfo>?> LoadUserGroups(
        IRedbService redb, long userId)
    {
        // Propagate errors instead of silently returning null \u2014 a SCIM client must NOT
        // receive a partial User resource missing its groups membership. Per RFC 7644
        // a 500 from the server is the correct outcome when the backend is down.
        var svc = new GroupService(redb);
        return await svc.GetUserGroupsAsync(userId);
    }

    // ── SCIM ↔ Core mapping ─────────────────────────────────────

    /// <summary>
    /// Builds a <see cref="redb.Core.Models.Users.UserSearchCriteria"/> from a parsed SCIM filter.
    /// Returns null when the filter attribute/operator combination is not supported.
    /// </summary>
    private static redb.Core.Models.Users.UserSearchCriteria? BuildUserCriteria(
        ScimFilterParser.ScimFilter filter)
    {
        var c = new redb.Core.Models.Users.UserSearchCriteria();

        // pr (presence) — always present for these attributes on active users
        if (filter.Operator == "pr")
        {
            return filter.Attribute switch
            {
                "username" or "displayname" or "active" => c, // always present
                "emails.value" => c, // email may be null but presence means "has email" — we accept all
                _ => null
            };
        }

        switch (filter.Attribute)
        {
            case "username":
                switch (filter.Operator)
                {
                    case "eq": c.LoginExact = filter.Value; break;
                    case "ne": c.LoginNotEqual = filter.Value; break;
                    case "sw": c.LoginStartsWith = filter.Value; break;
                    case "co": c.LoginPattern = filter.Value; break;
                    default: return null;
                }
                break;

            case "displayname":
                switch (filter.Operator)
                {
                    case "eq": c.NameExact = filter.Value; break;
                    case "ne": c.NameNotEqual = filter.Value; break;
                    case "sw": c.NameStartsWith = filter.Value; break;
                    case "co": c.NamePattern = filter.Value; break;
                    default: return null;
                }
                break;

            case "emails.value":
                switch (filter.Operator)
                {
                    case "eq": c.EmailExact = filter.Value; break;
                    case "ne": c.EmailNotEqual = filter.Value; break;
                    case "sw": c.EmailStartsWith = filter.Value; break;
                    case "co": c.EmailPattern = filter.Value; break;
                    default: return null;
                }
                break;

            default:
                return null;
        }

        return c;
    }

    /// <summary>
    /// Maps SCIM sortBy/sortOrder query params to UserSearchCriteria fields.
    /// </summary>
    private static void ApplySortToCriteria(
        redb.Core.Models.Users.UserSearchCriteria criteria,
        string? sortBy, string? sortOrder)
    {
        if (!string.IsNullOrEmpty(sortBy))
        {
            criteria.SortBy = sortBy.ToLowerInvariant() switch
            {
                "username" => redb.Core.Models.Users.UserSortField.Login,
                "displayname" => redb.Core.Models.Users.UserSortField.Name,
                "name.familyname" or "name.givenname" => redb.Core.Models.Users.UserSortField.Name,
                "emails.value" => redb.Core.Models.Users.UserSortField.Email,
                "meta.created" => redb.Core.Models.Users.UserSortField.DateRegister,
                "meta.lastmodified" => redb.Core.Models.Users.UserSortField.DateRegister,
                "id" => redb.Core.Models.Users.UserSortField.Id,
                _ => redb.Core.Models.Users.UserSortField.Name
            };
        }

        if (string.Equals(sortOrder, "descending", StringComparison.OrdinalIgnoreCase))
            criteria.SortDirection = redb.Core.Models.Users.UserSortDirection.Descending;
    }

    private static ScimUser MapToScimUser(
        IRedbUser user,
        RedbObject<UserProps>? oidc,
        List<IGroupService.UserGroupInfo>? groups = null,
        string? baseUrl = null,
        IReadOnlyDictionary<string, string>? managerNames = null)
    {
        var scimUser = new ScimUser
        {
            Id = user.Id.ToString(),
            UserName = user.Login ?? string.Empty,
            DisplayName = user.Name,
            Active = user.Enabled,
            ExternalId = oidc?.Props.ScimExternalId,
            Meta = new ScimMeta
            {
                ResourceType = "User",
                Created = oidc?.DateCreate ?? user.DateRegister,
                LastModified = oidc?.DateModify ?? user.DateRegister,
                Location = $"{baseUrl}/scim/v2/Users/{user.Id}",
                Version = user.Hash.HasValue ? $"W/\"{user.Hash.Value}\"" : null
            }
        };

        // Name
        if (oidc?.Props is { GivenName: not null } or { FamilyName: not null })
        {
            scimUser.Name = new ScimName
            {
                GivenName = oidc!.Props.GivenName,
                FamilyName = oidc.Props.FamilyName,
                Formatted = FormatName(oidc.Props.GivenName, oidc.Props.FamilyName)
            };
        }

        // Emails
        if (!string.IsNullOrEmpty(user.Email))
        {
            scimUser.Emails =
            [
                new ScimMultiValuedAttribute { Value = user.Email, Type = "work", Primary = true }
            ];
        }

        // Phone numbers
        if (!string.IsNullOrEmpty(user.Phone))
        {
            scimUser.PhoneNumbers =
            [
                new ScimMultiValuedAttribute { Value = user.Phone, Type = "work", Primary = true }
            ];
        }

        // Photos
        if (!string.IsNullOrEmpty(oidc?.Props.Picture))
        {
            scimUser.Photos =
            [
                new ScimMultiValuedAttribute { Value = oidc!.Props.Picture, Type = "photo", Primary = true }
            ];
        }

        // Enterprise User extension (RFC 7643 §4.3). Emitted only when something is actually
        // populated — an empty extension object plus its URN in `schemas` would tell the client
        // "this user has enterprise data" when it has none.
        //
        // `manager.$ref` and `manager.displayName` are derived, never stored: §4.3 marks displayName
        // read-only (the provider resolves it) and $ref is just the manager's resource URI. Deriving
        // them means they cannot rot out of sync with the manager's own record.
        if (oidc?.Props is { } p)
        {
            var enterprise = new ScimEnterpriseUser
            {
                EmployeeNumber = p.EmployeeNumber,
                CostCenter = p.CostCenter,
                Organization = p.Organization,
                Division = p.Division,
                Department = p.Department,
                Manager = string.IsNullOrEmpty(p.ManagerId) ? null : new ScimManager
                {
                    Value = p.ManagerId,
                    Ref = $"{baseUrl}/scim/v2/Users/{p.ManagerId}",
                    DisplayName = managerNames is not null
                                  && managerNames.TryGetValue(p.ManagerId, out var mn) ? mn : null
                }
            };

            if (!enterprise.IsEmpty)
            {
                scimUser.Enterprise = enterprise;
                // §3 — the extension's URN must be listed in `schemas`; that is what distinguishes
                // "the extension is present on this resource" from "the server supports it".
                scimUser.Schemas = [ScimConstants.UserSchema, ScimConstants.EnterpriseUserSchema];
            }
        }

        // Addresses
        if (oidc?.Props.Address is { } addr)
        {
            scimUser.Addresses =
            [
                new ScimAddress
                {
                    StreetAddress = addr.StreetAddress,
                    Locality = addr.Locality,
                    Region = addr.Region,
                    PostalCode = addr.PostalCode,
                    Country = addr.Country,
                    Formatted = addr.Formatted,
                    Primary = true
                }
            ];
        }

        // Groups (read-only, populated on individual reads)
        if (groups is { Count: > 0 })
        {
            scimUser.Groups = groups.Select(g => new ScimGroupRef
            {
                Value = g.GroupId.ToString(),
                Display = g.GroupName,
                Ref = $"/scim/v2/Groups/{g.GroupId}"
            }).ToList();
        }

        return scimUser;
    }

    private static string? GetPrimaryEmail(ScimUser user)
        => user.Emails?.FirstOrDefault(e => e.Primary)?.Value
           ?? user.Emails?.FirstOrDefault()?.Value;

    private static string? GetPrimaryPhone(ScimUser user)
        => user.PhoneNumbers?.FirstOrDefault(e => e.Primary)?.Value
           ?? user.PhoneNumbers?.FirstOrDefault()?.Value;

    private static string? FormatName(string? given, string? family) =>
        (given, family) switch
        {
            (not null, not null) => $"{given} {family}",
            (not null, _) => given,
            (_, not null) => family,
            _ => null
        };

    private static AddressClaim? MapScimAddress(ScimAddress? addr)
    {
        if (addr is null) return null;
        return new AddressClaim
        {
            StreetAddress = addr.StreetAddress,
            Locality = addr.Locality,
            Region = addr.Region,
            PostalCode = addr.PostalCode,
            Country = addr.Country,
            Formatted = addr.Formatted
        };
    }

    // ── PATCH value extraction ──────────────────────────────────

    private static string? GetStringValue(JsonElement? value)
    {
        if (value is null) return null;
        return value.Value.ValueKind == JsonValueKind.String
            ? value.Value.GetString()
            : value.Value.GetRawText();
    }

    private static bool? GetBoolValue(JsonElement? value)
    {
        if (value is null) return null;
        if (value.Value.ValueKind == JsonValueKind.True) return true;
        if (value.Value.ValueKind == JsonValueKind.False) return false;
        if (value.Value.ValueKind == JsonValueKind.String)
            return bool.TryParse(value.Value.GetString(), out var b) ? b : null;
        return null;
    }

    /// <summary>Extracts the primary value from a multi-valued array (emails, phoneNumbers).</summary>
    private static string? GetPrimaryMultiValue(JsonElement? value)
    {
        if (value is null) return null;
        if (value.Value.ValueKind == JsonValueKind.Array)
        {
            foreach (var elem in value.Value.EnumerateArray())
            {
                if (elem.TryGetProperty("primary", out var primary) && primary.GetBoolean()
                    && elem.TryGetProperty("value", out var v))
                    return v.GetString();
            }
            // No primary flag → take first element
            var first = value.Value.EnumerateArray().FirstOrDefault();
            if (first.ValueKind == JsonValueKind.Object && first.TryGetProperty("value", out var fv))
                return fv.GetString();
        }
        if (value.Value.ValueKind == JsonValueKind.String)
            return value.Value.GetString();
        return null;
    }

    /// <summary>
    /// Handles PATCH with no path — value is a partial ScimUser object.
    /// Azure Entra sends: { "op": "replace", "value": { "active": false } }
    /// </summary>
    private static void ApplyPartialResource(
        JsonElement? value,
        CoreUpdateUserRequest coreUpdate,
        UserProps oidcProps,
        ref bool coreChanged,
        ref bool oidcChanged)
    {
        if (value is null || value.Value.ValueKind != JsonValueKind.Object) return;

        var obj = value.Value;

        if (obj.TryGetProperty("displayName", out var dn))
        {
            coreUpdate.Name = dn.GetString();
            coreChanged = true;
        }
        if (obj.TryGetProperty("active", out var active))
        {
            coreUpdate.Enabled = active.ValueKind == JsonValueKind.True;
            coreChanged = true;
        }
        if (obj.TryGetProperty("name", out var name))
        {
            if (name.TryGetProperty("givenName", out var gn))
            { oidcProps.GivenName = gn.GetString(); oidcChanged = true; }
            if (name.TryGetProperty("familyName", out var fn))
            { oidcProps.FamilyName = fn.GetString(); oidcChanged = true; }
        }
        if (obj.TryGetProperty("externalId", out var eid))
        {
            oidcProps.ScimExternalId = eid.GetString();
            oidcChanged = true;
        }
        if (obj.TryGetProperty("emails", out var emails))
        {
            var email = ExtractPrimaryFromElement(emails);
            if (email is not null) { coreUpdate.Email = email; coreChanged = true; }
        }
        if (obj.TryGetProperty("phoneNumbers", out var phones))
        {
            var phone = ExtractPrimaryFromElement(phones);
            if (phone is not null) { coreUpdate.Phone = phone; coreChanged = true; }
        }

        // The Enterprise extension arrives as a member keyed by its URN (RFC 7643 §3), which is
        // exactly how Entra ID sends a no-path PATCH.
        if (obj.TryGetProperty(ScimConstants.EnterpriseUserSchema, out var ent)
            && ent.ValueKind == JsonValueKind.Object)
        {
            // A partial PATCH touches only what it names — unlike PUT, an absent attribute means
            // "leave it alone", not "clear it". Hence TryGetProperty per field, not a wholesale copy.
            if (ent.TryGetProperty("employeeNumber", out var v)) { oidcProps.EmployeeNumber = v.GetString(); oidcChanged = true; }
            if (ent.TryGetProperty("costCenter", out v)) { oidcProps.CostCenter = v.GetString(); oidcChanged = true; }
            if (ent.TryGetProperty("organization", out v)) { oidcProps.Organization = v.GetString(); oidcChanged = true; }
            if (ent.TryGetProperty("division", out v)) { oidcProps.Division = v.GetString(); oidcChanged = true; }
            if (ent.TryGetProperty("department", out v)) { oidcProps.Department = v.GetString(); oidcChanged = true; }
            if (ent.TryGetProperty("manager", out var mgr))
            {
                oidcProps.ManagerId = mgr.ValueKind switch
                {
                    JsonValueKind.Object when mgr.TryGetProperty("value", out var mv) => mv.GetString(),
                    JsonValueKind.String => mgr.GetString(),
                    _ => null
                };
                oidcChanged = true;
            }
        }
    }

    /// <summary>
    /// Copies the Enterprise User extension (RFC 7643 §4.3) onto the stored props. Used by the write
    /// paths where the whole resource is supplied (POST, PUT), so a null extension legitimately
    /// clears the fields — that is what "replace the resource" means.
    /// </summary>
    private static void ApplyEnterprise(ScimEnterpriseUser? ent, UserProps props)
    {
        props.EmployeeNumber = ent?.EmployeeNumber;
        props.CostCenter = ent?.CostCenter;
        props.Organization = ent?.Organization;
        props.Division = ent?.Division;
        props.Department = ent?.Department;
        props.ManagerId = ent?.Manager?.Value;
    }

    /// <summary>
    /// Reads <c>manager</c> from a PATCH value, accepting both shapes seen in the wild: the spec's
    /// complex object (<c>{"value":"42"}</c>) and the bare id some clients send.
    /// </summary>
    private static string? GetManagerId(JsonElement? value)
    {
        if (value is null) return null;
        return value.Value.ValueKind switch
        {
            JsonValueKind.Object when value.Value.TryGetProperty("value", out var v) => v.GetString(),
            JsonValueKind.String => value.Value.GetString(),
            _ => null
        };
    }

    /// <summary>
    /// Resolves <c>manager.displayName</c> for the managers referenced on a page of users. §4.3 marks
    /// displayName read-only — the provider is expected to resolve it — so we look it up rather than
    /// storing a copy that would drift when the manager renames.
    /// <para>
    /// Bounded by the distinct manager ids actually present (usually a handful per page), so listing
    /// users does not fan out into a lookup per row.
    /// </para>
    /// </summary>
    private static async Task<IReadOnlyDictionary<string, string>?> ResolveManagerNamesAsync(
        IRedbService redb, IEnumerable<UserProps?> props)
    {
        var ids = props
            .Select(p => p?.ManagerId)
            .Where(id => !string.IsNullOrEmpty(id))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (ids.Count == 0) return null;

        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var id in ids)
        {
            if (!long.TryParse(id, out var managerId)) continue;
            var manager = await redb.UserProvider.GetUserByIdAsync(managerId);
            // A dangling manager id (deleted user) yields no displayName rather than an error: the
            // reference itself is still the truth the provisioning client wrote.
            if (manager is not null)
                names[id!] = manager.Name ?? manager.Login ?? id!;
        }

        return names.Count > 0 ? names : null;
    }

    private static string? ExtractPrimaryFromElement(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array) return null;
        foreach (var elem in value.EnumerateArray())
        {
            if (elem.TryGetProperty("primary", out var primary) && primary.GetBoolean()
                && elem.TryGetProperty("value", out var v))
                return v.GetString();
        }
        var first = value.EnumerateArray().FirstOrDefault();
        if (first.ValueKind == JsonValueKind.Object && first.TryGetProperty("value", out var fv))
            return fv.GetString();
        return null;
    }

    // ── Error / result helpers ──────────────────────────────────

    private static void SetScimError(IExchange exchange, int status, string? scimType, string? detail)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new ScimError
        {
            Status = status.ToString(),
            ScimType = scimType,
            Detail = detail
        };
    }

    private static void SetResult(IExchange exchange, object body)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = body;
    }

    private static ScimListResponse<ScimUser> EmptyList(int startIndex) => new()
    {
        TotalResults = 0, StartIndex = startIndex, ItemsPerPage = 0
    };

    /// <summary>
    /// Checks the If-Match precondition header against the resource's current ETag.
    /// Returns false (and sets 412 error) if the precondition fails.
    /// </summary>
    private static bool CheckIfMatch(IExchange exchange, Guid? currentHash)
    {
        var ifMatch = exchange.In.GetHeader<string>("scim.IfMatch");
        if (string.IsNullOrEmpty(ifMatch)) return true; // no precondition

        if (ifMatch == "*") return true; // wildcard always matches

        // Strip W/ prefix and quotes: W/"abc" → abc
        var expected = ifMatch.Replace("W/", "").Trim('"');
        var actual = currentHash?.ToString();

        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            SetScimError(exchange, 412, null, "ETag precondition failed — resource has been modified");
            return false;
        }
        return true;
    }

    /// <summary>
    /// Sets the response ETag header from the resource hash. Writes to three places so the
    /// header survives the route pipeline regardless of which branch the SCIM HTTP mapper
    /// takes downstream:
    /// <list type="bullet">
    ///   <item><c>exchange.In.Headers["scim.ETag"]</c> — survives RedbHttpController rebinding
    ///     and is what <c>MapScimResponseToHttpStatus</c> reads.</item>
    ///   <item><c>exchange.Out.Headers["scim.ETag"]</c> — canonical out-channel.</item>
    ///   <item><c>exchange.Out.Headers["ETag"]</c> — direct HTTP header so the http
    ///     consumer projects it onto the wire even when the SCIM mapper does not run
    ///     (some 2xx paths short-circuit).</item>
    /// </list>
    /// </summary>
    private static void SetETagHeader(IExchange exchange, Guid? hash)
    {
        if (!hash.HasValue) return;
        var value = $"W/\"{hash.Value}\"";
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Headers["scim.ETag"] = value;
        exchange.Out.Headers["ETag"] = value;
        exchange.In.Headers["scim.ETag"] = value;
    }

    private static int GetInt(Dictionary<string, object?> dict, string key, int defaultValue)
    {
        if (dict.TryGetValue(key, out var val) && val is not null
            && int.TryParse(val.ToString(), out var result))
            return result;
        return defaultValue;
    }

    /// <summary>
    /// Generates a cryptographically strong random password that satisfies common complexity policies.
    /// Contains uppercase, lowercase, digits, and special characters.
    /// </summary>
    private static string GeneratePassword(int length)
    {
        const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lower = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*";
        const string all = upper + lower + digits + special;

        Span<byte> bytes = stackalloc byte[length];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);

        var chars = new char[length];
        // Guarantee at least one of each category
        chars[0] = upper[bytes[0] % upper.Length];
        chars[1] = lower[bytes[1] % lower.Length];
        chars[2] = digits[bytes[2] % digits.Length];
        chars[3] = special[bytes[3] % special.Length];
        for (int i = 4; i < length; i++)
            chars[i] = all[bytes[i] % all.Length];

        // Shuffle
        for (int i = length - 1; i > 0; i--)
        {
            int j = bytes[i] % (i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }
}
