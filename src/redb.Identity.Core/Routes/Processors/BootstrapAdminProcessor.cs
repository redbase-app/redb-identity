using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Models.Users;
using redb.Identity.Contracts.Endpoints;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Security;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// B1 — one-shot emergency-admin bootstrap processor for
/// <c>direct-vm://identity-bootstrap-admin</c>.
/// <para>
/// Atomically creates: scope <c>identity:admin</c>, group
/// <see cref="BootstrapOptions.AdminGroupName"/>, the admin user, the membership,
/// the canonical OIDC client (<see cref="BootstrapOptions.WebClientId"/>) with
/// <c>backchannel_logout_uri</c>, and the
/// <c>SystemFlag(name=bootstrap_completed)</c> sentinel that gates further
/// invocations. The whole flow runs inside the route-level <c>WithRedbTx</c>
/// wrapper so any partial failure rolls back.
/// </para>
/// <para>
/// Authenticated via the <c>X-Bootstrap-Secret</c> header (compared in constant
/// time). Self-locks via the unique <c>SystemFlag</c> sentinel — second call
/// returns <c>410 Gone</c>.
/// </para>
/// </summary>
internal sealed class BootstrapAdminProcessor : IProcessor
{
    private const string FlagName = "bootstrap_completed";

    // JSON options matching the HTTP wire format produced by browsers / curl /
    // System.Net.Http.Json.JsonContent.Create — camelCase property names with
    // case-insensitive fallback so PascalCase test bodies also work.
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IRouteContext _context;
    private readonly BootstrapOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly string? _redbName;
    private readonly ILogger? _securityLog;

    public BootstrapAdminProcessor(
        IRouteContext context,
        IOptions<RedbIdentityOptions> identityOptions,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null)
    {
        _context = context;
        _options = identityOptions.Value.Bootstrap ?? new BootstrapOptions();
        _redbName = identityOptions.Value.RedbInstanceName;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityLog = loggerFactory is null
            ? null
            : IdentitySecurityLog.CreateLogger(loggerFactory);
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        // ── 1. Master switch — disabled deployments hide the route entirely. ──
        if (!_options.Enabled)
        {
            // Spec §5: Bootstrap_Throws_When_Bootstrap_Disabled → 404 Not Found so the
            // endpoint is indistinguishable from "no such route" for un-trusted callers.
            SetError(exchange, 404, "not_found", "Bootstrap endpoint is not enabled.");
            return;
        }

        // ── 2. Constant-time secret comparison. ──
        var providedSecret = exchange.In.GetHeader<string>("X-Bootstrap-Secret");
        var expectedSecret = _options.Secret;
        if (string.IsNullOrEmpty(expectedSecret) ||
            string.IsNullOrEmpty(providedSecret) ||
            !FixedTimeStringEquals(providedSecret, expectedSecret))
        {
            _securityLog?.LogWarning(
                "B1 bootstrap-admin invocation rejected: invalid X-Bootstrap-Secret " +
                "(remote={Remote})", exchange.In.GetHeader<string>("redbHttp.RemoteAddress"));
            SetError(exchange, 403, "forbidden", "Invalid bootstrap secret.");
            return;
        }

        // ── 3. Parse request body (the HTTP facade hands a typed DTO; tests can also
        //       pass raw JSON / dictionary). ──
        var request = ParseRequest(exchange);
        if (request is null)
        {
            SetError(exchange, 400, "validation_error", "Invalid or missing request body.");
            return;
        }

        var validationError = ValidateRequest(request);
        if (validationError is not null)
        {
            SetError(exchange, 400, "validation_error", validationError);
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);

        // ── 4. Sentinel check: bootstrap already completed → 410 Gone. ──
        if (await IsBootstrapCompletedAsync(redb, ct).ConfigureAwait(false))
        {
            SetError(exchange, 410, "gone", "Bootstrap already completed.");
            return;
        }

        // ── 5. Resolve required services from the per-exchange scope. ──
        var applicationManager = _context.GetIdentityService<IOpenIddictApplicationManager>(exchange);
        var groupService = _context.GetIdentityServiceOrDefault<IGroupService>(exchange) ?? new GroupService(redb);

        var groupName = string.IsNullOrWhiteSpace(request.GroupName)
            ? _options.AdminGroupName
            : request.GroupName!;
        var scopeName = _options.AdminScope;
        var clientId = _options.WebClientId;

        try
        {
            // ── 6. Find-or-create OAuth scope (identity:admin). ──
            var scopeObj = await FindOrCreateScopeAsync(redb, scopeName, ct).ConfigureAwait(false);

            // ── 7. Find-or-create the admin group. ──
            long groupId = await FindOrCreateGroupAsync(redb, groupService, groupName, ct)
                .ConfigureAwait(false);

            // ── 8. Create the admin user via the relational UserProvider. ──
            //    Uniqueness is enforced inside CreateUserAsync (throws on duplicate login).
            var coreUser = await redb.UserProvider.CreateUserAsync(new CreateUserRequest
            {
                Login = request.Email!,
                Password = request.Password!,
                Name = request.Email!,
                Email = request.Email,
                Enabled = true,
            }).ConfigureAwait(false);

            // OIDC profile extension (linked via key = _users._id) — required so that
            // password / authorization_code logins can hydrate id_token claims.
            // value_guid: stable, instance-unique public identity used as the OIDC `sub` claim.
            var oidcObj = new RedbObject<UserProps>(new UserProps
            {
                EmailVerified = true,
            });
            oidcObj.Name = request.Email!;
            oidcObj.Key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
            await redb.SaveAsync(oidcObj).ConfigureAwait(false);

            // ── 9. Add membership (skip-if-exists handled inside helper). ──
            var alreadyMember = await groupService.IsMemberAsync(groupId, coreUser.Id, ct)
                .ConfigureAwait(false);
            if (!alreadyMember)
            {
                await groupService.AddMemberAsync(groupId, coreUser.Id, role: "admin", ct: ct)
                    .ConfigureAwait(false);
            }

            // ── 9b. Mirror the membership into the B.3 admin role.
            //     Bootstrap pre-dates the system-roles registry (B.3 added
            //     SeedSystemRolesListener with admin / system / everyone /
            //     impersonator), so installs created on the old code path
            //     have the admin user in the "admins" group but NOT in the
            //     "admin" role — the two authorisation models stay parallel
            //     instead of converging. Authorisation still works (group
            //     carries the identity:admin scope) but UI surfaces that
            //     enumerate role assignees (/admin/roles/{id} Users tab)
            //     correctly show "no users" for admin. Wire the bootstrap
            //     admin into the role here so the two models agree.
            //     Idempotent: RoleService.AssignUserAsync no-ops if the
            //     assignment already exists.
            try
            {
                var adminRole = await redb.Query<RoleProps>()
                    .Where(p => p.Name == "admin")
                    .Where(p => p.Audience == "organization")
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);
                if (adminRole is not null)
                {
                    var roleSvc = new RoleService(redb);
                    await roleSvc.AssignUserAsync(adminRole.Id, coreUser.Id, actingUserId: null, ct)
                        .ConfigureAwait(false);
                }
                // If the admin role isn't seeded yet (race with
                // SeedSystemRolesListener on the same startup) just skip —
                // the BootstrapAdminBackfillListener (see Module/) catches
                // up on the next startup.
            }
            catch (Exception ex)
            {
                _securityLog?.LogWarning(ex,
                    "B1 bootstrap-admin: failed to mirror admin user into admin role — operator can fix via /admin/roles UI; group-scope auth path remains functional.");
            }

            // ── 10. Create the canonical admin Web Console OIDC client. ──
            //    Confidential / authorization_code + PKCE / refresh_token, with
            //    backchannel_logout_uri stored as a custom property (OpenID Connect
            //    Back-Channel Logout 1.0 §2.2).
            var existingApp = await applicationManager.FindByClientIdAsync(clientId, ct)
                .ConfigureAwait(false);
            if (existingApp is not null)
            {
                // Idempotent rollback path — Bootstrap_Idempotent_When_Group_Or_Scope_Already_Exists.
                // The flag must still be set, so we treat this as success and re-issue a fresh
                // client_secret only if no existing client. For an existing client we surface a
                // duplicate error to avoid silently rotating credentials.
                SetError(exchange, 409, "duplicate",
                    $"OIDC client '{clientId}' already exists; bootstrap state is inconsistent — " +
                    "delete the client manually or restore the bootstrap_completed flag.");
                return;
            }

            var clientSecret = GenerateClientSecret();
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = "Identity Admin Web Console",
                ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
            };
            descriptor.RedirectUris.Add(new Uri(request.RedirectUri!));
            descriptor.PostLogoutRedirectUris.Add(new Uri(request.PostLogoutRedirectUri!));
            foreach (var permission in new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                OpenIddictConstants.Permissions.Prefixes.Scope + scopeName,
            })
            {
                descriptor.Permissions.Add(permission);
            }
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);

            if (!string.IsNullOrWhiteSpace(request.BackchannelLogoutUri))
            {
                // OpenIddict stores client metadata in System.Text.Json.JsonElement values
                // — build them via JsonDocument so the backchannel-logout dispatcher can
                // read them back out without an extra type conversion.
                descriptor.Properties["backchannel_logout_uri"] =
                    JsonDocument.Parse(JsonSerializer.Serialize(request.BackchannelLogoutUri)).RootElement.Clone();
                descriptor.Properties["backchannel_logout_session_required"] =
                    JsonDocument.Parse("true").RootElement.Clone();
            }

            var application = await applicationManager.CreateAsync(descriptor, ct)
                .ConfigureAwait(false);

            // ── 11. Set the bootstrap_completed sentinel. The UNIQUE index on
            //        SystemFlag._name guarantees that two concurrent successful bootstraps
            //        cannot both win — the second SaveAsync throws and the surrounding
            //        WithRedbTx rolls back this entire processor's writes. ──
            try
            {
                await SetBootstrapCompletedAsync(redb, clientId, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (IdentityProcessorHelpers.IsUniqueViolation(ex))
            {
                // Race lost — another caller's transaction committed first. Map to 410.
                SetError(exchange, 410, "gone",
                    "Bootstrap already completed (concurrent invocation won the race).");
                return;
            }

            _securityLog?.LogWarning(
                "B1 bootstrap-admin completed: created admin user {UserId} in group {Group} " +
                "with OIDC client {ClientId} and scope {Scope}",
                coreUser.Id, groupName, clientId, scopeName);

            // ── 12. Build response — clientSecret is returned in plain ONLY here. ──
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["userId"] = coreUser.Id,
                ["groupId"] = groupId,
                ["applicationId"] = clientId,
                ["clientSecret"] = clientSecret,
                ["scopeName"] = scopeName,
            };
            exchange.Out.Headers["redbHttp.ResponseCode"] = 201;

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientRegistered;
            exchange.Properties["identity-event-data"] = new
            {
                ClientId = clientId,
                Source = "bootstrap_admin",
                AdminUserId = coreUser.Id,
                AdminGroupId = groupId,
                Scope = scopeName,
            };
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already taken"))
        {
            // Login conflict — surface as 409 so operator can pick a different email.
            SetError(exchange, 409, "duplicate",
                $"User '{request.Email}' already exists; choose a different email or " +
                "restore the bootstrap_completed flag.");
        }
    }

    // ── Helpers ─────────────────────────────────────────────────

    private static BootstrapAdminRequest? ParseRequest(IExchange exchange)
    {
        try
        {
            return exchange.In.Body switch
            {
                BootstrapAdminRequest typed => typed,
                byte[] bytes => JsonSerializer.Deserialize<BootstrapAdminRequest>(bytes, JsonOptions),
                string json => JsonSerializer.Deserialize<BootstrapAdminRequest>(json, JsonOptions),
                Dictionary<string, object?> dict => DictToRequest(dict),
                _ => null,
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static BootstrapAdminRequest DictToRequest(Dictionary<string, object?> dict) => new()
    {
        Email = dict.GetValueOrDefault("email")?.ToString(),
        Password = dict.GetValueOrDefault("password")?.ToString(),
        GroupName = dict.GetValueOrDefault("groupName")?.ToString(),
        RedirectUri = dict.GetValueOrDefault("redirectUri")?.ToString(),
        PostLogoutRedirectUri = dict.GetValueOrDefault("postLogoutRedirectUri")?.ToString(),
        BackchannelLogoutUri = dict.GetValueOrDefault("backchannelLogoutUri")?.ToString(),
    };

    private static string? ValidateRequest(BootstrapAdminRequest r)
    {
        if (string.IsNullOrWhiteSpace(r.Email))
            return "Email is required.";
        if (string.IsNullOrWhiteSpace(r.Password) || r.Password!.Length < 8)
            return "Password is required and must be at least 8 characters.";
        if (string.IsNullOrWhiteSpace(r.RedirectUri) || !Uri.TryCreate(r.RedirectUri, UriKind.Absolute, out _))
            return "RedirectUri is required and must be an absolute URI.";
        if (string.IsNullOrWhiteSpace(r.PostLogoutRedirectUri) ||
            !Uri.TryCreate(r.PostLogoutRedirectUri, UriKind.Absolute, out _))
            return "PostLogoutRedirectUri is required and must be an absolute URI.";
        if (!string.IsNullOrWhiteSpace(r.BackchannelLogoutUri) &&
            !Uri.TryCreate(r.BackchannelLogoutUri, UriKind.Absolute, out _))
            return "BackchannelLogoutUri must be an absolute URI when provided.";
        return null;
    }

    private static async Task<bool> IsBootstrapCompletedAsync(IRedbService redb, CancellationToken ct)
    {
        var existing = await redb.Query<IdentitySystemFlagProps>()
            .WhereRedb(o => o.Name == FlagName)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        return existing is not null && existing.ValueBool == true;
    }

    private async Task SetBootstrapCompletedAsync(IRedbService redb, string clientId, CancellationToken ct)
    {
        var flag = new RedbObject<IdentitySystemFlagProps>(new IdentitySystemFlagProps());
        flag.Name = FlagName;
        flag.value_bool = true;
        flag.value_datetime = _timeProvider.GetUtcNow().UtcDateTime;
        flag.value_string = clientId;
        flag.note = "B1 — bootstrap completed; remove this row + the OIDC client to re-bootstrap.";
        await redb.SaveAsync(flag).ConfigureAwait(false);
    }

    private static async Task<RedbObject<ScopeProps>> FindOrCreateScopeAsync(
        IRedbService redb, string scopeName, CancellationToken ct)
    {
        var existing = await redb.Query<ScopeProps>()
            .WhereRedb(o => o.ValueString == scopeName)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is not null) return existing.Hydrate();

        var obj = new RedbObject<ScopeProps>(new ScopeProps
        {
            ScopeName = scopeName,
            Description = "Identity admin operations",
        });
        obj.Name = scopeName;
        obj.value_string = scopeName;
        await redb.SaveAsync(obj).ConfigureAwait(false);
        return obj;
    }

    private static async Task<long> FindOrCreateGroupAsync(
        IRedbService redb, IGroupService groupService, string groupName, CancellationToken ct)
    {
        var existing = await redb.Query<GroupProps>()
            .WhereRedb(o => o.Name == groupName)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is not null) return existing.Id;

        var created = await groupService
            .CreateGroupAsync(groupName, groupType: "role",
                description: "Identity Administrators", ct: ct)
            .ConfigureAwait(false);
        return created.Id;
    }

    private static string GenerateClientSecret()
    {
        // 32 bytes of CSPRNG entropy → URL-safe base64 (43 chars, no padding).
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlNoPad(buffer);
    }

    private static string Base64UrlNoPad(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static bool FixedTimeStringEquals(string a, string b)
    {
        // Encode both to UTF-8 first; CryptographicOperations.FixedTimeEquals requires
        // equal-length spans, so we compare lengths only after producing the byte buffers
        // via a constant-time path. When lengths differ we still spin a comparison over
        // the longer span to keep the runtime independent of the supplied secret length.
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        if (bytesA.Length != bytesB.Length)
        {
            // Force a length-independent dummy compare so timing remains stable.
            var dummy = new byte[bytesA.Length];
            CryptographicOperations.FixedTimeEquals(bytesA, dummy);
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }

    private static void SetError(IExchange exchange, int httpStatus, string error, string description)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["error"] = error,
            ["error_description"] = description,
        };
        exchange.Out.Headers["redbHttp.ResponseCode"] = httpStatus;
    }
}
