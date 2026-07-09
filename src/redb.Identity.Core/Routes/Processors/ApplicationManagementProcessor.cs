using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Contracts.Cors;
using redb.Identity.Core.Security;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// CRUD management processor for OAuth applications.
/// Dispatches on the "operation" header: create, read, update, delete, list.
/// </summary>
internal sealed class ApplicationManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ApplicationManagementProcessor(IRouteContext context, string? redbName = null)
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
            case "rotate-secret":
                await RotateSecret(redb, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private async Task Create(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as CreateApplicationRequest;

        // Validate ClientId
        var err = IdentityProcessorHelpers.ValidateIdentifier(request?.ClientId, "ClientId");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        if (request!.ClientType is not (null or "public" or "confidential"))
        { SetError(exchange, "validation_error", "ClientType must be 'public' or 'confidential'"); return; }

        if (request.ConsentType is not (null or "explicit" or "implicit" or "external"))
        { SetError(exchange, "validation_error", "ConsentType must be 'explicit', 'implicit', or 'external'"); return; }

        if (request.ApplicationType is not (null or "web" or "native"))
        { SetError(exchange, "validation_error", "ApplicationType must be 'web' or 'native'"); return; }

        err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateUris(request.RedirectUris, "redirect URI");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateUris(request.PostLogoutRedirectUris, "post-logout redirect URI");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        if (request.ClientSecret is not null && request.ClientSecret.Length > IdentityProcessorHelpers.MaxPasswordLength)
        { SetError(exchange, "validation_error", $"ClientSecret must not exceed {IdentityProcessorHelpers.MaxPasswordLength} characters"); return; }

        // Resolve OpenIddict application manager — required so that client_secret is hashed via
        // the same mechanism used by ValidateClientSecretAsync (BCrypt). Bypassing the manager
        // here would create credentials that token endpoint cannot verify.
        // Prefer the per-exchange scope so that scoped services (IOpenIddictApplicationManager
        // and its IRedbService dependency) are not captured from the root provider — doing so
        // would force every concurrent admin call onto a single Npgsql connection.
        var manager = _context.GetIdentityService<IOpenIddictApplicationManager>(exchange);

        // Check uniqueness via the manager (single source of truth, also hits the OpenIddict cache)
        if (await manager.FindByClientIdAsync(request.ClientId, ct) is not null)
        {
            SetError(exchange, "duplicate", $"ClientId '{request.ClientId}' already exists");
            return;
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = request.ClientId,
            ClientSecret = string.IsNullOrEmpty(request.ClientSecret) ? null : request.ClientSecret,
            // Smart default: confidential clients require a secret. When the caller omits both
            // ClientType and ClientSecret, default to public to keep the API ergonomic and to
            // avoid the OpenIddict "confidential without secret" validation error.
            ClientType = request.ClientType
                ?? (string.IsNullOrEmpty(request.ClientSecret) ? "public" : "confidential"),
            ConsentType = request.ConsentType ?? "explicit",
            DisplayName = request.DisplayName ?? request.ClientId,
        };

        if (request.ApplicationType == "native")
            descriptor.ApplicationType = OpenIddictConstants.ApplicationTypes.Native;
        else if (request.ApplicationType == "web")
            descriptor.ApplicationType = OpenIddictConstants.ApplicationTypes.Web;

        if (request.RedirectUris is { Length: > 0 })
            foreach (var uri in request.RedirectUris)
                descriptor.RedirectUris.Add(new Uri(uri));

        if (request.PostLogoutRedirectUris is { Length: > 0 })
            foreach (var uri in request.PostLogoutRedirectUris)
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));

        if (request.Permissions is { Length: > 0 })
            foreach (var p in request.Permissions)
                descriptor.Permissions.Add(p);

        if (request.Requirements is { Length: > 0 })
            foreach (var r in request.Requirements)
                descriptor.Requirements.Add(r);

        // OIDC Back-Channel Logout 1.0 §2.2 — store endpoint + sid flag as custom
        // properties so BackchannelLogoutDispatcher can read them at logout time.
        if (!string.IsNullOrWhiteSpace(request.BackchannelLogoutUri))
        {
            descriptor.Properties["backchannel_logout_uri"] =
                JsonDocument.Parse(JsonSerializer.Serialize(request.BackchannelLogoutUri)).RootElement.Clone();
            descriptor.Properties["backchannel_logout_session_required"] =
                JsonDocument.Parse((request.BackchannelLogoutSessionRequired ?? true) ? "true" : "false").RootElement.Clone();
        }

        RedbObject<ApplicationProps> created;
        try
        {
            created = (await manager.CreateAsync(descriptor, ct)) as RedbObject<ApplicationProps>
                ?? throw new InvalidOperationException("Application manager returned unexpected entity type");
        }
        catch (Exception ex) when (IdentityProcessorHelpers.IsUniqueViolation(ex))
        {
            // Concurrent writer won the race — partial unique index on _objects
            // (_value_string) WHERE _id_scheme = ApplicationProps rejected this insert.
            // Surface the same error as the app-level check above for clients.
            SetError(exchange, "duplicate", $"ClientId '{request.ClientId}' already exists");
            return;
        }

        // C15 / per-route CORS: registered-client origin snapshot is now stale.
        _context.GetIdentityServiceOrDefault<IRegisteredClientOriginRegistry>(exchange)?.Invalidate();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(created);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientRegistered;
        exchange.Properties["identity-event-data"] = new { ClientId = request.ClientId };
    }

    private async Task Read(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        RedbObject<ApplicationProps>? app = null;

        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("id", out var idVal) && idVal != null
                && long.TryParse(idVal.ToString(), out var id) && id > 0)
                app = (await _redb.LoadAsync<ApplicationProps>(id))?.Hydrate();
            else if (dict.TryGetValue("clientId", out var cidVal) && cidVal is string clientId
                     && !string.IsNullOrEmpty(clientId))
                app = (await _redb.Query<ApplicationProps>()
                    .WhereRedb(o => o.ValueString == clientId)
                    .FirstOrDefaultAsync())?.Hydrate();
            else
                throw new InvalidOperationException("Either 'id' or 'clientId' required");
        }
        else
        {
            throw new InvalidOperationException("Expected body with 'id' or 'clientId'");
        }

        if (app is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = "Application not found" };
            return;
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(app);
    }

    private async Task Update(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as UpdateApplicationRequest;
        if (request is null || !long.TryParse(request.Id, out var objectId) || objectId <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var app = (await _redb.LoadAsync<ApplicationProps>(objectId))?.Hydrate();
        if (app is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"Application {request.Id} not found" };
            return;
        }

        // Validate updatable fields
        if (request.ClientType is not (null or "public" or "confidential"))
        { SetError(exchange, "validation_error", "ClientType must be 'public' or 'confidential'"); return; }

        if (request.ConsentType is not (null or "explicit" or "implicit" or "external"))
        { SetError(exchange, "validation_error", "ConsentType must be 'explicit', 'implicit', or 'external'"); return; }

        var err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateUris(request.RedirectUris, "redirect URI");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateUris(request.PostLogoutRedirectUris, "post-logout redirect URI");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        if (request.DisplayName != null) app.Name = request.DisplayName;
        if (request.ClientType != null) app.Props.ClientType = request.ClientType;
        if (request.ConsentType != null) app.Props.ConsentType = request.ConsentType;
        if (request.Permissions != null) app.Props.Permissions = request.Permissions;
        if (request.RedirectUris != null) app.Props.RedirectUris = request.RedirectUris;
        if (request.PostLogoutRedirectUris != null) app.Props.PostLogoutRedirectUris = request.PostLogoutRedirectUris;
        if (request.Requirements != null) app.Props.Requirements = request.Requirements;
        // N-4 (Session C/E): per-client password-reset / verify-email / change-email
        // landing-URL whitelists. Without these wired through admin Update, the
        // server-side enforcement is unreachable from any external caller (the only
        // alternative is direct DB writes via the seed pipeline).
        if (request.PasswordResetUris != null) app.Props.PasswordResetUris = request.PasswordResetUris;
        if (request.EmailVerifyUris != null) app.Props.EmailVerifyUris = request.EmailVerifyUris;
        if (request.ChangeEmailUris != null) app.Props.ChangeEmailUris = request.ChangeEmailUris;

        // A.1 (Batch 1 follow-up): protocol-tab editable fields.
        // - PATCH semantics: a non-null empty string clears the value; null leaves
        //   the existing value alone.
        // - Validate Back-Channel Logout URI shape via the same helper as the
        //   redirect-URI list (single-element list for re-use).
        if (request.BackchannelLogoutUri != null)
        {
            var bclTrimmed = request.BackchannelLogoutUri.Trim();
            if (bclTrimmed.Length == 0)
            {
                app.Props.BackchannelLogoutUri = null;
            }
            else
            {
                err = IdentityProcessorHelpers.ValidateUris(new[] { bclTrimmed }, "back-channel logout URL");
                if (err != null) { SetError(exchange, "validation_error", err); return; }
                app.Props.BackchannelLogoutUri = bclTrimmed;
            }
        }
        if (request.BackchannelLogoutSessionRequired.HasValue)
            app.Props.BackchannelLogoutSessionRequired = request.BackchannelLogoutSessionRequired.Value;
        if (request.RequirePushedAuthorizationRequests.HasValue)
            app.Props.RequirePushedAuthorizationRequests = request.RequirePushedAuthorizationRequests.Value;
        if (request.JsonWebKeySet != null)
        {
            // Empty string clears; otherwise we accept the raw JSON as the caller
            // supplied it. We do NOT parse-validate here because we want the same
            // tolerant behaviour as our other JSON-bearing fields (the caller's
            // JWKS may carry vendor extensions OpenIddict ignores). A future
            // refinement: validate via JsonWebKeySet.Create at admin time.
            app.Props.JsonWebKeySet = request.JsonWebKeySet.Length == 0 ? null : request.JsonWebKeySet;
        }

        // A.2: per-client token lifetime overrides — write through to
        // ApplicationProps.Settings using OpenIddict's well-known setting keys.
        // RedbApplicationStore.GetSettingsAsync surfaces this dict verbatim, and
        // OpenIddict's built-in AttachAccessTokenLifetime / AttachIdentityToken-
        // Lifetime / AttachRefreshTokenLifetime handlers prefer per-client values
        // over the server-wide RedbIdentityOptions defaults. Negative or zero
        // clears the override (reverts to global default).
        ApplyLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.AccessToken, request.AccessTokenLifetimeSeconds);
        ApplyLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.RefreshToken, request.RefreshTokenLifetimeSeconds);
        ApplyLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.IdentityToken, request.IdentityTokenLifetimeSeconds);

        // A.3: extra id_token audiences. null leaves alone, empty clears,
        // non-empty replaces. The trim/dedupe pass below mirrors how we
        // sanitise RedirectUris — caller can paste duplicates without
        // poisoning the array.
        if (request.IdTokenAudiences != null)
        {
            app.Props.IdTokenAudiences = request.IdTokenAudiences
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (app.Props.IdTokenAudiences.Length == 0)
                app.Props.IdTokenAudiences = null;
        }

        // A.6 (Request Object) — PATCH semantics: empty string clears, null leaves alone.
        if (request.RequestObjectSigningAlg != null)
            app.Props.RequestObjectSigningAlg = request.RequestObjectSigningAlg.Length == 0
                ? null : request.RequestObjectSigningAlg;
        if (request.RequestObjectEncryptionAlg != null)
            app.Props.RequestObjectEncryptionAlg = request.RequestObjectEncryptionAlg.Length == 0
                ? null : request.RequestObjectEncryptionAlg;
        if (request.RequestObjectEncryptionEnc != null)
            app.Props.RequestObjectEncryptionEnc = request.RequestObjectEncryptionEnc.Length == 0
                ? null : request.RequestObjectEncryptionEnc;

        // A.8: per-client strict DPoP opt-in.
        if (request.RequireDpop.HasValue)
            app.Props.RequireDpop = request.RequireDpop.Value;

        // A.10: Advanced-tab toggles.
        if (request.SkipLogoutConsent.HasValue)
            app.Props.SkipLogoutConsent = request.SkipLogoutConsent.Value;
        if (request.IsFidoTrusted.HasValue)
            app.Props.IsFidoTrusted = request.IsFidoTrusted.Value;

        // β: AllowedGroups whitelist (per-app group restriction). Empty array
        // clears the whitelist (any user); non-empty trim + dedupe + dropna so
        // the stored array is tidy regardless of operator input shape.
        if (request.AllowedGroups != null)
        {
            app.Props.AllowedGroups = request.AllowedGroups
                .Where(g => !string.IsNullOrWhiteSpace(g))
                .Select(g => g.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (app.Props.AllowedGroups.Length == 0)
                app.Props.AllowedGroups = null;
        }

        // A.7: JWKS endpoint URL — validate as a single URI when present so we
        // reject obviously malformed input at admin time rather than discovering
        // it during the first RP authentication round-trip.
        if (request.JwksUri != null)
        {
            var trimmed = request.JwksUri.Trim();
            if (trimmed.Length == 0)
            {
                app.Props.JwksUri = null;
            }
            else
            {
                err = IdentityProcessorHelpers.ValidateUris(new[] { trimmed }, "JWKS URI");
                if (err != null) { SetError(exchange, "validation_error", err); return; }
                app.Props.JwksUri = trimmed;
            }
        }

        await _redb.SaveAsync(app);

        // C15 / per-route CORS: invalidate registry whenever redirect URIs may have changed.
        if (request.RedirectUris != null || request.PostLogoutRedirectUris != null)
            _context.GetIdentityServiceOrDefault<IRegisteredClientOriginRegistry>(exchange)?.Invalidate();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(app);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientUpdated;
        exchange.Properties["identity-event-data"] = new { app.Props.ClientId };
    }

    private async Task Delete(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        await IdentityDeletionHelper.DeleteAsync(_redb, bg, id);

        // C15 / per-route CORS: a deleted application may have contributed origins.
        _context.GetIdentityServiceOrDefault<IRegisteredClientOriginRegistry>(exchange)?.Invalidate();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id };
    }

    private async Task List(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();

        var query = _redb.Query<ApplicationProps>()
            .OrderByRedb(o => o.Id);

        var total = await query.CountAsync();
        var count = Math.Min(request.Count, 100);
        var items = await query
            .Skip(request.Offset)
            .Take(count)
            .ToListAsync();
        items.ForEach(i => i.Hydrate());

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ApplicationResponse>
        {
            Items = items.Select(MapToResponse).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count
        };
    }

    /// <summary>
    /// Generates a fresh BCrypt-hashed <c>client_secret</c> for a confidential application
    /// and returns the plaintext value <b>once</b> in the HTTP response. The old secret is
    /// invalidated immediately — any client_credentials/refresh flow using the previous
    /// secret will receive 401 from the next call onward.
    /// <para>
    /// Hashing goes through <see cref="IOpenIddictApplicationManager.UpdateAsync(object, string, CancellationToken)"/>
    /// so that the same code path used at credential validation (BCrypt) produces the stored hash;
    /// bypassing the manager would yield a hash format the token endpoint cannot verify.
    /// </para>
    /// <para>
    /// Audit payload carries only the <c>ClientId</c>; the new plaintext secret is NEVER
    /// written to audit logs (see <see cref="IdentityAuditEventIds.ClientSecretRotated"/>).
    /// </para>
    /// </summary>
    private async Task RotateSecret(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var app = (await _redb.LoadAsync<ApplicationProps>(id))?.Hydrate();
        if (app is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"Application {id} not found" };
            return;
        }

        // Public clients have no secret by definition (RFC 6749 §2.1) — reject explicitly.
        if (string.Equals(app.Props.ClientType, "public", StringComparison.OrdinalIgnoreCase))
        {
            SetError(exchange, "invalid_client_type",
                "Public clients have no client_secret to rotate. Switch the client to 'confidential' first.");
            return;
        }

        // CSPRNG: 32 random bytes → ~44 chars Base64. The plaintext is returned exactly once
        // in the HTTP response and never persisted (the manager stores only the BCrypt hash).
        var newSecret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        var manager = _context.GetIdentityService<IOpenIddictApplicationManager>(exchange);

        // Hand the entity we already loaded straight to the manager — its store-side
        // UpdateAsync re-loads under a row lock for optimistic concurrency, so calling
        // FindByIdAsync first would only add a wasted round-trip and risk passing in a
        // separately-cached instance whose hash() would not match the locked snapshot.
        // Dedicated overload: hashes the secret (BCrypt) and persists in one atomic call.
        await manager.UpdateAsync(app, newSecret, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        var response = MapToResponse(app);
        response.NewSecret = newSecret;
        exchange.Out.Body = response;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientSecretRotated;
        // SECURITY: payload deliberately omits the plaintext secret. ClientId is enough
        // to correlate against tokens issued before/after the rotation in audit queries.
        exchange.Properties["identity-event-data"] = new { app.Props.ClientId };
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static ApplicationResponse MapToResponse(RedbObject<ApplicationProps> app) => new()
    {
        Id = app.Id.ToString(),
        ClientId = app.Props.ClientId,
        DisplayName = app.Name,
        ClientType = app.Props.ClientType,
        ConsentType = app.Props.ConsentType,
        ApplicationType = app.Props.ApplicationType,
        Permissions = app.Props.Permissions,
        RedirectUris = app.Props.RedirectUris,
        PostLogoutRedirectUris = app.Props.PostLogoutRedirectUris,
        Requirements = app.Props.Requirements,
        PasswordResetUris = app.Props.PasswordResetUris,
        EmailVerifyUris = app.Props.EmailVerifyUris,
        ChangeEmailUris = app.Props.ChangeEmailUris,
        // A.1 (Batch 1 follow-up): surface the previously-write-only protocol
        // properties so the admin UI can render and edit them on the Protocol tab.
        BackchannelLogoutUri = app.Props.BackchannelLogoutUri,
        BackchannelLogoutSessionRequired = app.Props.BackchannelLogoutSessionRequired,
        RequirePushedAuthorizationRequests = app.Props.RequirePushedAuthorizationRequests,
        JsonWebKeySet = app.Props.JsonWebKeySet,
        // A.2: per-client lifetime overrides — pulled out of ApplicationProps.Settings
        // back into typed int? seconds so the admin client doesn't need to parse the
        // OpenIddict TimeSpan format itself.
        AccessTokenLifetimeSeconds = ReadLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.AccessToken),
        RefreshTokenLifetimeSeconds = ReadLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.RefreshToken),
        IdentityTokenLifetimeSeconds = ReadLifetimeSetting(app, OpenIddictConstants.Settings.TokenLifetimes.IdentityToken),
        // A.3
        IdTokenAudiences = app.Props.IdTokenAudiences,
        // A.6
        RequestObjectSigningAlg = app.Props.RequestObjectSigningAlg,
        RequestObjectEncryptionAlg = app.Props.RequestObjectEncryptionAlg,
        RequestObjectEncryptionEnc = app.Props.RequestObjectEncryptionEnc,
        // A.7
        JwksUri = app.Props.JwksUri,
        // A.8
        RequireDpop = app.Props.RequireDpop,
        // A.10
        SkipLogoutConsent = app.Props.SkipLogoutConsent,
        IsFidoTrusted = app.Props.IsFidoTrusted,
        // β
        AllowedGroups = app.Props.AllowedGroups,
    };

    /// <summary>
    /// Apply / clear one per-client lifetime override. OpenIddict stores these as
    /// invariant-culture TimeSpan strings in the application's Settings dictionary
    /// (its AttachAccessTokenLifetime / IdentityToken / RefreshToken handlers parse
    /// via <see cref="System.Globalization.CultureInfo.InvariantCulture"/>).
    /// Null seconds → leave alone. Zero or negative → clear (revert to global default).
    /// Positive → set the override.
    /// </summary>
    private static void ApplyLifetimeSetting(RedbObject<ApplicationProps> app, string key, int? seconds)
    {
        if (seconds is null) return;
        var settings = app.Props.Settings is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(app.Props.Settings, StringComparer.Ordinal);

        if (seconds.Value <= 0)
        {
            settings.Remove(key);
        }
        else
        {
            settings[key] = TimeSpan.FromSeconds(seconds.Value)
                .ToString("c", System.Globalization.CultureInfo.InvariantCulture);
        }
        app.Props.Settings = settings.Count == 0 ? null : settings;
    }

    /// <summary>
    /// Project one stored lifetime back into int? seconds. Missing key → null
    /// (means "use the global RedbIdentityOptions default"). Unparseable value →
    /// null (defensive — bad data in Settings should not 500 the admin GET).
    /// </summary>
    private static int? ReadLifetimeSetting(RedbObject<ApplicationProps> app, string key)
    {
        if (app.Props.Settings is null || !app.Props.Settings.TryGetValue(key, out var raw))
            return null;
        if (TimeSpan.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, out var ts))
            return (int)Math.Round(ts.TotalSeconds);
        return null;
    }
}
