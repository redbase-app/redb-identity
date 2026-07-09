using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Models.Users;
using redb.Core.Query;
using redb.Core.Security;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Verifies user credentials via external providers (if any) then falls back
/// to the local <c>_users</c> table. Single orchestration point for all
/// authentication: Login page, ROPC grant, Device code verification.
/// </summary>
public sealed class LoginService
{
    private readonly IRedbService _redb;
    private readonly ILogger<LoginService> _logger;
    private readonly ILogger _securityLogger;
    private readonly IExternalUserProvider[] _externalProviders;
    private readonly MfaService? _mfaService;
    private readonly TimeProvider _timeProvider;
    private readonly IPasswordHasher? _passwordHasher;
    private readonly IdentityMetrics? _metrics;
    private readonly IServiceScopeFactory? _scopeFactory;
    private readonly Configuration.PasswordPolicyOptions? _passwordPolicy;

    public LoginService(
        IRedbService redb,
        ILogger<LoginService> logger,
        IEnumerable<IExternalUserProvider>? externalProviders = null,
        MfaService? mfaService = null,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        IPasswordHasher? passwordHasher = null,
        IdentityMetrics? metrics = null,
        IServiceScopeFactory? scopeFactory = null,
        Configuration.PasswordPolicyOptions? passwordPolicy = null)
    {
        _redb = redb;
        _logger = logger;
        _scopeFactory = scopeFactory;
        _externalProviders = (externalProviders ?? [])
            .OrderBy(p => p.Priority)
            .ToArray();
        _mfaService = mfaService;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _passwordHasher = passwordHasher;
        _metrics = metrics;
        _passwordPolicy = passwordPolicy;
        // E5: route audit-class signals (denied logins, per-provider deny) to the
        // RedbIdentity.Security channel so SIEM/audit sinks can subscribe without
        // also ingesting routine operational logs. Fall back to the regular logger
        // when no factory is available (tests / non-DI construction).
        _securityLogger = loggerFactory is not null
            ? Security.IdentitySecurityLog.CreateLogger(loggerFactory)
            : logger;
    }

    /// <summary>
    /// Validates username/password and returns the user on success.
    /// Tries external providers in priority order, then falls back to local.
    /// </summary>
    public async Task<LoginResult> AuthenticateAsync(
        string username, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return LoginResult.Failed("Username and password are required.");

        // Phase 1: Try external providers in priority order
        foreach (var provider in _externalProviders)
        {
            ExternalAuthResult? extResult;
            try
            {
                extResult = await provider.AuthenticateAsync(username, password, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "External provider '{Provider}' threw for user '{Username}', skipping",
                    provider.ProviderName, username);
                continue;
            }

            if (extResult is null)
                continue; // provider doesn't handle this user

            if (!extResult.Succeeded)
            {
                // Provider recognized the user but auth failed — do NOT fall through
                _securityLogger.LogWarning("Login denied by '{Provider}' for user '{Username}': {Error}",
                    provider.ProviderName, username, extResult.ErrorMessage);
                return LoginResult.Failed(extResult.ErrorMessage ?? "Authentication failed.");
            }

            _logger.LogDebug("User '{Username}' authenticated via external provider '{Provider}'",
                username, provider.ProviderName);

            return await ResolveExternalUser(provider.ProviderName, extResult, username)
                .ConfigureAwait(false);
        }

        // Phase 2: Fall back to local _users password check
        return await AuthenticateLocal(username, password).ConfigureAwait(false);
    }

    private async Task<LoginResult> AuthenticateLocal(string username, string password)
    {
        // C12 / F3: measure verify duration across both success and failure branches —
        // ValidateUserAsync wraps the BCrypt/Argon2id verify plus SELECT latency. The
        // histogram bucket discriminates `result` success/fail for OTEL tagging.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var coreUser = await _redb.UserProvider.ValidateUserAsync(username, password)
            .ConfigureAwait(false);
        sw.Stop();
        _metrics?.PasswordVerifyDuration.Record(
            sw.Elapsed.TotalMilliseconds,
            new KeyValuePair<string, object?>("result", coreUser is null ? "fail" : "success"));

        if (coreUser is null)
        {
            // C14 / SEC-A20: timing-equivalence. ValidateUserAsync returns null for
            // (a) user not found, (b) user disabled, (c) wrong password — but only the
            // last path actually invokes the BCrypt verify (~100 ms). The first two paths
            // return early, leaking via timing whether a username exists. Run a fake
            // BCrypt verify so the wall-clock cost of all three negative branches is
            // approximately equivalent. The fake hash is precomputed and the result is
            // intentionally discarded.
            try { _ = BCrypt.Net.BCrypt.Verify(password ?? "", FakeBcryptHash); } catch { }

            _securityLogger.LogWarning("Login denied: user '{Username}' — invalid credentials or not found", username);
            return LoginResult.Failed("Invalid credentials.");
        }

        // C12: upgrade-on-login. If the stored hash is in a legacy format (BCrypt,
        // SHA256+salt) or uses weaker Argon2id parameters than the current configuration,
        // re-hash the plaintext and persist. Fire-and-forget — a rehash failure must not
        // block login (the user is already authenticated).
        if (_passwordHasher is not null && !string.IsNullOrEmpty(coreUser.Password)
            && NeedsRehash(_passwordHasher, coreUser.Password))
        {
            // C12 / BUG: the rehash is fire-and-forget, so it MUST NOT capture the
            // request-scoped IRedbService (that scope will be disposed as soon as the
            // login response returns, causing any subsequent use to hang or throw).
            // Instead, create a fresh DI scope and resolve a new IRedbService there.
            var scopeFactory = _scopeFactory;
            var userId = coreUser.Id;
            var capturedPassword = password;
            if (scopeFactory is not null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var rehashScope = scopeFactory.CreateScope();
                        var rehashRedb = rehashScope.ServiceProvider.GetRequiredService<IRedbService>();
                        var freshUser = await rehashRedb.UserProvider.GetUserByIdAsync(userId).ConfigureAwait(false);
                        if (freshUser is null) return;
                        await rehashRedb.UserProvider.SetPasswordAsync(freshUser, capturedPassword, currentUser: freshUser)
                            .ConfigureAwait(false);
                        _logger.LogDebug("Password hash upgraded to current algorithm for user id={UserId}", userId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Password hash auto-rehash failed for user id={UserId}", userId);
                    }
                });
            }
            else
            {
                _logger.LogDebug("Password hash rehash skipped for user id={UserId}: no IServiceScopeFactory available", userId);
            }
        }

        // Note: ValidateUserAsync already returns null for disabled users — no separate
        // branch is needed here, and adding one would re-introduce the enumeration leak
        // (different error message for "disabled" vs "wrong password").
        var oidcObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        _logger.LogDebug("User '{Username}' (id={UserId}) authenticated locally",
            username, coreUser.Id);

        // Check MFA (after password validated, before session creation).
        // B9 / BUG-4: single atomic read of MfaProps via LoadMfaStatusAsync (was two
        // separate reads — IsMfaEnabledAsync + GetEnabledMethodsAsync — leaving a TOCTOU
        // window where MFA could be enabled/disabled between the two calls).
        if (_mfaService is not null)
        {
            var (mfaEnabled, methods) = await _mfaService.LoadMfaStatusAsync(coreUser.Id).ConfigureAwait(false);
            if (mfaEnabled && methods.Length > 0)
            {
                _logger.LogDebug("MFA required for user '{Username}' (id={UserId}), methods={Methods}",
                    username, coreUser.Id, string.Join(",", methods));
                return LoginResult.MfaChallenge(coreUser, methods);
            }
        }

        // H10 — password expiration. Compare against the configured MaxAge if any. Null
        // PasswordChangedAt is treated as "not tracked" (legacy users), to avoid forcing
        // a password change on every account that pre-dates H10.
        var maxAge = _passwordPolicy?.MaxAge ?? TimeSpan.Zero;
        if (maxAge > TimeSpan.Zero
            && oidcObj?.Props.PasswordChangedAt is DateTimeOffset changedAt
            && _timeProvider.GetUtcNow() - changedAt > maxAge)
        {
            _logger.LogDebug(
                "Password expired for user '{Username}' (id={UserId}); changedAt={ChangedAt}, maxAge={MaxAge}",
                username, coreUser.Id, changedAt, maxAge);
            return LoginResult.PasswordExpired(coreUser, oidcObj);
        }

        return LoginResult.Success(coreUser, oidcObj);
    }

    /// <summary>
    /// Pre-computed BCrypt hash of an arbitrary unguessable string used solely for
    /// timing-equivalence (see C14 / SEC-A20). Cost factor 12 to mirror the production
    /// hash work factor used by <see cref="redb.Core.Security.BcryptPasswordHasher"/>.
    /// </summary>
    private static readonly string FakeBcryptHash =
        BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString("N"), workFactor: 12);

    /// <summary>
    /// C12: ask the hasher whether the stored hash should be re-hashed after a successful
    /// verify. <see cref="IPasswordHasher"/> itself has no <c>NeedsRehash</c> contract, so
    /// we duck-type against the concrete hashers supplied by this module. Unknown
    /// implementations report "no upgrade needed" (conservative — no spurious rehashes).
    /// </summary>
    private static bool NeedsRehash(IPasswordHasher hasher, string storedHash) => hasher switch
    {
        Security.MultiFormatPasswordHasher mf => mf.NeedsRehash(storedHash),
        Security.Argon2idPasswordHasher a => a.NeedsRehash(storedHash),
        _ => false,
    };

    /// <summary>
    /// Find-or-create local _users + UserProps for an externally authenticated user.
    /// On subsequent logins, updates profile from external source.
    /// </summary>
    private async Task<LoginResult> ResolveExternalUser(
        string providerName, ExternalAuthResult ext, string username)
    {
        return await ResolveExternalUserCore(providerName, ext, username).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves a federated user by reverse lookup on <c>value_string</c> (indexed, O(1)).
    /// Used by the federation callback flow where there is no username/password — only
    /// an <see cref="ExternalAuthResult"/> from the external IdP.
    /// On first login: auto-provisions a local user (login = email ?? sub).
    /// On subsequent logins: syncs profile from external source.
    /// </summary>
    public async Task<LoginResult> ResolveFederatedUserAsync(
        string providerName, ExternalAuthResult ext, CancellationToken ct = default)
    {
        if (ext is null || !ext.Succeeded || string.IsNullOrEmpty(ext.ExternalId))
            return LoginResult.Failed("Invalid external authentication result.");

        // H8: per-link reverse lookup via FederatedIdentityProps (UNIQUE on value_string).
        // O(1) — supports many federated identities per user.
        var valueString = $"{providerName}:{ext.ExternalId}";
        var link = await _redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.ValueString == valueString)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        long? linkedUserId = link?.key;

        if (linkedUserId.HasValue)
        {
            var coreUser = await _redb.UserProvider.GetUserByIdAsync(linkedUserId.Value)
                .ConfigureAwait(false);

            if (coreUser is null)
            {
                _logger.LogWarning(
                    "Federated link references userId={UserId} but _users row not found (provider={Provider}, sub={Sub})",
                    linkedUserId.Value, providerName, ext.ExternalId);
                return LoginResult.Failed("User account not found.");
            }

            if (!coreUser.Enabled)
            {
                _securityLogger.LogWarning("Login denied: federated user '{Username}' is disabled locally", coreUser.Login);
                return LoginResult.Failed("User account is not active.");
            }

            // Authoritative profile sync
            await SyncCoreProfile(coreUser, ext).ConfigureAwait(false);

            var oidcObj = await _redb.Query<UserProps>()
                .WhereRedb(o => o.Key == coreUser.Id)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);

            if (oidcObj is not null)
            {
                await SyncOidcProps(oidcObj, providerName, ext, coreUser.Login ?? ext.Email ?? ext.ExternalId)
                    .ConfigureAwait(false);
            }

            // H8: upsert per-link record
            await UpsertFederatedIdentityLinkAsync(coreUser.Id, providerName, ext, isNewLink: link is null)
                .ConfigureAwait(false);

            _logger.LogDebug(
                "Federated user '{Username}' (id={UserId}) authenticated via '{Provider}'",
                coreUser.Login, coreUser.Id, providerName);

            return LoginResult.Success(coreUser, oidcObj);
        }

        // H8 (gap (c)): conflict-on-email — if a local user already exists with this email
        // but no federated link, refuse to silently take over the account. Caller
        // (FederationCallbackProcessor) translates this into a redirect to the configured
        // conflict-resolution page so the user can either log in locally then link, or
        // confirm a takeover with proper credentials.
        //
        // Was previously `GetUserByLoginAsync(ext.Email)` — that only triggered when the
        // local user's login literally equalled the external email, but self-register
        // forbids '@' in login so the probe was effectively dead code. `GetUserByEmailAsync`
        // (added to redb.Core in this batch) does a proper case-insensitive lookup on
        // `_users._email`, so the conflict path now fires for genuine email overlap.
        if (!string.IsNullOrEmpty(ext.Email))
        {
            var existingByEmail = await _redb.UserProvider.GetUserByEmailAsync(ext.Email)
                .ConfigureAwait(false);
            if (existingByEmail is not null)
            {
                _securityLogger.LogWarning(
                    "Federated email conflict: provider={Provider} sub={Sub} email={Email} matches existing local user id={UserId}",
                    providerName, ext.ExternalId, ext.Email, existingByEmail.Id);
                return LoginResult.EmailConflict(ext.Email, providerName, ext.ExternalId);
            }
        }

        // New user — auto-provision
        var username = ext.Email ?? ext.ExternalId;
        return await ResolveExternalUserCore(providerName, ext, username).ConfigureAwait(false);
    }

    private async Task<LoginResult> ResolveExternalUserCore(
        string providerName, ExternalAuthResult ext, string username)
    {
        // Try to find existing user by login (unique in _users)
        var coreUser = await _redb.UserProvider.GetUserByLoginAsync(username)
            .ConfigureAwait(false);

        if (coreUser is null)
        {
            // First login ever — create local user with random password (external-only)
            coreUser = await _redb.UserProvider.CreateUserAsync(new CreateUserRequest
            {
                Login = username,
                Password = Guid.NewGuid().ToString("N") + "Aa1!", // satisfies any complexity rules
                Name = ext.DisplayName ?? username,
                Email = ext.Email,
                Phone = ext.Phone,
                Enabled = true,
                CodeString = providerName // quick marker on _users level
            }).ConfigureAwait(false);

            _logger.LogDebug("Created local user '{Username}' (id={UserId}) for external provider '{Provider}'",
                username, coreUser.Id, providerName);
        }

        if (!coreUser.Enabled)
        {
            _securityLogger.LogWarning("Login denied: external user '{Username}' is disabled locally", username);
            return LoginResult.Failed("User account is not active.");
        }

        // Authoritative sync: always push external profile → _users row
        var needsUpdate = false;
        var updateReq = new UpdateUserRequest();

        if (ext.DisplayName is not null && ext.DisplayName != coreUser.Name)
        {
            updateReq.Name = ext.DisplayName;
            needsUpdate = true;
        }
        if (ext.Email is not null && ext.Email != coreUser.Email)
        {
            updateReq.Email = ext.Email;
            needsUpdate = true;
        }
        if (ext.Phone is not null && ext.Phone != coreUser.Phone)
        {
            updateReq.Phone = ext.Phone;
            needsUpdate = true;
        }

        if (needsUpdate)
        {
            coreUser = await _redb.UserProvider.UpdateUserAsync(coreUser, updateReq)
                .ConfigureAwait(false);
        }

        // Upsert UserProps with external linking + profile sync
        var oidcObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = username;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }

        // Always sync external profile on login
        oidcObj.Props.ExternalIdentities ??= new Dictionary<string, ExternalIdentity>();
        oidcObj.Props.ExternalIdentities[providerName] = new ExternalIdentity
        {
            Sub = ext.ExternalId,
            LinkedAt = _timeProvider.GetUtcNow()
        };
        // H8: do NOT touch oidcObj.value_string here — it would silently overwrite any
        // earlier federated link's reverse-lookup key. Per-link reverse lookup is
        // handled by FederatedIdentityProps (UpsertFederatedIdentityLinkAsync below).

        if (ext.GivenName is not null) oidcObj.Props.GivenName = ext.GivenName;
        if (ext.FamilyName is not null) oidcObj.Props.FamilyName = ext.FamilyName;
        if (ext.Email is not null) oidcObj.Props.EmailVerified = true;
        if (ext.Phone is not null) oidcObj.Props.PhoneNumberVerified = true;

        // Merge additional claims from external provider
        if (ext.AdditionalClaims is { Count: > 0 })
        {
            oidcObj.Props.CustomClaims ??= new Dictionary<string, string>();
            foreach (var (key, value) in ext.AdditionalClaims)
                oidcObj.Props.CustomClaims[key] = value;
        }

        await _redb.SaveAsync(oidcObj).ConfigureAwait(false);

        // H8: per-link PROPS record (enables multi-provider linking + reverse lookup)
        await UpsertFederatedIdentityLinkAsync(coreUser.Id, providerName, ext, isNewLink: true)
            .ConfigureAwait(false);

        return LoginResult.Success(coreUser, oidcObj);
    }

    private async Task SyncCoreProfile(IRedbUser coreUser, ExternalAuthResult ext)
    {
        var needsUpdate = false;
        var updateReq = new UpdateUserRequest();

        if (ext.DisplayName is not null && ext.DisplayName != coreUser.Name)
        {
            updateReq.Name = ext.DisplayName;
            needsUpdate = true;
        }
        if (ext.Email is not null && ext.Email != coreUser.Email)
        {
            updateReq.Email = ext.Email;
            needsUpdate = true;
        }
        if (ext.Phone is not null && ext.Phone != coreUser.Phone)
        {
            updateReq.Phone = ext.Phone;
            needsUpdate = true;
        }

        if (needsUpdate)
            await _redb.UserProvider.UpdateUserAsync(coreUser, updateReq).ConfigureAwait(false);
    }

    private async Task SyncOidcProps(
        RedbObject<UserProps> oidcObj, string providerName, ExternalAuthResult ext, string username)
    {
        oidcObj.Props.ExternalIdentities ??= new Dictionary<string, ExternalIdentity>();
        oidcObj.Props.ExternalIdentities[providerName] = new ExternalIdentity
        {
            Sub = ext.ExternalId,
            LinkedAt = _timeProvider.GetUtcNow()
        };
        // H8: do NOT touch oidcObj.value_string — see ResolveExternalUserCore for rationale.

        if (ext.GivenName is not null) oidcObj.Props.GivenName = ext.GivenName;
        if (ext.FamilyName is not null) oidcObj.Props.FamilyName = ext.FamilyName;
        if (ext.Email is not null) oidcObj.Props.EmailVerified = true;
        if (ext.Phone is not null) oidcObj.Props.PhoneNumberVerified = true;

        if (ext.AdditionalClaims is { Count: > 0 })
        {
            oidcObj.Props.CustomClaims ??= new Dictionary<string, string>();
            foreach (var (key, value) in ext.AdditionalClaims)
                oidcObj.Props.CustomClaims[key] = value;
        }

        await _redb.SaveAsync(oidcObj).ConfigureAwait(false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // H8 (DoD §4): per-link FederatedIdentityProps maintenance + public
    // self-service link/unlink/list API consumed by MeFederatedIdentitiesProcessor.
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Upserts a single (user, provider) federated link in the per-link PROPS scheme.
    /// Idempotent — safe to call on every successful federated login. The
    /// <c>value_string = "{provider}:{sub}"</c> is UNIQUE per scheme via the partial
    /// index on <c>_objects</c>, so concurrent inserts of the same external identity
    /// would collide at the DB level (caller logs and surfaces as a generic federation
    /// error).
    /// </summary>
    private async Task UpsertFederatedIdentityLinkAsync(
        long userId, string providerName, ExternalAuthResult ext, bool isNewLink)
    {
        var valueString = $"{providerName}:{ext.ExternalId}";
        var existing = await _redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.ValueString == valueString)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        var obj = existing ?? new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
        {
            ProviderId = providerName,
            ExternalSub = ext.ExternalId,
            LinkedAt = now,
        });

        if (existing is null)
        {
            obj.name = $"{providerName}:{ext.ExternalId}";
            obj.key = userId;
            obj.value_string = valueString;
        }
        else if (existing.key != userId)
        {
            // Hard data integrity: same external sub linked to a different local user.
            // Should never happen because of the unique constraint, but log and refuse
            // rather than silently re-pointing the link.
            _securityLogger.LogError(
                "FederatedIdentityProps integrity violation: value_string={ValueString} already links to userId={ExistingUserId}, refused re-link to userId={NewUserId}",
                valueString, existing.key, userId);
            throw new InvalidOperationException(
                $"External identity '{valueString}' is already linked to a different user.");
        }

        obj.Props.ExternalEmail = ext.Email;
        obj.Props.ExternalDisplayName = ext.DisplayName;
        obj.Props.LastLoginAt = now;

        await _redb.SaveAsync(obj).ConfigureAwait(false);
    }

    /// <summary>
    /// H8 (gap (b)): self-service link of a federated identity to an already-authenticated
    /// local user. Used by <c>MeFederatedIdentitiesProcessor</c>. Throws when the external
    /// identity is already linked to a different user.
    /// </summary>
    public async Task LinkFederatedIdentityAsync(
        long userId, string providerName, ExternalAuthResult ext, CancellationToken ct = default)
    {
        await UpsertFederatedIdentityLinkAsync(userId, providerName, ext, isNewLink: true)
            .ConfigureAwait(false);

        // Mirror to denormalized cache on UserProps
        var oidcObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.key = userId;
            oidcObj.value_guid = Guid.NewGuid();
        }

        oidcObj.Props.ExternalIdentities ??= new Dictionary<string, ExternalIdentity>();
        oidcObj.Props.ExternalIdentities[providerName] = new ExternalIdentity
        {
            Sub = ext.ExternalId,
            LinkedAt = _timeProvider.GetUtcNow()
        };
        await _redb.SaveAsync(oidcObj).ConfigureAwait(false);
    }

    /// <summary>
    /// H8 (gap (b)/(d)): self-service unlink. Returns false when no such link exists.
    /// Caller is responsible for the "last credential method" guard (it requires reading
    /// <see cref="UserProps.HasUserPassword"/>).
    /// </summary>
    public async Task<bool> UnlinkFederatedIdentityAsync(
        long userId, string providerName, CancellationToken ct = default)
    {
        var links = await _redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()
            .ConfigureAwait(false);

        var match = links.FirstOrDefault(o => string.Equals(o.Props.ProviderId, providerName, StringComparison.OrdinalIgnoreCase));
        if (match is null) return false;

        await _redb.DeleteAsync(match).ConfigureAwait(false);

        // Mirror to denormalized cache
        var oidcObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (oidcObj?.Props.ExternalIdentities is { } map && map.Remove(providerName))
            await _redb.SaveAsync(oidcObj).ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// H8 (gap (b)): list all federated links for a user. Returned in stable order
    /// (provider id ascending) for deterministic UI display.
    /// </summary>
    public async Task<IReadOnlyList<FederatedIdentityLink>> ListFederatedIdentitiesAsync(
        long userId, CancellationToken ct = default)
    {
        var links = await _redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()
            .ConfigureAwait(false);

        return links
            .OrderBy(o => o.Props.ProviderId, StringComparer.OrdinalIgnoreCase)
            .Select(o => new FederatedIdentityLink(
                o.Props.ProviderId,
                o.Props.ExternalSub,
                o.Props.ExternalEmail,
                o.Props.ExternalDisplayName,
                o.Props.LinkedAt,
                o.Props.LastLoginAt))
            .ToList();
    }
}

/// <summary>
/// H8: read-model record for a single federated identity link, returned to callers of
/// <see cref="LoginService.ListFederatedIdentitiesAsync"/>.
/// </summary>
public sealed record FederatedIdentityLink(
    string ProviderId,
    string ExternalSub,
    string? ExternalEmail,
    string? ExternalDisplayName,
    DateTimeOffset LinkedAt,
    DateTimeOffset? LastLoginAt);

/// <summary>
/// Result of a login attempt.
/// </summary>
public sealed class LoginResult
{
    public bool Succeeded { get; private init; }
    public long UserId { get; private init; }
    public string? Username { get; private init; }

    /// <summary>Core <c>_users</c> row.</summary>
    public IRedbUser? User { get; private init; }

    /// <summary>OIDC extension props (may be null if profile was never saved).</summary>
    public UserProps? OidcProps { get; private init; }

    /// <summary>
    /// Public-facing GUID identity used for the OIDC <c>sub</c> claim. Pulled from
    /// <c>RedbObject&lt;UserProps&gt;.value_guid</c> at login time so the same user has
    /// the same GUID across all sessions and tokens. <see cref="Guid.Empty"/> when the
    /// login attempt failed (no user resolved) or for legacy data without value_guid.
    /// </summary>
    public Guid SubjectGuid { get; private init; }

    public string? ErrorMessage { get; private init; }

    /// <summary>True when password is valid but MFA verification is still required.</summary>
    public bool MfaRequired { get; private init; }

    /// <summary>Available MFA methods when <see cref="MfaRequired"/> is true.</summary>
    public string[]? MfaMethods { get; private init; }

    /// <summary>
    /// H10 — password verified, but
    /// <see cref="Configuration.PasswordPolicyOptions.MaxAge"/> elapsed since
    /// <see cref="UserProps.PasswordChangedAt"/>. Caller (interactive login or password
    /// grant) must redirect the user to the password-change flow before issuing tokens.
    /// </summary>
    public bool MustChangePassword { get; private init; }

    /// <summary>
    /// H8 (gap (c)): set when the federated callback discovered an existing local user
    /// with the same email but no explicit federated link. Caller must NOT mint tokens —
    /// it should redirect the user to a "log in locally and link your social account" page.
    /// </summary>
    public bool IsEmailConflict { get; private init; }

    /// <summary>H8 (gap (c)): conflicting email reported by the external IdP.</summary>
    public string? ConflictEmail { get; private init; }

    /// <summary>H8 (gap (c)): provider id that initiated the conflicting callback.</summary>
    public string? ConflictProviderId { get; private init; }

    /// <summary>H8 (gap (c)): external subject from the IdP for the pending link.</summary>
    public string? ConflictExternalSub { get; private init; }

    public static LoginResult Success(IRedbUser user, RedbObject<UserProps>? oidcObj) => new()
    {
        Succeeded = true,
        UserId = user.Id,
        Username = user.Login,
        User = user,
        OidcProps = oidcObj?.Props,
        SubjectGuid = oidcObj?.value_guid ?? Guid.Empty
    };

    public static LoginResult Failed(string message) => new()
    {
        Succeeded = false,
        ErrorMessage = message
    };

    /// <summary>Password verified, but MFA is required before session creation.</summary>
    public static LoginResult MfaChallenge(IRedbUser user, string[] methods) => new()
    {
        Succeeded = false,
        MfaRequired = true,
        UserId = user.Id,
        Username = user.Login,
        User = user,
        MfaMethods = methods
    };

    /// <summary>
    /// H10 — password verified but expired. Caller must steer the user into the
    /// password-change flow (interactive: redirect; ROPC: reject with
    /// <c>password_expired</c>).
    /// </summary>
    public static LoginResult PasswordExpired(IRedbUser user, RedbObject<UserProps>? oidcObj) => new()
    {
        Succeeded = false,
        MustChangePassword = true,
        UserId = user.Id,
        Username = user.Login,
        User = user,
        OidcProps = oidcObj?.Props,
        SubjectGuid = oidcObj?.value_guid ?? Guid.Empty,
        ErrorMessage = "Password expired."
    };

    /// <summary>
    /// H8 (gap (c)): federated callback discovered an existing local user with this
    /// email but no link from this provider yet. Caller redirects to the conflict
    /// resolution page so the user can sign in locally and explicitly add the link.
    /// </summary>
    public static LoginResult EmailConflict(string email, string providerId, string externalSub) => new()
    {
        Succeeded = false,
        IsEmailConflict = true,
        ConflictEmail = email,
        ConflictProviderId = providerId,
        ConflictExternalSub = externalSub,
        ErrorMessage = "Federated email already registered locally."
    };
}
