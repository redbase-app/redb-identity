using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Exceptions;
using redb.Identity.Core.Mfa;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// MFA-3: WebAuthn (FIDO2) orchestration on top of <see cref="MfaService"/>.
/// <para>
/// Unlike OTP-based methods, WebAuthn does not flow through <see cref="IMfaMethod"/>'s
/// <c>InitiateSetupAsync</c> / <c>ConfirmAndApplyAsync</c> / <c>VerifyAsync</c> path
/// (the shapes are mismatched: WebAuthn has no shared secret, no destination, no 6-digit
/// code). Instead, this partial exposes four bespoke methods (Begin/Complete \u00d7 Register/Assert)
/// that the dedicated processors call. The orchestrator integrates the same lockout,
/// recovery-code, audit and challenge-replay primitives used by the OTP path.
/// </para>
/// </summary>
public sealed partial class MfaService
{
    private static readonly JsonSerializerOptions s_webAuthnJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// MFA-3: starts a WebAuthn registration ceremony. Returns
    /// <see cref="CredentialCreateOptions"/> (forwarded as JSON to the browser) bundled with
    /// an opaque <c>setupToken</c> that round-trips the challenge + serialized options.
    /// <para>
    /// No DB write occurs until <see cref="CompleteWebAuthnRegistrationAsync"/> succeeds.
    /// </para>
    /// </summary>
    public async Task<(CredentialCreateOptions Options, string SetupToken)> BeginWebAuthnRegistrationAsync(
        long userId,
        string username,
        string? displayName,
        CancellationToken ct = default)
    {
        var webAuthn = ResolveWebAuthnMethod();
        var existing = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        var creds = existing?.Props?.WebAuthnCredentials;

        // Per-user UV ratchet: if the user already has a UV credential, force UV on the new
        // credential too \u2014 we never let a user weaken their own posture by adding a
        // non-UV authenticator after a UV one.
        bool enforceUv = creds is { Count: > 0 } && creds.Values.Any(c => c.UserVerified);

        var options = webAuthn.BeginRegistration(
            userId,
            username,
            string.IsNullOrEmpty(displayName) ? username : displayName,
            creds,
            enforceUv);

        var token = _setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = userId,
            MethodId = "webauthn",
            IssuedAt = _timeProvider.GetUtcNow(),
            Jti = Guid.NewGuid(),
            WebAuthnChallenge = options.Challenge,
            WebAuthnOptionsJson = JsonSerializer.Serialize(options, s_webAuthnJson),
        });

        _logger.LogDebug("WebAuthn registration begin: userId={UserId}", userId);
        return (options, token);
    }

    /// <summary>
    /// MFA-3: completes a WebAuthn registration ceremony. Verifies the attestation, runs the
    /// AAGUID/UV gates inside <see cref="WebAuthnMfaMethod"/>, persists the credential, and
    /// (if this is the user's first MFA method) issues fresh recovery codes returned to the
    /// caller exactly once.
    /// <para>
    /// Caller must hold a transaction with a row-lock on the user's MFA props row when
    /// calling this method \u2014 the processor wraps it in <c>BeginTransactionAsync</c> +
    /// <c>LockForUpdateAsync</c> just like <see cref="VerifyAsync"/>.
    /// </para>
    /// </summary>
    /// <returns>
    /// Tuple of (success, recoveryCodes-or-null, credentialKey). <c>recoveryCodes</c> is non-null
    /// only on the very first MFA method enrolled by this user. <c>credentialKey</c> is the
    /// dictionary key used to look up / rename / delete this credential later.
    /// </returns>
    public async Task<(bool Success, string[]? RecoveryCodes, string? CredentialKey, string? ErrorCode)>
        CompleteWebAuthnRegistrationAsync(
            long userId,
            AuthenticatorAttestationRawResponse attestationResponse,
            string setupToken,
            string? credentialDisplayName,
            CancellationToken ct = default)
    {
        var payload = _setupTokenProtector.Unprotect(setupToken);
        if (payload is null
            || payload.UserId != userId
            || !string.Equals(payload.MethodId, "webauthn", StringComparison.OrdinalIgnoreCase)
            || payload.WebAuthnChallenge is null
            || string.IsNullOrEmpty(payload.WebAuthnOptionsJson))
        {
            _logger.LogWarning("WebAuthn register confirm rejected: invalid setup token (userId={UserId})", userId);
            return (false, null, null, "invalid_setup_token");
        }

        var originalOptions = JsonSerializer.Deserialize<CredentialCreateOptions>(
            payload.WebAuthnOptionsJson, s_webAuthnJson);
        if (originalOptions is null)
            return (false, null, null, "invalid_setup_token");

        // Single-use: reject second confirm with the same setup token.
        var consumeResult = await ResolveChallengeStore().ConsumeAsync(
            payload.WebAuthnChallenge, userId, "register",
            TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);
        if (consumeResult == WebAuthnConsumeResult.Replay)
        {
            _securityLogger.LogWarning("WebAuthn register replay detected: userId={UserId}", userId);
            return (false, null, null, "replay_detected");
        }

        WebAuthnCredential newCred;
        try
        {
            newCred = await ResolveWebAuthnMethod().CompleteRegistrationAsync(
                attestationResponse, originalOptions, userId, ct).ConfigureAwait(false);
        }
        catch (WebAuthnException ex)
        {
            _logger.LogWarning("WebAuthn register failed: userId={UserId}, code={Code}", userId, ex.ErrorCode);
            return (false, null, null, ex.ErrorCode);
        }

        if (!string.IsNullOrWhiteSpace(credentialDisplayName))
            newCred.DisplayName = credentialDisplayName!.Trim();

        var key = EncodeCredentialKey(newCred.CredentialId);
        var obj = await LoadOrCreateMfaPropsAsync(userId, ct).ConfigureAwait(false);
        obj.Props.WebAuthnCredentials ??= new Dictionary<string, WebAuthnCredential>(StringComparer.Ordinal);

        // Defence-in-depth: same credential id MUST NOT be added twice. Fido2NetLib's
        // ExcludeCredentials covers the well-behaved-browser case; this guards against a
        // malicious/buggy client that strips ExcludeCredentials and submits a duplicate.
        if (obj.Props.WebAuthnCredentials.ContainsKey(key))
        {
            return (false, null, null, "credential_already_registered");
        }
        obj.Props.WebAuthnCredentials[key] = newCred;

        var wasAlreadyEnabled = obj.Props.Enabled;
        obj.Props.Enabled = true;
        if (string.IsNullOrEmpty(obj.Props.DefaultMethod))
            obj.Props.DefaultMethod = "webauthn";

        string[]? plainCodes = null;
        if (!wasAlreadyEnabled || obj.Props.RecoveryCodes is null or { Count: 0 })
        {
            var (codes, hashedCodes) = GenerateRecoveryCodes();
            obj.Props.RecoveryCodes = hashedCodes;
            plainCodes = codes;
        }

        obj.Props.FailedAttempts = 0;
        obj.Props.LockedUntil = null;

        await _redb.SaveAsync(obj).ConfigureAwait(false);
        _logger.LogDebug("WebAuthn credential registered: userId={UserId}, key={Key}", userId, key);

        return (true, plainCodes, key, null);
    }

    /// <summary>
    /// MFA-3: starts a WebAuthn assertion ceremony for an authenticated user (login flow or
    /// step-up). Returns <see cref="AssertionOptions"/> + an encrypted <c>mfa_state</c> that
    /// the caller forwards to the client.
    /// </summary>
    /// <returns>
    /// (options, mfaStateToken). When the user has zero registered credentials the returned
    /// options' AllowedCredentials list is empty \u2014 the browser will surface a graceful
    /// no-credential error, identical to a non-existent userId, preserving username privacy.
    /// </returns>
    public async Task<(AssertionOptions Options, string MfaStateToken)?> BeginWebAuthnAssertionAsync(
        long userId,
        string? username,
        string? returnUrl,
        CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        var creds = obj?.Props?.WebAuthnCredentials;
        if (creds is null || creds.Count == 0)
            return null;

        var options = ResolveWebAuthnMethod().BeginAssertion(creds);

        var state = new MfaState
        {
            Jti = Guid.NewGuid(),
            UserId = userId,
            Username = username,
            Methods = ["webauthn"],
            ReturnUrl = returnUrl,
            IssuedAt = _timeProvider.GetUtcNow(),
            WebAuthnChallenge = options.Challenge,
            WebAuthnFlow = "assert",
            WebAuthnOptionsJson = JsonSerializer.Serialize(options, s_webAuthnJson),
        };

        var token = _stateProtector.Protect(state);
        return (options, token);
    }

    /// <summary>
    /// MFA-3: completes a WebAuthn assertion. Caller must hold a transaction with a row-lock
    /// on the MFA props (same pattern as <see cref="VerifyAsync"/>) so concurrent assertions
    /// cannot lose each other's <see cref="WebAuthnCredential.SignCount"/> updates.
    /// </summary>
    /// <returns>
    /// (success, errorCode). <c>success == true</c> means the credential mutations were
    /// persisted; <c>errorCode</c> on failure is one of <c>invalid_state</c> /
    /// <c>flow_mismatch</c> / <c>replay_detected</c> / <c>locked_out</c> /
    /// <c>uv_downgrade</c> / <c>sign_counter_rollback</c> / <c>credential_not_found</c> /
    /// <c>verification_failed</c>.
    /// </returns>
    public async Task<(bool Success, string? ErrorCode)> CompleteWebAuthnAssertionAsync(
        long userId,
        AuthenticatorAssertionRawResponse assertionResponse,
        MfaState state,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.UserId != userId)
        {
            _securityLogger.LogWarning("WebAuthn assert rejected (state.UserId mismatch): caller={UserId}", userId);
            return (false, "invalid_state");
        }
        if (!string.Equals(state.WebAuthnFlow, "assert", StringComparison.Ordinal)
            || state.WebAuthnChallenge is null
            || string.IsNullOrEmpty(state.WebAuthnOptionsJson))
        {
            return (false, "flow_mismatch");
        }

        var originalOptions = JsonSerializer.Deserialize<AssertionOptions>(
            state.WebAuthnOptionsJson, s_webAuthnJson);
        if (originalOptions is null)
            return (false, "invalid_state");

        // Single-use challenge \u2014 reject replays even within the state token's TTL.
        var ttl = TimeSpan.FromSeconds(Math.Max(60, ResolveWebAuthnOptions().ChallengeTtlSeconds));
        var consumeResult = await ResolveChallengeStore().ConsumeAsync(
            state.WebAuthnChallenge, userId, "assert", ttl, ct).ConfigureAwait(false);
        if (consumeResult == WebAuthnConsumeResult.Replay)
        {
            _securityLogger.LogWarning("WebAuthn assert replay detected: userId={UserId}", userId);
            return (false, "replay_detected");
        }

        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is null)
            return (false, "credential_not_found");
        var props = obj.Props;

        if (IsLockedOut(props))
        {
            _securityLogger.LogWarning("WebAuthn assert rejected (locked out): userId={UserId}", userId);
            return (false, "locked_out");
        }

        if (props.WebAuthnCredentials is null || props.WebAuthnCredentials.Count == 0)
            return (false, "credential_not_found");

        WebAuthnCredential? mutated;
        try
        {
            mutated = await ResolveWebAuthnMethod().CompleteAssertionAsync(
                assertionResponse, originalOptions, props.WebAuthnCredentials, userId, ct).ConfigureAwait(false);
        }
        catch (WebAuthnException ex)
        {
            // Counter rollback / UV downgrade / credential_not_found are *typed* failures;
            // surface them but still treat as a failed verify for lockout accounting.
            BumpFailedAttempts(props);
            await _redb.SaveAsync(obj).ConfigureAwait(false);
            return (false, ex.ErrorCode);
        }

        if (mutated is null)
        {
            BumpFailedAttempts(props);
            await _redb.SaveAsync(obj).ConfigureAwait(false);
            return (false, "verification_failed");
        }

        props.FailedAttempts = 0;
        props.LockedUntil = null;
        props.LastVerifiedAt = _timeProvider.GetUtcNow();
        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return (true, null);
    }

    /// <summary>
    /// MFA-3: lists registered WebAuthn credentials for the given user.
    /// </summary>
    public async Task<IReadOnlyList<WebAuthnCredentialSummary>> ListWebAuthnCredentialsAsync(
        long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        var creds = obj?.Props?.WebAuthnCredentials;
        if (creds is null || creds.Count == 0)
            return Array.Empty<WebAuthnCredentialSummary>();

        return creds.Select(kv => new WebAuthnCredentialSummary(
            kv.Key,
            kv.Value.DisplayName,
            kv.Value.Aaguid,
            kv.Value.RegisteredAt,
            kv.Value.LastUsedAt,
            kv.Value.UserVerified,
            kv.Value.BackupEligible,
            kv.Value.BackupState
        )).ToList();
    }

    /// <summary>
    /// MFA-3: renames a single credential (the friendly display label).
    /// </summary>
    public async Task<bool> RenameWebAuthnCredentialAsync(
        long userId, string credentialKey, string? newDisplayName, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props?.WebAuthnCredentials is null) return false;
        if (!obj.Props.WebAuthnCredentials.TryGetValue(credentialKey, out var cred)) return false;
        cred.DisplayName = string.IsNullOrWhiteSpace(newDisplayName) ? null : newDisplayName!.Trim();
        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// MFA-3: deletes one credential. If this was the last credential and no other MFA method
    /// is enabled, the WebAuthn-method subsystem is silently disabled (but Enabled flag is left
    /// untouched if e.g. TOTP is still configured).
    /// </summary>
    public async Task<bool> DeleteWebAuthnCredentialAsync(
        long userId, string credentialKey, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props?.WebAuthnCredentials is null) return false;
        if (!obj.Props.WebAuthnCredentials.Remove(credentialKey)) return false;

        if (obj.Props.WebAuthnCredentials.Count == 0)
        {
            obj.Props.WebAuthnCredentials = null;
            // Defer to existing CollectEnabledMethods semantics: Enabled stays true if any other
            // method is confirmed; otherwise drop it.
            if (CollectEnabledMethods(obj.Props).Length == 0)
            {
                obj.Props.Enabled = false;
                if (string.Equals(obj.Props.DefaultMethod, "webauthn", StringComparison.OrdinalIgnoreCase))
                    obj.Props.DefaultMethod = null;
            }
        }
        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return true;
    }

    // ── helpers ──

    /// <summary>
    /// Encodes a raw credential id as a stable dictionary key (base64url, no padding) suitable
    /// for use both as the JSON property name and the URL-path segment in REST endpoints.
    /// </summary>
    internal static string EncodeCredentialKey(byte[] rawId)
    {
        return Convert.ToBase64String(rawId)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private void BumpFailedAttempts(MfaProps props)
    {
        props.FailedAttempts++;
        if (props.FailedAttempts >= _maxFailedAttempts)
        {
            props.LockedUntil = _timeProvider.GetUtcNow() + _lockoutDuration;
            _securityLogger.LogWarning(
                "MFA lockout activated via WebAuthn: attempts={Attempts}", props.FailedAttempts);
        }
    }

    private IWebAuthnMfaMethod ResolveWebAuthnMethod()
    {
        if (_methods.TryGetValue("webauthn", out var m) && m is IWebAuthnMfaMethod web)
            return web;
        throw new InvalidOperationException(
            "WebAuthn is not enabled. Set RedbIdentityOptions.WebAuthn.Enabled = true and ensure IFido2 is registered.");
    }

    /// <summary>
    /// MFA-3: lazy-resolved <see cref="IWebAuthnChallengeStore"/> dependency. We deliberately
    /// avoid making it a constructor parameter so that the OTP-only configuration of the
    /// service does not have to register a no-op stub when WebAuthn is disabled.
    /// </summary>
    private IWebAuthnChallengeStore ResolveChallengeStore()
        => _webAuthnChallengeStore
            ?? throw new InvalidOperationException(
                "IWebAuthnChallengeStore is not registered. Enable RedbIdentityOptions.WebAuthn to wire it up.");

    private IdentityWebAuthnOptions ResolveWebAuthnOptions()
        => _webAuthnOptions
            ?? throw new InvalidOperationException(
                "IdentityWebAuthnOptions is not registered. Enable RedbIdentityOptions.WebAuthn to wire it up.");

    // Cached-via-DI references injected by the partial constructor extension below.
    private IWebAuthnChallengeStore? _webAuthnChallengeStore;
    private IdentityWebAuthnOptions? _webAuthnOptions;

    /// <summary>
    /// Property setter for DI activation \u2014 called from <c>RedbIdentityServiceExtensions</c>
    /// when WebAuthn is enabled. Kept off the primary constructor signature so existing
    /// MfaService construction sites (and hundreds of unit tests) do not need new arguments.
    /// </summary>
    public void AttachWebAuthn(IWebAuthnChallengeStore challengeStore, IdentityWebAuthnOptions options)
    {
        _webAuthnChallengeStore = challengeStore;
        _webAuthnOptions = options;
    }
}

/// <summary>MFA-3: client-facing summary of a registered WebAuthn credential.</summary>
public sealed record WebAuthnCredentialSummary(
    string Key,
    string? DisplayName,
    string? Aaguid,
    DateTimeOffset RegisteredAt,
    DateTimeOffset? LastUsedAt,
    bool UserVerified,
    bool BackupEligible,
    bool BackupState);
