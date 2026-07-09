using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// Result of validating a federation state blob. Distinguishes the failure mode so
/// callers / audit hooks can react appropriately (and so tests can assert precisely).
/// </summary>
public enum FederationStateValidationFailure
{
    None = 0,
    /// <summary>Blob is null/empty/garbage or its DataProtection envelope was tampered with.</summary>
    Tampered,
    /// <summary>Blob decrypted but its <c>IssuedAt + StateMaxAge</c> has elapsed.</summary>
    Expired,
    /// <summary>Blob's <c>jti</c> was already consumed (one-time-use violation, replay).</summary>
    AlreadyUsed,
    /// <summary>Browser-binding cookie missing or its hash didn't match the value baked into the state.</summary>
    BindingMismatch,
}

/// <summary>
/// Encrypts/decrypts federation state parameters using ASP.NET DataProtection.
/// State carries the provider id, return URL, OIDC nonce, PKCE code verifier,
/// issuance timestamp, a unique <c>jti</c> for one-time-use enforcement (C6),
/// and an optional browser-binding hash (C6).
/// </summary>
public sealed class FederationStateProtector
{
    private const string Purpose = "redb.identity.federation-state";
    private static readonly TimeSpan FallbackMaxAge = TimeSpan.FromMinutes(5);

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly IFederationStateNonceStore? _nonceStore;
    private readonly FederationStateOptions _options;
    private readonly ILogger<FederationStateProtector>? _logger;

    public FederationStateProtector(IDataProtectionProvider provider)
        : this(provider, TimeProvider.System, nonceStore: null, options: null, logger: null)
    {
    }

    public FederationStateProtector(
        IDataProtectionProvider provider,
        TimeProvider? timeProvider,
        IFederationStateNonceStore? nonceStore,
        FederationStateOptions? options)
        : this(provider, timeProvider, nonceStore, options, logger: null)
    {
    }

    public FederationStateProtector(
        IDataProtectionProvider provider,
        TimeProvider? timeProvider,
        IFederationStateNonceStore? nonceStore,
        FederationStateOptions? options,
        ILogger<FederationStateProtector>? logger)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _nonceStore = nonceStore;
        _options = options ?? new FederationStateOptions();
        _logger = logger;
    }

    /// <summary>
    /// Encrypts federation state into a base64-safe string. Sets <c>IssuedAt</c> to
    /// the current <see cref="TimeProvider"/> time when missing and assigns a fresh
    /// <c>Jti</c> when missing.
    /// </summary>
    public string Protect(FederationState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        state.IssuedAt ??= _timeProvider.GetUtcNow();
        if (string.IsNullOrEmpty(state.Jti))
            state.Jti = Guid.NewGuid().ToString("N");

        var json = JsonSerializer.SerializeToUtf8Bytes(state);
        var encrypted = _protector.Protect(json);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Computes the browser-binding hash that should be stored inside the state blob
    /// for a given per-flow secret. Uses SHA-256 — the secret never traverses storage.
    /// </summary>
    public static string ComputeBindingHash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Legacy synchronous overload. Decrypts and validates TTL only. Does NOT consult
    /// the nonce store and does NOT verify browser binding — kept for compatibility
    /// with callers that don't need C6 hardening (and for unit tests).
    /// </summary>
    public FederationState? Unprotect(string protectedState, TimeSpan? maxAge = null)
    {
        var (state, _) = TryDecrypt(protectedState, maxAge);
        return state;
    }

    /// <summary>
    /// Full C6 validation path: decrypt, TTL check, browser-binding (if present in state),
    /// one-time-use (if a nonce store is configured and RequireOneTimeUse).
    /// Returns the decrypted state and a precise failure reason.
    /// </summary>
    public async Task<(FederationState? State, FederationStateValidationFailure Failure)> UnprotectAsync(
        string protectedState,
        string? bindingSecret,
        CancellationToken ct = default)
    {
        var (state, failure) = TryDecrypt(protectedState, _options.StateMaxAge);
        if (state is null)
            return (null, failure);

        if (!string.IsNullOrEmpty(state.BindingHash))
        {
            if (string.IsNullOrEmpty(bindingSecret))
                return (null, FederationStateValidationFailure.BindingMismatch);

            var presented = ComputeBindingHash(bindingSecret);
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(presented),
                    Encoding.ASCII.GetBytes(state.BindingHash)))
            {
                return (null, FederationStateValidationFailure.BindingMismatch);
            }
        }

        if (_options.RequireOneTimeUse && _nonceStore is not null)
        {
            var jti = state.Jti;
            if (string.IsNullOrEmpty(jti))
                return (null, FederationStateValidationFailure.Tampered);

            var consumed = await _nonceStore.TryConsumeAsync(jti, _options.StateMaxAge, ct).ConfigureAwait(false);
            if (!consumed)
                return (null, FederationStateValidationFailure.AlreadyUsed);
        }

        return (state, FederationStateValidationFailure.None);
    }

    private (FederationState? State, FederationStateValidationFailure Failure) TryDecrypt(
        string protectedState, TimeSpan? maxAge)
    {
        if (string.IsNullOrEmpty(protectedState))
            return (null, FederationStateValidationFailure.Tampered);

        FederationState? state;
        try
        {
            var encrypted = Convert.FromBase64String(protectedState);
            var json = _protector.Unprotect(encrypted);
            state = JsonSerializer.Deserialize<FederationState>(json);
        }
        catch (Exception ex)
        {
            // Tampered ciphertext OR DataProtection key rotation. Both must be visible to
            // operators — a sustained run of these is a security signal.
            _logger?.LogWarning(ex,
                "FederationStateProtector: failed to decrypt federation state (length={Length}).",
                protectedState.Length);
            return (null, FederationStateValidationFailure.Tampered);
        }

        if (state is null || string.IsNullOrEmpty(state.ProviderId))
        {
            _logger?.LogWarning(
                "FederationStateProtector: decrypted state was null or had empty ProviderId.");
            return (null, FederationStateValidationFailure.Tampered);
        }

        var ttl = maxAge ?? FallbackMaxAge;
        var age = _timeProvider.GetUtcNow() - (state.IssuedAt ?? DateTimeOffset.MinValue);
        if (age > ttl)
        {
            _logger?.LogDebug(
                "FederationStateProtector: state expired (age={AgeSeconds}s, max={MaxSeconds}s, provider={ProviderId}).",
                age.TotalSeconds, ttl.TotalSeconds, state.ProviderId);
            return (null, FederationStateValidationFailure.Expired);
        }

        return (state, FederationStateValidationFailure.None);
    }
}

/// <summary>
/// Data encrypted in the federation state parameter.
/// </summary>
public sealed class FederationState
{
    public required string ProviderId { get; set; }
    public string? ReturnUrl { get; set; }
    public string? Nonce { get; set; }
    public string? CodeVerifier { get; set; }
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>Unique id for one-time-use enforcement (C6). Assigned by Protect when missing.</summary>
    public string? Jti { get; set; }

    /// <summary>Optional SHA-256 hash of the per-flow browser-binding secret (C6, opt-in).</summary>
    public string? BindingHash { get; set; }

    /// <summary>
    /// H8 (DoD §4 gap (b)): when present, the callback is interpreted as an
    /// "add this federated identity to the existing user" operation rather than a regular
    /// login. The challenge processor sets this from the access-token subject of the
    /// authenticated caller; the callback processor must reject when the resolved value
    /// does not match the still-authenticated session.
    /// </summary>
    public long? LinkUserId { get; set; }
}