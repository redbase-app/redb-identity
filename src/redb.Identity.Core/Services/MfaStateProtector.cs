using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using redb.Identity.Contracts.Mfa;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Encrypts/decrypts temporary MFA state using ASP.NET DataProtection with TTL enforcement.
/// Same pattern as <see cref="FederationStateProtector"/> but for the MFA challenge flow.
/// <para>
/// Also implements <see cref="IMfaStateInspector"/> — a minimal read-only surface in
/// <c>redb.Identity.Contracts</c> that transport facades (HTTP, gRPC, …) consume to render
/// MFA-method selectors without taking a project-reference on Core.
/// </para>
/// </summary>
public sealed class MfaStateProtector : IMfaStateInspector
{
    private const string Purpose = "redb.identity.mfa-state";
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(5);

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<MfaStateProtector>? _logger;

    public MfaStateProtector(IDataProtectionProvider provider)
        : this(provider, TimeProvider.System, null)
    {
    }

    public MfaStateProtector(IDataProtectionProvider provider, TimeProvider? timeProvider)
        : this(provider, timeProvider, null)
    {
    }

    public MfaStateProtector(
        IDataProtectionProvider provider,
        TimeProvider? timeProvider,
        ILogger<MfaStateProtector>? logger)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    /// <summary>Encrypts MFA state into a base64 string for use as a hidden form field or query parameter.</summary>
    public string Protect(MfaState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        state.IssuedAt ??= _timeProvider.GetUtcNow();
        var json = JsonSerializer.SerializeToUtf8Bytes(state);
        var encrypted = _protector.Protect(json);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Decrypts and validates MFA state. Returns null if invalid, tampered, or expired.
    /// </summary>
    public MfaState? Unprotect(string protectedState, TimeSpan? maxAge = null)
    {
        if (string.IsNullOrEmpty(protectedState))
            return null;

        try
        {
            var encrypted = Convert.FromBase64String(protectedState);
            var json = _protector.Unprotect(encrypted);
            var state = JsonSerializer.Deserialize<MfaState>(json);

            if (state is null || state.UserId <= 0)
            {
                _logger?.LogWarning(
                    "MfaStateProtector: decrypted state was null or had invalid UserId.");
                return null;
            }

            var age = _timeProvider.GetUtcNow() - (state.IssuedAt ?? DateTimeOffset.MinValue);
            if (age > (maxAge ?? DefaultMaxAge))
            {
                _logger?.LogDebug(
                    "MfaStateProtector: state expired (age={AgeSeconds}s, max={MaxSeconds}s).",
                    age.TotalSeconds, (maxAge ?? DefaultMaxAge).TotalSeconds);
                return null;
            }

            return state;
        }
        catch (Exception ex)
        {
            // Tampering or DataProtection key rotation. Public contract preserved (null).
            _logger?.LogWarning(ex,
                "MfaStateProtector: failed to decrypt MFA state (length={Length}).",
                protectedState.Length);
            return null;
        }
    }

    /// <inheritdoc />
    string[]? IMfaStateInspector.TryGetMethods(string? protectedState)
    {
        if (string.IsNullOrEmpty(protectedState))
            return null;
        var state = Unprotect(protectedState);
        return state?.Methods;
    }
}
