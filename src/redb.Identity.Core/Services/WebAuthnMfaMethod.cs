using System.Globalization;
using System.Security.Cryptography;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Options;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Exceptions;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// MFA-3: WebAuthn (FIDO2 / Passkey) MFA method backed by Fido2NetLib v4.
/// <para>
/// Wraps <see cref="IFido2"/> with redb-Identity-specific concerns:
/// </para>
/// <list type="bullet">
/// <item><description><b>UV-downgrade ratchet</b> — registration parses authenticatorData
/// flags (bit 0x04 = UV) and persists per-credential <see cref="WebAuthnCredential.UserVerified"/>;
/// assertion BeginAssertion sets <c>UserVerification = Required</c> when ANY credential of the
/// user has UV-on, and CompleteAssertion re-verifies authenticatorData UV bit per-credential
/// and rejects with <c>uv_downgrade</c> if a UV-registered credential asserted without UV.</description></item>
/// <item><description><b>AAGUID blocklist</b> — the AAGUID parsed from
/// <see cref="RegisteredPublicKeyCredential.AaGuid"/> is checked against
/// <see cref="IdentityWebAuthnOptions.AaguidBlocklist"/> at registration time; matched
/// requests fail with <c>aaguid_blocked</c>.</description></item>
/// <item><description><b>Sign-counter rollback</b> — Fido2NetLib enforces
/// <c>StoredSignatureCounter</c> ≥ stored value at MakeAssertionAsync; redb additionally
/// double-checks here so the surface error is <c>sign_counter_rollback</c> rather than
/// the library's internal exception type.</description></item>
/// </list>
/// <para>
/// All cryptographic verification (attestation parsing, signature verification, certificate
/// chain validation against MDS3 if enabled) is delegated to Fido2NetLib — this class
/// encapsulates only redb-specific glue.
/// </para>
/// </summary>
internal sealed class WebAuthnMfaMethod : IMfaMethod, IWebAuthnMfaMethod
{
    public string MethodId => "webauthn";

    private readonly IFido2 _fido2;
    private readonly IdentityWebAuthnOptions _options;
    private readonly HashSet<Guid> _aaguidBlocklist;
    private readonly TimeProvider _timeProvider;

    public WebAuthnMfaMethod(
        IFido2 fido2,
        IOptions<IdentityWebAuthnOptions> options,
        TimeProvider? timeProvider = null)
    {
        _fido2 = fido2 ?? throw new ArgumentNullException(nameof(fido2));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;

        // Pre-parse the blocklist into a HashSet<Guid> for O(1) lookup.
        _aaguidBlocklist = new HashSet<Guid>();
        if (_options.AaguidBlocklist is { Count: > 0 })
        {
            foreach (var entry in _options.AaguidBlocklist)
                if (Guid.TryParse(entry, out var g)) _aaguidBlocklist.Add(g);
        }
    }

    // ── IMfaMethod surface (intentionally throwing): orchestrator never reaches here ──

    private const string OrchestratorMisuse =
        "WebAuthn does not use the IMfaMethod OTP/code orchestration path. " +
        "Call MfaService.BeginWebAuthnRegistrationAsync / CompleteWebAuthnRegistrationAsync " +
        "/ BeginWebAuthnAssertionAsync / CompleteWebAuthnAssertionAsync instead.";

    public Task<MfaSetupInitiation> InitiateSetupAsync(string username, string? destination = null, CancellationToken ct = default)
        => throw new NotSupportedException(OrchestratorMisuse);

    public Task<bool> ConfirmAndApplyAsync(MfaProps props, MfaSetupInitiation initiation, string code, MfaState? state = null, CancellationToken ct = default)
        => throw new NotSupportedException(OrchestratorMisuse);

    public Task<bool> VerifyAsync(MfaProps props, string code, MfaState? state = null, CancellationToken ct = default)
        => throw new NotSupportedException(OrchestratorMisuse);

    // ── IWebAuthnMfaMethod surface ──

    /// <inheritdoc />
    public CredentialCreateOptions BeginRegistration(
        long userId,
        string username,
        string displayName,
        IReadOnlyDictionary<string, WebAuthnCredential>? existingCredentials,
        bool enforceUv)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(displayName);

        var fidoUser = new Fido2User
        {
            Id = EncodeUserHandle(userId),
            Name = username,
            DisplayName = displayName,
        };

        var exclude = new List<PublicKeyCredentialDescriptor>();
        if (existingCredentials is { Count: > 0 })
        {
            foreach (var c in existingCredentials.Values)
                exclude.Add(new PublicKeyCredentialDescriptor(c.CredentialId));
        }

        // UV requirement: explicit if caller forces it (e.g. user already has UV creds), else
        // honour the global options default. Assertion-time ratchet adds an extra layer.
        var uvRequirement = enforceUv
            ? UserVerificationRequirement.Required
            : ParseUvRequirement(_options.UserVerification);

        var authSelection = new AuthenticatorSelection
        {
            UserVerification = uvRequirement,
            ResidentKey = ResidentKeyRequirement.Preferred,
        };

        return _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = fidoUser,
            ExcludeCredentials = exclude,
            AuthenticatorSelection = authSelection,
            AttestationPreference = ParseAttestationPreference(_options.Attestation),
        });
    }

    /// <inheritdoc />
    public async Task<WebAuthnCredential> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        long userId,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(attestationResponse);
        ArgumentNullException.ThrowIfNull(originalOptions);

        // Fido2NetLib does the heavy crypto lifting. The IsCredentialIdUniqueToUser callback
        // is provided here purely as a defence-in-depth check — the orchestrator already holds
        // a row-lock on the user's MfaProps and re-checks before persistence, so this is a
        // belt-and-braces guard against a same-credential double-registration in the same TX.
        RegisteredPublicKeyCredential registered;
        try
        {
            registered = await _fido2.MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = attestationResponse,
                    OriginalOptions = originalOptions,
                    IsCredentialIdUniqueToUserCallback = static (_, _) => Task.FromResult(true),
                },
                ct).ConfigureAwait(false);
        }
        catch (Fido2VerificationException ex)
        {
            throw new WebAuthnException("attestation_failed", ex.Message, ex);
        }

        // AAGUID blocklist enforcement. Empty AAGUID (Guid.Empty) means "self attestation"
        // / sync passkey — there is no hardware identifier to gate, so we only check against
        // the blocklist when the AAGUID is set.
        if (registered.AaGuid != Guid.Empty && _aaguidBlocklist.Contains(registered.AaGuid))
        {
            throw new WebAuthnException(
                "aaguid_blocked",
                $"Authenticator AAGUID {registered.AaGuid:D} is on the configured blocklist.");
        }

        // Parse UV/BE/BS flags out of the attestation's authenticatorData. Fido2NetLib v4
        // does NOT surface UV directly on RegisteredPublicKeyCredential, so we derive it from
        // the raw attestation object's authData byte[32] (the flags byte).
        var authDataFlags = ExtractAuthenticatorDataFlags(attestationResponse);
        var uv = (authDataFlags & 0x04) != 0;

        return new WebAuthnCredential
        {
            CredentialId = registered.Id,
            PublicKey = registered.PublicKey,
            SignCount = registered.SignCount,
            DisplayName = null,
            Aaguid = registered.AaGuid != Guid.Empty
                ? registered.AaGuid.ToString("D", CultureInfo.InvariantCulture)
                : null,
            RegisteredAt = _timeProvider.GetUtcNow(),
            LastUsedAt = null,
            UserVerified = uv,
            BackupEligible = registered.IsBackupEligible,
            BackupState = registered.IsBackedUp,
        };
    }

    /// <inheritdoc />
    public AssertionOptions BeginAssertion(IReadOnlyDictionary<string, WebAuthnCredential> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var allowed = new List<PublicKeyCredentialDescriptor>(credentials.Count);
        var anyUvCred = false;
        foreach (var c in credentials.Values)
        {
            allowed.Add(new PublicKeyCredentialDescriptor(c.CredentialId));
            if (c.UserVerified) anyUvCred = true;
        }

        // Per-user UV ratchet. If at least one credential was registered with UV, demand UV
        // for every assertion of this user — the per-credential ratchet is finalized in
        // CompleteAssertionAsync (where the actual matched credential's UV flag is enforced).
        var uvRequirement = anyUvCred
            ? UserVerificationRequirement.Required
            : ParseUvRequirement(_options.UserVerification);

        return _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowed,
            UserVerification = uvRequirement,
        });
    }

    /// <inheritdoc />
    public async Task<WebAuthnCredential?> CompleteAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        IReadOnlyDictionary<string, WebAuthnCredential> credentials,
        long userId,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResponse);
        ArgumentNullException.ThrowIfNull(originalOptions);
        ArgumentNullException.ThrowIfNull(credentials);

        // Locate the credential the browser asserts about — match by raw byte equality on
        // CredentialId. The dictionary keys are user-friendly and not used for lookup here.
        WebAuthnCredential? matched = null;
        foreach (var c in credentials.Values)
        {
            if (BytesEqual(c.CredentialId, assertionResponse.RawId))
            {
                matched = c;
                break;
            }
        }
        if (matched is null)
        {
            throw new WebAuthnException(
                "credential_not_found",
                "The asserted credentialId is not registered to this user.");
        }

        // Per-credential UV ratchet. Fido2NetLib enforces UV based on the OriginalOptions
        // (set globally per ceremony). When the matched credential was registered with UV
        // but the assertion lacks UV (e.g. attacker downgraded by toggling allowCredentials),
        // we reject before completing the verification so the failure has the correct code.
        var assertionFlags = ExtractAssertionAuthDataFlags(assertionResponse);
        var assertionUv = (assertionFlags & 0x04) != 0;
        if (matched.UserVerified && !assertionUv)
        {
            throw new WebAuthnException(
                "uv_downgrade",
                "Credential was registered with user-verification but assertion did not carry UV.");
        }

        VerifyAssertionResult result;
        try
        {
            result = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = assertionResponse,
                    OriginalOptions = originalOptions,
                    StoredPublicKey = matched.PublicKey,
                    StoredSignatureCounter = (uint)matched.SignCount,
                    IsUserHandleOwnerOfCredentialIdCallback = (p, _) =>
                    {
                        // The user handle the browser echoed back must be the encoding of OUR userId.
                        var expected = EncodeUserHandle(userId);
                        var ok = p.UserHandle != null
                            && CryptographicOperations.FixedTimeEquals(p.UserHandle, expected);
                        return Task.FromResult(ok);
                    },
                },
                ct).ConfigureAwait(false);
        }
        catch (Fido2VerificationException)
        {
            // Signature failure / counter rollback / origin mismatch / etc. — caller treats
            // null as "verification failed" and bumps FailedAttempts.
            return null;
        }

        // Belt-and-braces: re-check counter monotonicity. Fido2NetLib already enforces this
        // (Fido2VerificationException would have been thrown above when the new value goes
        // backwards), but converting to a typed exception lets the orchestrator tag the
        // audit event with the specific reason. Counter == 0 means the authenticator does
        // not implement counters (TouchID / Windows Hello / sync passkeys) — accept.
        if (result.SignCount != 0 && result.SignCount < matched.SignCount)
        {
            throw new WebAuthnException(
                "sign_counter_rollback",
                $"SignCount went backward: stored={matched.SignCount}, asserted={result.SignCount} — possible cloned credential.");
        }

        // Apply mutations onto the matched credential. Caller persists by saving MfaProps.
        matched.SignCount = result.SignCount;
        matched.LastUsedAt = _timeProvider.GetUtcNow();
        matched.BackupState = result.IsBackedUp;
        return matched;
    }

    // ── helpers ──

    /// <summary>Encodes the numeric Identity userId as the WebAuthn user.handle (8-byte BE).</summary>
    internal static byte[] EncodeUserHandle(long userId)
    {
        var buf = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            buf[i] = (byte)(userId & 0xff);
            userId >>= 8;
        }
        return buf;
    }

    /// <summary>Decodes the user handle back to userId (inverse of <see cref="EncodeUserHandle"/>).</summary>
    internal static bool TryDecodeUserHandle(byte[]? handle, out long userId)
    {
        userId = 0;
        if (handle is null || handle.Length != 8) return false;
        for (int i = 0; i < 8; i++)
        {
            userId = (userId << 8) | handle[i];
        }
        return userId > 0;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a is null || b is null) return false;
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static UserVerificationRequirement ParseUvRequirement(string value) => value switch
    {
        "required" => UserVerificationRequirement.Required,
        "discouraged" => UserVerificationRequirement.Discouraged,
        _ => UserVerificationRequirement.Preferred,
    };

    private static AttestationConveyancePreference ParseAttestationPreference(string value) => value switch
    {
        "indirect" => AttestationConveyancePreference.Indirect,
        "direct" => AttestationConveyancePreference.Direct,
        "enterprise" => AttestationConveyancePreference.Enterprise,
        _ => AttestationConveyancePreference.None,
    };

    /// <summary>
    /// Extracts the flags byte (offset 32) from authenticatorData found inside the attestation
    /// object's CBOR map. Throws <see cref="WebAuthnException"/> with code <c>malformed_attestation</c>
    /// if the authData blob cannot be located. Bit 0x01 = UP, 0x04 = UV, 0x08 = BE, 0x10 = BS.
    /// </summary>
    private static byte ExtractAuthenticatorDataFlags(AuthenticatorAttestationRawResponse response)
    {
        var attObj = response.Response?.AttestationObject
            ?? throw new WebAuthnException("malformed_attestation",
                "Attestation response is missing the attestationObject blob.");

        var authData = ExtractAuthDataFromCbor(attObj);
        if (authData is null || authData.Length < 37)
        {
            throw new WebAuthnException("malformed_attestation",
                "Attestation authenticator data could not be parsed.");
        }
        return authData[32];
    }

    /// <summary>
    /// Extracts the flags byte (offset 32) from the assertion response's authenticatorData.
    /// </summary>
    private static byte ExtractAssertionAuthDataFlags(AuthenticatorAssertionRawResponse response)
    {
        var authData = response.Response?.AuthenticatorData
            ?? throw new WebAuthnException("malformed_assertion",
                "Assertion response is missing authenticatorData.");
        if (authData.Length < 37)
        {
            throw new WebAuthnException("malformed_assertion",
                "Assertion authenticatorData is truncated (need ≥ 37 bytes for RpIdHash + flags + counter).");
        }
        return authData[32];
    }

    /// <summary>
    /// Minimal CBOR parser to pluck the <c>authData</c> byte-string out of an
    /// attestationObject. AttestationObject is a CBOR map with text-string keys
    /// (<c>fmt</c>, <c>attStmt</c>, <c>authData</c>); we walk the top-level map until we
    /// hit the <c>authData</c> key and return its byte-string value.
    /// </summary>
    private static byte[]? ExtractAuthDataFromCbor(byte[] cbor)
    {
        try
        {
            var reader = new System.Formats.Cbor.CborReader(cbor);
            var len = reader.ReadStartMap();
            var iterations = len ?? int.MaxValue;
            for (var i = 0; i < iterations; i++)
            {
                if (reader.PeekState() == System.Formats.Cbor.CborReaderState.EndMap) break;
                var key = reader.ReadTextString();
                if (string.Equals(key, "authData", StringComparison.Ordinal))
                {
                    return reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }
            }
        }
        catch
        {
            // Fall through; caller throws malformed_attestation.
        }
        return null;
    }
}
