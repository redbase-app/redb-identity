using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// MFA-3: typed SPI for the WebAuthn (FIDO2 / Passkey) flow. Standalone — does NOT
/// inherit <see cref="IMfaMethod"/> because the WebAuthn shape (typed ceremony objects,
/// dual begin/complete, allow-credentials filtering) is fundamentally different from the
/// OTP-style <c>InitiateSetup / ConfirmAndApply / Verify(code)</c> contract. Orchestration
/// of WebAuthn lives on dedicated <see cref="MfaService"/> methods rather than the generic
/// <see cref="MfaService.SetupAsync"/> / <see cref="MfaService.VerifyAsync"/> pipeline.
/// <para>
/// All cryptographic verification (attestation parsing, signature verification, sign-counter
/// rollback) is delegated to Fido2NetLib (<c>IFido2</c>). This abstraction sits ONE level above
/// it and adds: per-credential UV-downgrade ratchet (<see cref="WebAuthnCredential.UserVerified"/>),
/// AAGUID blocklist enforcement, anti-replay via <see cref="Mfa.IWebAuthnChallengeStore"/>,
/// fail-fast options validation. <see cref="MfaService"/> owns the surrounding transactions
/// and persists the resulting <see cref="WebAuthnCredential"/> mutations.
/// </para>
/// </summary>
public interface IWebAuthnMfaMethod
{
    /// <summary>
    /// Builds <see cref="CredentialCreateOptions"/> for the browser to invoke
    /// <c>navigator.credentials.create</c>. Generates 32 random challenge bytes; the caller
    /// is expected to encrypt them into the setup-token so the corresponding <c>complete</c>
    /// call can verify byte-equality. <see cref="WebAuthnCredential.UserVerified"/> on any
    /// existing credential of the user is honoured by passing the matching
    /// <c>UserVerification</c> requirement so a downgrade attack at registration time is rejected.
    /// </summary>
    /// <param name="userId">Numeric Identity user id; encoded into <c>user.id</c>.</param>
    /// <param name="username">Login (e.g. e-mail). Shown in the OS authenticator UI.</param>
    /// <param name="displayName">Friendly display name. Shown in the OS authenticator UI.</param>
    /// <param name="existingCredentials">Already-registered credentials for the user — added
    /// to <c>excludeCredentials</c> so a single device cannot register twice.</param>
    /// <param name="enforceUv">If true, requires UV at registration. False → preferred.</param>
    /// <returns>The Fido2 <see cref="CredentialCreateOptions"/> with 32-byte
    /// <c>Challenge</c>; caller persists those bytes in the setup-token.</returns>
    CredentialCreateOptions BeginRegistration(
        long userId,
        string username,
        string displayName,
        IReadOnlyDictionary<string, WebAuthnCredential>? existingCredentials,
        bool enforceUv);

    /// <summary>
    /// Verifies an attestation response against the original options + challenge bytes.
    /// On success returns a fully-formed <see cref="WebAuthnCredential"/> with UV/BE/BS flags
    /// (parsed from authenticatorData) and AAGUID. Throws
    /// <see cref="Exceptions.WebAuthnException"/> with code <c>aaguid_blocked</c> when the
    /// attested AAGUID is in the configured blocklist.
    /// </summary>
    /// <param name="attestationResponse">Raw browser response (deserialized).</param>
    /// <param name="originalOptions">Options that produced the challenge.</param>
    /// <param name="userId">User who initiated the ceremony.</param>
    /// <param name="ct">Cancellation.</param>
    Task<WebAuthnCredential> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        long userId,
        CancellationToken ct = default);

    /// <summary>
    /// Builds <see cref="AssertionOptions"/> for the browser to invoke
    /// <c>navigator.credentials.get</c>. Allow-credentials lists every credential registered
    /// to the user. UV requirement is set to <c>required</c> when ANY existing credential has
    /// <see cref="WebAuthnCredential.UserVerified"/>=true (per-user UV ratchet — rejects a
    /// downgrade attack where the attacker chooses a less-protected credential).
    /// </summary>
    AssertionOptions BeginAssertion(IReadOnlyDictionary<string, WebAuthnCredential> credentials);

    /// <summary>
    /// Verifies an assertion response. Returns the matched credential (mutated in-place
    /// with new <see cref="WebAuthnCredential.SignCount"/>, <see cref="WebAuthnCredential.LastUsedAt"/>
    /// and <see cref="WebAuthnCredential.BackupState"/>) on success. Returns null on signature
    /// failure. Throws <see cref="Exceptions.WebAuthnException"/> with codes:
    /// <list type="bullet">
    ///   <item><description><c>uv_downgrade</c> — credential was registered with UV but assertion has UV=0</description></item>
    ///   <item><description><c>sign_counter_rollback</c> — new SignCount &lt; stored SignCount (CTAP2 §6.1.4)</description></item>
    ///   <item><description><c>credential_not_found</c> — assertion's credentialId not in user's set</description></item>
    /// </list>
    /// </summary>
    Task<WebAuthnCredential?> CompleteAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        IReadOnlyDictionary<string, WebAuthnCredential> credentials,
        long userId,
        CancellationToken ct = default);
}
