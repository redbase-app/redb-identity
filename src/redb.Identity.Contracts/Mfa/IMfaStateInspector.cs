namespace redb.Identity.Contracts.Mfa;

/// <summary>
/// Minimal read-only surface over the encrypted MFA challenge state for transport facades
/// (HTTP, gRPC, …) that need to render UI dependent on which MFA methods the user has
/// configured, without taking a project-reference on Core's full <c>MfaStateProtector</c>
/// + <c>MfaState</c> POCO (which carries 50+ fields including WebAuthn challenges that
/// belong to Core's domain).
/// <para>
/// Implemented by Core (<c>MfaStateProtector</c>) and registered in DI alongside the
/// concrete protector. HTTP UI processors lookup this interface only.
/// </para>
/// </summary>
public interface IMfaStateInspector
{
    /// <summary>
    /// Decrypts the supplied protected MFA-state token and returns the configured MFA
    /// method identifiers (for example <c>"totp"</c>, <c>"sms"</c>, <c>"email"</c>) that
    /// the user can present at the verification step. Returns <c>null</c> when the token
    /// is missing, tampered, expired, or otherwise undecryptable — callers should treat
    /// that as "no methods known" and fall back to a default UI.
    /// </summary>
    /// <param name="protectedState">Base64-encoded DataProtection-protected state token.</param>
    /// <returns>Method identifiers, or <c>null</c> on any failure.</returns>
    string[]? TryGetMethods(string? protectedState);
}
