namespace redb.Identity.Contracts.Mfa;

/// <summary>
/// Phase 9d cross-context request DTO for <c>direct-vm://identity-mfa-methods-from-state</c>.
/// HTTP UI renders the verification page; it must show which MFA methods (TOTP / SMS /
/// email) the user has configured. The configured-method list is embedded in the
/// encrypted <c>mfa_state</c> token issued by <c>LoginProcessor</c>; Core decrypts it
/// here so the HTTP transport never needs the DataProtection key-ring at compile time
/// (only at runtime for cookies, via the shared <c>redb.Identity.DataProtection</c> ring).
/// </summary>
public sealed class MfaMethodsFromStateRequest
{
    /// <summary>Encrypted <c>mfa_state</c> token (base64). Null/empty returns empty methods.</summary>
    public string? MfaState { get; set; }
}

/// <summary>
/// Reply DTO for <c>direct-vm://identity-mfa-methods-from-state</c>.
/// </summary>
public sealed class MfaMethodsFromStateResponse
{
    /// <summary>True when the token decrypted successfully and is not expired.</summary>
    public bool Success { get; set; }
    /// <summary>Configured method identifiers (subset of <c>"totp"</c>, <c>"sms"</c>, <c>"email"</c>).</summary>
    public string[] Methods { get; set; } = Array.Empty<string>();
}
