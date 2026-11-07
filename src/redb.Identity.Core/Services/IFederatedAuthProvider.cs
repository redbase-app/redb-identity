namespace redb.Identity.Core.Services;

/// <summary>
/// SPI for redirect-based federated authentication (OIDC, SAML, etc.).
/// Unlike <see cref="IExternalUserProvider"/> (password-based, synchronous),
/// federation uses a two-step redirect flow: challenge → callback.
/// </summary>
public interface IFederatedAuthProvider
{
    /// <summary>Provider ID used as key in ExternalIdentities dict. E.g. "google", "azure-ad".</summary>
    string ProviderId { get; }

    /// <summary>Display name for login page button.</summary>
    string DisplayName { get; }

    /// <summary>Priority for ordering on the login page. Lower = shown first.</summary>
    int Priority { get; }

    /// <summary>Build authorization redirect URI with state, nonce, PKCE.</summary>
    Task<FederationChallenge> CreateChallengeAsync(string callbackUrl, string returnUrl, CancellationToken ct = default);

    /// <summary>Handle callback: exchange code → validate tokens → return identity.</summary>
    Task<ExternalAuthResult> HandleCallbackAsync(
        string code, string callbackUrl, string? codeVerifier = null, string? nonce = null,
        CancellationToken ct = default);
}

/// <summary>
/// Result of <see cref="IFederatedAuthProvider.CreateChallengeAsync"/>:
/// contains the redirect URI and state that must be round-tripped.
/// </summary>
public sealed class FederationChallenge
{
    /// <summary>Full URI to external IdP authorization endpoint.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>Opaque state for CSRF protection (round-tripped via query param).</summary>
    public required string State { get; init; }

    /// <summary>Nonce for id_token replay protection.</summary>
    public string? Nonce { get; init; }

    /// <summary>PKCE code_verifier (S256). Must be stored server-side for token exchange.</summary>
    public string? CodeVerifier { get; init; }
}
