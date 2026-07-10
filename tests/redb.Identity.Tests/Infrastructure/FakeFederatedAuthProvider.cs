using redb.Identity.Core.Services;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// A configurable fake federated auth provider for integration testing.
/// Allows tests to control challenge and callback behavior without a real OIDC server.
/// </summary>
public sealed class FakeFederatedAuthProvider : IFederatedAuthProvider
{
    public string ProviderId { get; set; } = "fake-oidc";
    public string DisplayName { get; set; } = "Fake OIDC Provider";
    public int Priority { get; set; } = 10;

    /// <summary>
    /// Custom challenge handler. If null, returns a default challenge.
    /// </summary>
    public Func<string, string, FederationChallenge>? ChallengeHandler { get; set; }

    /// <summary>
    /// Custom callback handler. If null, returns success with code-based sub.
    /// </summary>
    public Func<string, string?, string?, ExternalAuthResult>? CallbackHandler { get; set; }

    public Task<FederationChallenge> CreateChallengeAsync(
        string callbackUrl, string returnUrl, CancellationToken ct = default)
    {
        if (ChallengeHandler is not null)
            return Task.FromResult(ChallengeHandler(callbackUrl, returnUrl));

        var state = Guid.NewGuid().ToString("N");
        return Task.FromResult(new FederationChallenge
        {
            RedirectUri = $"https://fake-oidc.test/authorize?state={Uri.EscapeDataString(state)}&redirect_uri={Uri.EscapeDataString(callbackUrl)}",
            State = state,
            Nonce = Guid.NewGuid().ToString("N"),
            CodeVerifier = Guid.NewGuid().ToString("N")
        });
    }

    public Task<ExternalAuthResult> HandleCallbackAsync(
        string code, string callbackUrl, string? codeVerifier = null, string? nonce = null,
        CancellationToken ct = default)
    {
        if (CallbackHandler is not null)
            return Task.FromResult(CallbackHandler(code, codeVerifier, nonce));

        return Task.FromResult(ExternalAuthResult.Success(
            externalId: $"fake-sub-{code}",
            displayName: $"FakeUser {code}",
            email: $"fake-{code}@test.com",
            givenName: "Fake",
            familyName: "User"));
    }
}
