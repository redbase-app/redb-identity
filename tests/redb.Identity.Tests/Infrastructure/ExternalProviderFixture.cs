using redb.Identity.Core.Services;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// A configurable fake external user provider for integration testing.
/// Instantiated per-test (not via DI) and passed directly to LoginService constructor.
/// </summary>
public sealed class FakeExternalUserProvider : IExternalUserProvider
{
    public string ProviderName { get; set; } = "fake-test";
    public int Priority { get; set; } = 10;

    /// <summary>
    /// Map of username → result handler. Return null to skip, non-null to claim the user.
    /// </summary>
    public Dictionary<string, Func<string, ExternalAuthResult?>> UserHandlers { get; } = new();

    public Task<ExternalAuthResult?> AuthenticateAsync(string username, string password, CancellationToken ct = default)
    {
        if (!UserHandlers.TryGetValue(username, out var handler))
            return Task.FromResult<ExternalAuthResult?>(null);

        return Task.FromResult(handler(password));
    }
}
