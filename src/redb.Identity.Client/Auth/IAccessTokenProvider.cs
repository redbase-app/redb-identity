namespace redb.Identity.Client.Auth;

/// <summary>
/// Resolves a bearer access token for outgoing Identity API calls.
/// Implementations:
///   - <c>HttpContextAccessTokenProvider</c> (in redb.Identity.Web) — reads from cookie session
///   - <see cref="ClientCredentialsAccessTokenProvider"/> — for CLI / server-to-server
/// </summary>
public interface IAccessTokenProvider
{
    Task<string?> GetAccessTokenAsync(CancellationToken ct = default);
}
