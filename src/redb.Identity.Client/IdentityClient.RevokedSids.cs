using System.Text.Json;
using redb.Identity.Contracts.Sessions;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>
    /// W6-0: Publish a backchannel revocation entry. At least one of <paramref name="sid"/>
    /// / <paramref name="sub"/> MUST be supplied.
    /// </summary>
    /// <param name="sid">OIDC <c>sid</c> claim of the revoked session, or null.</param>
    /// <param name="sub">OIDC <c>sub</c> claim. Set without <paramref name="sid"/> for a
    ///     "revoke all sessions of subject" entry.</param>
    /// <param name="clientId">Optional client_id scope. Null = applies to all clients.</param>
    /// <param name="expiresAt">When the entry expires. Server clamps to the configured
    ///     <c>RevokedSidsMaxRetention</c> upper bound.</param>
    Task<RevokedSidEntry> AddRevokedSidAsync(
        string? sid, string? sub, string? clientId,
        DateTimeOffset? expiresAt = null,
        CancellationToken ct = default);

    /// <summary>
    /// W6-0: Incremental poll of the backchannel revoked-sids list. Pass
    /// <see cref="RevokedSidsSinceResponse.NextCursor"/> from the previous response on
    /// subsequent calls; omit on the first call to receive a baseline window.
    /// </summary>
    Task<RevokedSidsSinceResponse> GetRevokedSidsSinceAsync(
        DateTimeOffset? cursor = null,
        CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string RevokedSidsBase = "/api/v1/identity/revoked-sids";

    public async Task<RevokedSidEntry> AddRevokedSidAsync(
        string? sid, string? sub, string? clientId,
        DateTimeOffset? expiresAt = null,
        CancellationToken ct = default)
    {
        var request = new RevokedSidsAddRequest
        {
            Sid = sid,
            Sub = sub,
            ClientId = clientId,
            ExpiresAt = expiresAt
        };
        using var resp = await _http.PostAsJsonAsync(RevokedSidsBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<RevokedSidEntry>(ct).ConfigureAwait(false);
    }

    public async Task<RevokedSidsSinceResponse> GetRevokedSidsSinceAsync(
        DateTimeOffset? cursor = null,
        CancellationToken ct = default)
    {
        var url = cursor.HasValue
            ? $"{RevokedSidsBase}/since?cursor={Uri.EscapeDataString(cursor.Value.ToString("O"))}"
            : $"{RevokedSidsBase}/since";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<RevokedSidsSinceResponse>(ct).ConfigureAwait(false);
    }
}
