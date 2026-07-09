using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Sessions;

/// <summary>
/// Response of <c>GET /api/internal/revoked-sids/since?cursor=...</c>.
/// <para>
/// Polling Relying Parties (RPs) call this periodically to refresh their local blacklist.
/// On first call cursor is omitted — server returns a baseline starting from
/// <c>now - retention</c>. Subsequent calls use <see cref="NextCursor"/> from previous response.
/// </para>
/// </summary>
public sealed class RevokedSidsSinceResponse
{
    /// <summary>Entries strictly newer than the supplied cursor, ordered by <c>RevokedAt</c> ascending.</summary>
    [JsonPropertyName("entries")]
    public List<RevokedSidEntry> Entries { get; set; } = new();

    /// <summary>
    /// Cursor to pass on the next polling call. Equals the server-side timestamp of the most
    /// recent entry in <see cref="Entries"/>, or the request <c>cursor</c> when there were no
    /// new entries (so the next poll keeps the same window).
    /// </summary>
    [JsonPropertyName("nextCursor")]
    public DateTimeOffset NextCursor { get; set; }

    /// <summary>Server time at the moment this response was assembled (for clock-skew diagnostics).</summary>
    [JsonPropertyName("serverTime")]
    public DateTimeOffset ServerTime { get; set; }
}
