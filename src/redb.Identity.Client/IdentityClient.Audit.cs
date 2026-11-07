using System.Globalization;
using redb.Identity.Contracts.Audit;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>Query the audit log with the given filters.</summary>
    Task<AuditQueryResponse> QueryAuditAsync(AuditQueryRequest filter, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string AuditBase = "/api/v1/identity/audit";

    public async Task<AuditQueryResponse> QueryAuditAsync(AuditQueryRequest filter, CancellationToken ct = default)
    {
        var qs = BuildAuditQuery(filter);
        using var resp = await _http.GetAsync($"{AuditBase}{qs}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<AuditQueryResponse>(ct).ConfigureAwait(false);
    }

    private static string BuildAuditQuery(AuditQueryRequest f)
    {
        var parts = new List<string> { $"offset={f.Offset}", $"count={f.Count}" };
        if (!string.IsNullOrEmpty(f.EventType)) parts.Add($"eventType={Uri.EscapeDataString(f.EventType)}");
        if (!string.IsNullOrEmpty(f.Category)) parts.Add($"category={Uri.EscapeDataString(f.Category)}");
        if (!string.IsNullOrEmpty(f.UserId)) parts.Add($"userId={Uri.EscapeDataString(f.UserId)}");
        if (!string.IsNullOrEmpty(f.Login)) parts.Add($"login={Uri.EscapeDataString(f.Login)}");
        if (!string.IsNullOrEmpty(f.ClientId)) parts.Add($"clientId={Uri.EscapeDataString(f.ClientId)}");
        if (f.From is { } from) parts.Add($"from={Uri.EscapeDataString(from.ToString("O", CultureInfo.InvariantCulture))}");
        if (f.To is { } to) parts.Add($"to={Uri.EscapeDataString(to.ToString("O", CultureInfo.InvariantCulture))}");
        return "?" + string.Join("&", parts);
    }
}
