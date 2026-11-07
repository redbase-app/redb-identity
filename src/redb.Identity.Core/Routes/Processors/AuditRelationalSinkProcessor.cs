using System.Text.Json;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// R1 — replaces <c>AuditEventSinkProcessor</c> (props-based) with a flat
/// relational INSERT into <c>identity_audit_log</c> (DDL ensured by
/// <see cref="Module.IdentityAuditLogTableInitListener"/>).
///
/// <para>
/// Same input contract: reads <c>event_type</c>, <c>event_id</c>,
/// <c>timestamp</c>, <c>details</c> JSON, <c>user_id</c>, <c>login</c>,
/// <c>client_id</c>, <c>ip_address</c>, <c>user_agent</c> off the message
/// headers populated by <see cref="EventDispatchProcessor"/>. Derives the
/// category from <see cref="IdentityAuditEventIds.CategoryOf"/>. Tolerantly
/// extracts <c>login</c> from the JSON <c>details</c> payload when the emitter
/// stamped <c>identity-event-data.Login</c> but not the per-exchange header
/// — same fallback the props sink used to keep per-user audit aligned with
/// emitters that pre-date the explicit <c>login</c> header.
/// </para>
///
/// <para>
/// Failures are swallowed and logged: audit persistence must never kill the
/// originating mutation.
/// </para>
/// </summary>
internal sealed class AuditRelationalSinkProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly ILogger _logger;
    private readonly string? _redbName;

    public AuditRelationalSinkProcessor(IRouteContext context, ILogger logger, string? redbName = null)
    {
        _context = context;
        _logger = logger;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        // EventDispatchProcessor writes the canonical envelope onto Out.Headers
        // (event_id / event_type / user_id / details / ...). Older emitters that
        // bypass the dispatcher leave the same shape on In.Headers — prefer Out
        // when populated, fall back to In to stay compatible with both paths.
        var headers = (exchange.Out?.Headers?.Count > 0)
            ? exchange.Out.Headers
            : exchange.In.Headers;
        var eventType = GetString(headers, "event_type");
        if (string.IsNullOrEmpty(eventType)) return;

        try
        {
            var redb = _context.GetRedbService(_redbName, exchange);

            var eventId = GetGuid(headers, "event_id") ?? Guid.NewGuid();
            var category = IdentityAuditEventIds.CategoryOf(eventType);
            var timestamp = GetDateTimeOffset(headers, "timestamp") ?? DateTimeOffset.UtcNow;
            var detailsJson = GetString(headers, "details");
            var login = GetString(headers, "login") ?? ExtractLoginFromDetailsJson(detailsJson);

            // @p0..@p9 — convert per dialect (Postgres → $1..$10 done by
            // NpgsqlRedbConnection; MSSQL keeps @p0). Positional binding.
            const string sql = """
                INSERT INTO identity_audit_log
                  (event_id, event_type, category, "timestamp", user_id, login, client_id, ip_address, user_agent, details)
                VALUES
                  (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9)
                """;

            // user_id column is BIGINT. Emitters hand us a string (long.ToString())
            // for indexed seeks; parse here. Non-numeric → NULL so federated
            // pre-link events still land instead of crashing the INSERT.
            var userIdRaw = GetString(headers, "user_id");
            object userIdParam = DBNull.Value;
            if (!string.IsNullOrEmpty(userIdRaw))
            {
                if (long.TryParse(userIdRaw, out var uid))
                    userIdParam = uid;
                else
                    _logger.LogWarning(
                        "AuditRelationalSinkProcessor: '{EventType}' carried non-numeric user_id '{UserId}' — storing NULL",
                        eventType, userIdRaw);
            }

            await redb.Context.ExecuteAsync(sql,
                (object?)eventId ?? DBNull.Value,
                eventType,
                (object?)category ?? DBNull.Value,
                timestamp,
                userIdParam,
                (object?)login ?? DBNull.Value,
                (object?)GetString(headers, "client_id") ?? DBNull.Value,
                (object?)GetString(headers, "ip_address") ?? DBNull.Value,
                (object?)GetString(headers, "user_agent") ?? DBNull.Value,
                (object?)detailsJson ?? DBNull.Value
            ).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AuditRelationalSinkProcessor failed to persist {EventType}", eventType);
        }
    }

    // A header value of DBNull.Value (EventDispatchProcessor stamps it for absent
    // client_id/ip_address/user_agent so the same dictionary doubles as SQL bind
    // params) must round-trip back to null here — DBNull.Value.ToString() is "",
    // which would otherwise land an empty string in a column meant to be NULL.
    private static string? GetString(IDictionary<string, object?> headers, string key)
        => headers.TryGetValue(key, out var v) && v is not null and not DBNull ? v.ToString() : null;

    private static Guid? GetGuid(IDictionary<string, object?> headers, string key)
    {
        if (!headers.TryGetValue(key, out var v) || v is null) return null;
        return v switch
        {
            Guid g => g,
            string s => Guid.TryParse(s, out var parsed) ? parsed : null,
            _ => null
        };
    }

    private static DateTimeOffset? GetDateTimeOffset(IDictionary<string, object?> headers, string key)
    {
        if (!headers.TryGetValue(key, out var v) || v is null) return null;
        return v switch
        {
            DateTimeOffset dto => dto,
            DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
            string s => DateTimeOffset.TryParse(s, out var parsed) ? parsed : null,
            _ => null
        };
    }

    private static string? ExtractLoginFromDetailsJson(string? detailsJson)
    {
        if (string.IsNullOrEmpty(detailsJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(detailsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            if (doc.RootElement.TryGetProperty("Login", out var l) && l.ValueKind == JsonValueKind.String)
                return l.GetString();
            if (doc.RootElement.TryGetProperty("login", out var l2) && l2.ValueKind == JsonValueKind.String)
                return l2.GetString();
            return null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Used by <c>AuditQueryProcessor</c> to deserialise the JSON details
    /// column back to a structured dictionary for the API response.
    /// Returns null on any failure so the surrounding row still surfaces in
    /// the audit page.
    /// </summary>
    public static Dictionary<string, object?>? TryDeserializeDetails(string? detailsJson)
    {
        if (string.IsNullOrEmpty(detailsJson)) return null;
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, object?>>(detailsJson);
        }
        catch { return null; }
    }
}
