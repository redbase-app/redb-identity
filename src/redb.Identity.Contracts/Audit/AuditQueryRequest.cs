using redb.Identity.Contracts.Routes;
namespace redb.Identity.Contracts.Audit;

/// <summary>
/// H9 (v1.0 DoD): Audit log query request for <c>GET /api/v1/identity/audit</c>.
/// All filter fields are optional — omitting narrows are logically ANDed.
/// </summary>
public class AuditQueryRequest
{
    /// <summary>Filter by exact event type (see <c>IdentityAuditEventIds</c>). Null = all.</summary>
    public string? EventType { get; set; }

    /// <summary>Filter by semantic category (<c>authentication</c>, <c>admin</c>, ...). Null = all.</summary>
    public string? Category { get; set; }

    /// <summary>Filter by user identifier. Null = all.</summary>
    public string? UserId { get; set; }

    /// <summary>
    /// Filter by user login. OR'd against <see cref="UserId"/> on the server
    /// — useful for per-user audit timelines where the emitting processor
    /// stamped Login on the event payload but not the internal user_id
    /// header. Null = all.
    /// </summary>
    public string? Login { get; set; }

    /// <summary>Filter by OAuth client identifier. Null = all.</summary>
    public string? ClientId { get; set; }

    /// <summary>Inclusive lower bound on event timestamp.</summary>
    public DateTimeOffset? From { get; set; }

    /// <summary>Exclusive upper bound on event timestamp.</summary>
    public DateTimeOffset? To { get; set; }

    /// <summary>Page offset (rows to skip). Must be &gt;= 0.</summary>
    public int Offset { get; set; }

    /// <summary>Page size. Clamped to <c>[1..500]</c> server-side.</summary>
    public int Count { get; set; } = 50;
}

/// <summary>A single audit row in <see cref="AuditQueryResponse.Items"/>.</summary>
public class AuditQueryItem
{
    public string EventId { get; set; } = "";
    public string EventType { get; set; } = "";
    public string Category { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public string? UserId { get; set; }
    public string? ClientId { get; set; }
    public string? Login { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public Dictionary<string, object?>? Details { get; set; }
}

/// <summary>Paged result of <see cref="AuditQueryRequest"/>.</summary>
public class AuditQueryResponse
{
    public int Total { get; set; }
    public int Offset { get; set; }
    public int Count { get; set; }
    public List<AuditQueryItem> Items { get; set; } = [];
}
