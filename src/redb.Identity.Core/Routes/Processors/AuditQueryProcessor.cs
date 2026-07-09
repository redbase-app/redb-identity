using System.Text;
using System.Text.Json.Serialization;
using redb.Core;
using redb.Identity.Contracts.Audit;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// R1 — admin audit log query. Reads from the flat <c>identity_audit_log</c>
/// relational table (created by
/// <see cref="Module.IdentityAuditLogTableInitListener"/>) via redb's raw-SQL
/// API. Replaces the props-based query that used to scan <c>AuditEventProps</c>
/// rows in <c>_objects</c> + <c>_values</c>.
///
/// <para>
/// Why raw SQL instead of <c>redb.Query&lt;T&gt;</c>: audit is an append-only
/// flat shape with no per-event prop variability; a direct index seek on
/// <c>(login, timestamp DESC)</c> or <c>(user_id, timestamp DESC)</c> wins
/// trivially over EAV. We still go through <c>IRedbService.Context</c> so
/// connection / dialect / transaction management stays in redb's hands.
/// </para>
///
/// <para>
/// Filter precedence matches the prior implementation:
/// <list type="bullet">
///   <item>UserId AND Login both set → OR (catch emitters that stamped only one)</item>
///   <item>Either alone → that single column</item>
///   <item>EventType / Category / ClientId / From / To → AND-composed</item>
/// </list>
/// </para>
/// </summary>
internal sealed class AuditQueryProcessor : IProcessor
{
    private const int MaxPageSize = 500;

    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public AuditQueryProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as AuditQueryRequest ?? new AuditQueryRequest();

        var offset = Math.Max(0, request.Offset);
        var count = Math.Clamp(request.Count, 1, MaxPageSize);

        var redb = _context.GetRedbService(_redbName, exchange);

        // Build WHERE incrementally with positional @p0..@pN parameters. Same
        // syntax NpgsqlRedbConnection / MSSQL adapters both accept; Postgres
        // rewrites to $N internally.
        var where = new StringBuilder();
        var args = new List<object>();

        void AddClause(string clause, object value)
        {
            where.Append(where.Length == 0 ? " WHERE " : " AND ");
            where.Append(clause.Replace("{P}", "@p" + args.Count));
            args.Add(value);
        }

        if (!string.IsNullOrEmpty(request.EventType))
            AddClause("event_type = {P}", request.EventType);

        if (!string.IsNullOrEmpty(request.Category))
            AddClause("category = {P}", request.Category);

        // user_id column is BIGINT — parse the HTTP query string once. If it
        // fails to parse, drop the userId filter (treat as not-supplied) so
        // the query still returns whatever the login filter matches.
        long? userIdNum = null;
        if (!string.IsNullOrEmpty(request.UserId) && long.TryParse(request.UserId, out var parsedUid))
            userIdNum = parsedUid;

        var hasUserId = userIdNum.HasValue;
        var hasLogin = !string.IsNullOrEmpty(request.Login);
        if (hasUserId && hasLogin)
        {
            // Two-parameter OR — both placeholders consume the same args slot
            // pair so the next clause builder picks up from the right index.
            where.Append(where.Length == 0 ? " WHERE " : " AND ");
            where.Append("(user_id = @p").Append(args.Count).Append(" OR login = @p").Append(args.Count + 1).Append(")");
            args.Add(userIdNum!.Value);
            args.Add(request.Login!);
        }
        else if (hasUserId)
        {
            AddClause("user_id = {P}", userIdNum!.Value);
        }
        else if (hasLogin)
        {
            AddClause("login = {P}", request.Login!);
        }

        if (!string.IsNullOrEmpty(request.ClientId))
            AddClause("client_id = {P}", request.ClientId);

        if (request.From is { } fromTs)
            AddClause("timestamp >= {P}", fromTs);

        if (request.To is { } toTs)
            AddClause("timestamp < {P}", toTs);

        var whereSql = where.ToString();

        // Total — single scalar.
        var countSql = "SELECT COUNT(*) FROM identity_audit_log" + whereSql;
        var total = await redb.Context.ExecuteScalarAsync<long>(countSql, args.ToArray()).ConfigureAwait(false);

        // Page rows — same WHERE + ORDER + pagination. Append the pagination
        // params after the filter args so positional indices line up.
        //
        // Pagination dialect varies per provider:
        //   * PostgreSQL / SQLite — "LIMIT N OFFSET M"  (rejected by MSSQL).
        //   * SQL Server          — "OFFSET M ROWS FETCH NEXT N ROWS ONLY".
        //
        // The audit query goes through redb.Context.QueryAsync (raw SQL), so it
        // can't ride the IDialect.FormatPagination path the structured query
        // pipeline uses. We sniff the connection type at the callsite to pick
        // the right tail clause — cheap, no IRedbConnection API change.
        var connTypeName = redb.Context.Db.GetType().Name;
        var isMsSql = connTypeName.Contains("Sql", StringComparison.OrdinalIgnoreCase)
                      && !connTypeName.Contains("Sqlite", StringComparison.OrdinalIgnoreCase)
                      && !connTypeName.Contains("Npgsql", StringComparison.OrdinalIgnoreCase);
        var paginationSql = isMsSql
            ? $"OFFSET @p{args.Count + 1} ROWS FETCH NEXT @p{args.Count} ROWS ONLY"   // MSSQL: offset first, then count
            : $"LIMIT @p{args.Count} OFFSET @p{args.Count + 1}";                       // PG / SQLite
        var rowsSql = $"""
            SELECT event_id, event_type, category, "timestamp", user_id, login,
                   client_id, ip_address, user_agent, details
              FROM identity_audit_log
              {whereSql}
             ORDER BY "timestamp" DESC
             {paginationSql}
            """;
        args.Add(count);
        args.Add(offset);

        var rows = await redb.Context.QueryAsync<AuditRow>(rowsSql, args.ToArray()).ConfigureAwait(false);

        var items = rows.Select(r => new AuditQueryItem
        {
            EventId = NormalizeEventId(r.EventId),
            EventType = r.EventType ?? "",
            Category = r.Category ?? "",
            Timestamp = r.Timestamp,
            UserId = r.UserId?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Login = r.Login,
            ClientId = r.ClientId,
            IpAddress = r.IpAddress,
            UserAgent = r.UserAgent,
            Details = AuditRelationalSinkProcessor.TryDeserializeDetails(r.Details)
        }).ToList();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new AuditQueryResponse
        {
            Total = (int)Math.Min(total, int.MaxValue),
            Offset = offset,
            Count = count,
            Items = items
        };
    }

    /// <summary>
    /// Row DTO for <c>redb.Context.QueryAsync&lt;T&gt;</c>. Column → property
    /// mapping uses <c>JsonPropertyName</c> (snake_case → PascalCase) so the
    /// names mirror the DDL exactly.
    /// <para>
    /// <c>EventId</c> is typed <c>object?</c> because Postgres returns
    /// <c>Guid</c> (UUID column), MSSQL returns <c>Guid</c>
    /// (UNIQUEIDENTIFIER), and SQLite returns <c>string</c> (TEXT). The
    /// generic mapper can't <c>Convert.ChangeType</c> a Guid into a string
    /// slot — we normalise in <see cref="NormalizeEventId"/>.
    /// </para>
    /// </summary>
    private sealed class AuditRow
    {
        [JsonPropertyName("event_id")]     public object? EventId { get; set; }
        [JsonPropertyName("event_type")]   public string? EventType { get; set; }
        [JsonPropertyName("category")]     public string? Category { get; set; }
        [JsonPropertyName("timestamp")]    public DateTimeOffset Timestamp { get; set; }
        [JsonPropertyName("user_id")]      public long? UserId { get; set; }
        [JsonPropertyName("login")]        public string? Login { get; set; }
        [JsonPropertyName("client_id")]    public string? ClientId { get; set; }
        [JsonPropertyName("ip_address")]   public string? IpAddress { get; set; }
        [JsonPropertyName("user_agent")]   public string? UserAgent { get; set; }
        [JsonPropertyName("details")]      public string? Details { get; set; }
    }

    private static string NormalizeEventId(object? v) => v switch
    {
        null => "",
        Guid g => g.ToString("N"),
        string s => s.Replace("-", "").ToLowerInvariant(),
        _ => v.ToString() ?? ""
    };
}
