using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// W6-0: Management processor for the backchannel revoked-sids list. Dispatches on the
/// "operation" header:
/// <list type="bullet">
///   <item><c>add</c> \u2014 publishes a new revocation entry (body: <see cref="RevokedSidsAddRequest"/>);
///         server clamps <c>ExpiresAt</c> to <c>now + <see cref="RedbIdentityOptions.RevokedSidsMaxRetention"/></c>.</item>
///   <item><c>since</c> \u2014 incremental poll. Cursor passed via the <c>cursor</c> header
///         (ISO-8601 string) or omitted on the first call. Returns entries with
///         <c>DateCreate &gt; cursor</c>, ordered ascending; capped at
///         <see cref="MaxBatchSize"/> entries per response. The <c>nextCursor</c> field of
///         the response equals the <c>DateCreate</c> of the last returned entry, or the
///         supplied cursor when there were no new entries.</item>
/// </list>
/// </summary>
internal sealed class RevokedSidsManagementProcessor : IProcessor
{
    /// <summary>Hard cap on entries returned per <c>since</c> call. Polls usually run every
    /// 60s on RPs, so 1000 entries / poll is enough for any realistic revocation burst.</summary>
    public const int MaxBatchSize = 1000;

    private readonly IRouteContext _context;
    private readonly RedbIdentityOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly string? _redbName;

    public RevokedSidsManagementProcessor(
        IRouteContext context,
        IOptions<RedbIdentityOptions> options,
        string? redbName = null,
        TimeProvider? timeProvider = null)
    {
        _context = context;
        _options = options.Value;
        _redbName = redbName;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName!, exchange);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "add":
                await Add(redb, exchange, ct);
                break;
            case "since":
                await Since(redb, exchange, ct);
                break;
            default:
                IdentityProcessorHelpers.SetError(exchange, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    private async Task Add(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request", "Body is required");
            return;
        }

        var sid = TryString(dict, "sid");
        var sub = TryString(dict, "sub");
        var clientId = TryString(dict, "clientId");

        if (string.IsNullOrEmpty(sid) && string.IsNullOrEmpty(sub))
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request", "Either 'sid' or 'sub' must be provided");
            return;
        }

        var now = _timeProvider.GetUtcNow();
        var maxExpires = now.Add(_options.RevokedSidsMaxRetention);
        var requested = TryDateTimeOffset(dict, "expiresAt");
        // Clamp client-supplied ExpiresAt to [now, now + RevokedSidsMaxRetention].
        var expiresAt = requested.HasValue && requested.Value < maxExpires && requested.Value > now
            ? requested.Value
            : maxExpires;

        var entry = new RedbObject<RevokedSidProps>
        {
            Props = new RevokedSidProps
            {
                Sid = string.IsNullOrEmpty(sid) ? null : sid,
                Sub = string.IsNullOrEmpty(sub) ? null : sub,
                ClientId = string.IsNullOrEmpty(clientId) ? null : clientId,
                RevokedAt = now,
                ExpiresAt = expiresAt
            }
        };

        entry.id = await redb.SaveAsync(entry).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new RevokedSidEntry
        {
            Sid = entry.Props.Sid,
            Sub = entry.Props.Sub,
            ClientId = entry.Props.ClientId,
            RevokedAt = entry.Props.RevokedAt,
            ExpiresAt = entry.Props.ExpiresAt
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SidRevoked;
        exchange.Properties["identity-event-data"] = new
        {
            Sid = entry.Props.Sid,
            Sub = entry.Props.Sub,
            ClientId = entry.Props.ClientId,
            ExpiresAt = entry.Props.ExpiresAt
        };
    }

    private async Task Since(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?>;
        var cursorRaw = dict is not null ? TryString(dict, "cursor") : null;
        var now = _timeProvider.GetUtcNow();
        // Bootstrap window when no cursor supplied: full retention period.
        var defaultCursor = now.Subtract(_options.RevokedSidsMaxRetention);
        var cursor = ParseCursor(cursorRaw) ?? defaultCursor;

        var rows = await redb.Query<RevokedSidProps>()
            .WhereRedb(o => o.DateCreate > cursor)
            .OrderByRedb(o => o.DateCreate)
            .Take(MaxBatchSize)
            .ToListAsync()
            .ConfigureAwait(false);

        var entries = new List<RevokedSidEntry>(rows.Count);
        var maxDateCreate = cursor;
        foreach (var row in rows)
        {
            entries.Add(new RevokedSidEntry
            {
                Sid = row.Props.Sid,
                Sub = row.Props.Sub,
                ClientId = row.Props.ClientId,
                RevokedAt = row.Props.RevokedAt,
                ExpiresAt = row.Props.ExpiresAt
            });
            if (row.DateCreate > maxDateCreate) maxDateCreate = row.DateCreate;
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new RevokedSidsSinceResponse
        {
            Entries = entries,
            NextCursor = maxDateCreate,
            ServerTime = now
        };
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private static string? TryString(Dictionary<string, object?> dict, string key)
        => dict.TryGetValue(key, out var v) && v is not null ? v.ToString() : null;

    private static DateTimeOffset? TryDateTimeOffset(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var v) || v is null) return null;
        return v switch
        {
            DateTimeOffset dto => dto,
            DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc), TimeSpan.Zero),
            string s when DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var parsed) => parsed,
            _ => null
        };
    }

    private static DateTimeOffset? ParseCursor(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return DateTimeOffset.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var parsed) ? parsed : null;
    }
}
