using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Manages user login sessions. Sessions track when a user logged into an application.
/// Revoking sessions cascades to revoking all authorizations (which invalidates tokens).
/// </summary>
public sealed class SessionService
{
    private readonly IRedbService _redb;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _idleTimeout;
    private readonly TimeSpan _absoluteTimeout;

    public SessionService(IRedbService redb)
        : this(redb, TimeProvider.System, null)
    {
    }

    public SessionService(IRedbService redb, TimeProvider? timeProvider)
        : this(redb, timeProvider, null)
    {
    }

    public SessionService(IRedbService redb, TimeProvider? timeProvider, IOptions<RedbIdentityOptions>? options)
    {
        _redb = redb;
        _timeProvider = timeProvider ?? TimeProvider.System;
        // No DI source → fall back to industry-default 24 h idle / 30 d absolute.
        // Same defaults as RedbIdentityOptions; declared twice so a SessionService
        // built without options (legacy call sites) doesn't fail-open with
        // TimeSpan.Zero.
        _idleTimeout = options?.Value.SessionIdleTimeout ?? TimeSpan.FromHours(24);
        _absoluteTimeout = options?.Value.SessionAbsoluteTimeout ?? TimeSpan.FromDays(30);
    }

    /// <summary>
    /// S-track: is this session beyond either timeout? Mirrors the check done
    /// at <see cref="ListAsync"/> (lazy) and <see cref="SessionCleanupProcessor"/>
    /// (eager).
    /// </summary>
    public bool IsExpired(SessionProps props, DateTimeOffset? createdAt, DateTimeOffset now)
    {
        if (createdAt is { } c && now - c > _absoluteTimeout) return true;
        if (props.LastAccessedAt is { } la && now - la > _idleTimeout) return true;
        return false;
    }

    /// <summary>
    /// Creates a new active session record. <paramref name="ipAddress"/>, <paramref name="userAgent"/>
    /// and <paramref name="deviceLabel"/> are optional device-identification fields populated by
    /// the HTTP authentication processors from the calling request's headers.
    /// </summary>
    public async Task<RedbObject<SessionProps>> CreateAsync(
        long userId, long applicationObjectId,
        bool mfaVerified = false, string? mfaMethod = null,
        string? ipAddress = null, string? userAgent = null, string? deviceLabel = null,
        CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow();
        var session = new RedbObject<SessionProps>
        {
            key = userId,
            Props = new SessionProps
            {
                ApplicationObjectId = applicationObjectId,
                Status = "active",
                MfaVerified = mfaVerified,
                MfaMethod = mfaMethod,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                DeviceLabel = deviceLabel,
                LastAccessedAt = now,
                LastAccessedBy = "create",
            }
        };

        session.id = await _redb.SaveAsync(session).ConfigureAwait(false);
        return session;
    }

    /// <summary>
    /// S-track: bump <c>LastAccessedAt</c> on the given session. Called by
    /// <see cref="OpenIddict.Handlers.HandleTokenRequestHandler"/> on
    /// refresh_token grant, by the cookie OnValidatePrincipal handler, and
    /// by /connect/userinfo. <paramref name="activity"/> is a short label
    /// stored for diagnostics ("refresh_token", "cookie", "userinfo").
    /// No-op (returns false) when the session doesn't exist or is revoked.
    /// </summary>
    public async Task<bool> TouchAsync(long sessionId, string activity, CancellationToken ct = default)
    {
        if (sessionId <= 0) return false;
        var session = await _redb.LoadAsync<SessionProps>(sessionId).ConfigureAwait(false);
        if (session is null || session.Props.Status != "active") return false;

        session.Props.LastAccessedAt = _timeProvider.GetUtcNow();
        session.Props.LastAccessedBy = activity;
        await _redb.SaveAsync(session).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Checks whether a specific session (by its object ID) has been revoked.
    /// Returns <c>true</c> if the session exists and is revoked, <c>false</c> otherwise.
    /// </summary>
    public async Task<bool> IsSessionRevokedAsync(long sessionObjectId, CancellationToken ct = default)
    {
        if (sessionObjectId <= 0)
            return false;

        var session = await _redb.LoadAsync<SessionProps>(sessionObjectId)
            .ConfigureAwait(false);

        return session?.Props.Status == "revoked";
    }

    /// <summary>
    /// Checks whether the user's sessions have been revoked (indicating explicit logout).
    /// Returns <c>true</c> only if revoked sessions exist AND there are zero active ones.
    /// If no sessions exist at all (first authorize), returns <c>false</c> (not revoked).
    /// </summary>
    public async Task<bool> IsFullyRevokedAsync(
        long userId, TimeSpan? lookbackWindow = null, CancellationToken ct = default)
    {
        var sessions = await _redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()
            .ConfigureAwait(false);

        // Only consider sessions within the lookback window (default: all).
        // Sessions older than the cookie lifetime are irrelevant — any cookie from that era
        // has already expired, so revoked sessions from previous login generations don't matter.
        if (lookbackWindow.HasValue)
        {
            var cutoff = _timeProvider.GetUtcNow() - lookbackWindow.Value;
            sessions = sessions
                .Where(s => s.date_create >= cutoff)
                .ToList();
        }

        // No sessions at all — user hasn't authorized yet, not revoked
        if (sessions.Count == 0)
            return false;

        // If any session is active, not fully revoked
        return sessions.All(s => s.Props.Status == "revoked");
    }

    /// <summary>
    /// Lists all active sessions for a user. Includes application info.
    /// <para>
    /// Application metadata is fetched in a single batched <c>WhereInRedb(o =&gt; o.Id, ids)</c>
    /// query rather than per-row <see cref="IRedbService.LoadAsync"/> — a user with many
    /// active sessions across multiple clients would otherwise turn this admin endpoint
    /// into an O(N) round-trip storm.
    /// </para>
    /// </summary>
    public async Task<List<SessionInfo>> ListAsync(long userId, CancellationToken ct = default)
    {
        var sessions = await _redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(s => s.Status == "active")
            .ToListAsync()
            .ConfigureAwait(false);

        // S-track: lazy-expire any active rows that have crossed either
        // timeout. Mark + persist + drop from the result so the caller sees
        // only sessions actually still alive. Eager cleanup also runs in
        // SessionCleanupProcessor for tenants where the user never lists.
        var now = _timeProvider.GetUtcNow();
        var stillAlive = new List<RedbObject<SessionProps>>(sessions.Count);
        foreach (var s in sessions)
        {
            if (IsExpired(s.Props, s.date_create, now))
            {
                s.Props.Status = "revoked";
                await _redb.SaveAsync(s).ConfigureAwait(false);
            }
            else
            {
                stillAlive.Add(s);
            }
        }
        sessions = stillAlive;

        // Batch-fetch every distinct ApplicationProps in ONE query to avoid N+1.
        var appIds = sessions
            .Where(s => s.Props.ApplicationObjectId > 0)
            .Select(s => s.Props.ApplicationObjectId)
            .Distinct()
            .ToArray();

        var appsById = new Dictionary<long, RedbObject<ApplicationProps>>(appIds.Length);
        if (appIds.Length > 0)
        {
            var apps = await _redb.Query<ApplicationProps>()
                .WhereInRedb(o => o.Id, appIds)
                .ToListAsync()
                .ConfigureAwait(false);

            // Hydrate copies _objects.value_string -> Props.ClientId, since ClientId is
            // [RedbIgnore] and stored on the base object, not the PROPS facets.
            foreach (var app in apps)
                appsById[app.id] = app.Hydrate();
        }

        var result = new List<SessionInfo>(sessions.Count);

        foreach (var session in sessions)
        {
            string? clientId = null;
            string? appName = null;

            if (session.Props.ApplicationObjectId > 0
                && appsById.TryGetValue(session.Props.ApplicationObjectId, out var app))
            {
                clientId = app.Props.ClientId;
                appName = app.Name;
            }

            result.Add(new SessionInfo
            {
                SessionId = session.id,
                UserId = session.key ?? 0,
                ApplicationObjectId = session.Props.ApplicationObjectId,
                ClientId = clientId,
                ApplicationName = appName,
                Status = session.Props.Status ?? "active",
                CreatedAt = session.date_create,
                IpAddress = session.Props.IpAddress,
                UserAgent = session.Props.UserAgent,
                DeviceLabel = session.Props.DeviceLabel,
                LastAccessedAt = session.Props.LastAccessedAt,
                LastAccessedBy = session.Props.LastAccessedBy
            });
        }

        return result;
    }

    /// <summary>
    /// Admin-wide list of recent active sessions across ALL users, paginated.
    /// Powers the /admin/sessions browse-by-default page (WSO2-style). The
    /// per-user <see cref="ListAsync"/> stays the targeted path; this one is
    /// the operator's first-look "what's alive right now" view.
    /// </summary>
    public async Task<(List<SessionInfo> Items, int Total)> ListAllActiveAsync(
        int offset, int count, CancellationToken ct = default)
    {
        offset = Math.Max(0, offset);
        count = Math.Clamp(count, 1, 200);

        var total = (int)await _redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .CountAsync()
            .ConfigureAwait(false);

        var sessions = await _redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .OrderByDescendingRedb(o => o.Id)
            .Skip(offset)
            .Take(count)
            .ToListAsync()
            .ConfigureAwait(false);

        var appIds = sessions
            .Where(s => s.Props.ApplicationObjectId > 0)
            .Select(s => s.Props.ApplicationObjectId)
            .Distinct()
            .ToArray();

        var appsById = new Dictionary<long, RedbObject<ApplicationProps>>(appIds.Length);
        if (appIds.Length > 0)
        {
            var apps = await _redb.Query<ApplicationProps>()
                .WhereInRedb(o => o.Id, appIds)
                .ToListAsync()
                .ConfigureAwait(false);
            foreach (var app in apps) appsById[app.id] = app.Hydrate();
        }

        var items = new List<SessionInfo>(sessions.Count);
        foreach (var s in sessions)
        {
            string? clientId = null;
            string? appName = null;
            if (s.Props.ApplicationObjectId > 0
                && appsById.TryGetValue(s.Props.ApplicationObjectId, out var app))
            {
                clientId = app.value_string;
                appName = app.name;
            }

            items.Add(new SessionInfo
            {
                SessionId = s.id,
                UserId = s.key ?? 0,
                ApplicationObjectId = s.Props.ApplicationObjectId,
                ClientId = clientId,
                ApplicationName = appName,
                Status = s.Props.Status,
                CreatedAt = s.date_create,
                IpAddress = s.Props.IpAddress,
                UserAgent = s.Props.UserAgent,
                DeviceLabel = s.Props.DeviceLabel,
                LastAccessedAt = s.Props.LastAccessedAt,
                LastAccessedBy = s.Props.LastAccessedBy
            });
        }

        return (items, total);
    }

    /// <summary>
    /// Revokes a single session by its object ID.
    /// </summary>
    public async Task<int> RevokeAsync(long sessionObjectId, CancellationToken ct = default)
    {
        var session = await _redb.LoadAsync<SessionProps>(sessionObjectId)
            .ConfigureAwait(false);
        if (session is null || session.Props.Status == "revoked")
            return 0;

        session.Props.Status = "revoked";
        await _redb.SaveAsync(session).ConfigureAwait(false);
        return 1;
    }

    /// <summary>
    /// Revokes all active sessions for a user.
    /// <para>
    /// Mutated rows are persisted in a single batched <c>SaveAsync(IEnumerable&lt;...&gt;)</c>
    /// call rather than per-row inside the loop \u2014 a power user with many open device
    /// sessions otherwise turned this admin / logout step into an O(N) round-trip storm.
    /// </para>
    /// </summary>
    public async Task<int> RevokeAllAsync(long userId, CancellationToken ct = default)
    {
        var sessions = await _redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(s => s.Status == "active")
            .ToListAsync()
            .ConfigureAwait(false);

        if (sessions.Count == 0)
            return 0;

        foreach (var session in sessions)
            session.Props.Status = "revoked";

        await _redb.SaveAsync(sessions).ConfigureAwait(false);

        return sessions.Count;
    }

    /// <summary>
    /// N7-4 dry-run: returns how many active sessions <see cref="RevokeAllAsync"/> would
    /// revoke plus a small sample of their ids, WITHOUT mutating any rows. Intended as the
    /// preview backing for admin destructive-operation confirmation flows.
    /// </summary>
    public async Task<(int Count, IReadOnlyList<long> SampleSessionIds)> PreviewRevokeAllAsync(
        long userId, CancellationToken ct = default)
    {
        const int sampleSize = 10;
        var ids = await _redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(s => s.Status == "active")
            .Select(o => o.Id)
            .ToListAsync()
            .ConfigureAwait(false);
        return (ids.Count, ids.Take(sampleSize).ToList());
    }

    /// <summary>
    /// Performs full logout: revokes all sessions AND all authorizations for the user.
    /// Revoking authorizations effectively invalidates all tokens linked to them.
    /// <para>
    /// Both session and authorization revocations are flushed via batched
    /// <c>SaveAsync(IEnumerable&lt;...&gt;)</c> rather than per-row \u2014 a user with many
    /// long-lived consents (one row per (user, client) authorization, plus a fresh row
    /// per refresh-token rotation) would otherwise force the logout endpoint into
    /// hundreds of sequential round-trips.
    /// </para>
    /// </summary>
    /// <returns>Number of sessions revoked.</returns>
    public async Task<int> LogoutAsync(long userId, CancellationToken ct = default)
    {
        // 1. Revoke all active sessions
        var sessionCount = await RevokeAllAsync(userId, ct).ConfigureAwait(false);

        // 2. Revoke all non-revoked authorizations \u2192 cascades to token invalidation
        var auths = await _redb.Query<AuthorizationProps>()
            .WhereRedb(a => a.Key == userId)
            .Where(a => a.Status != "revoked")
            .ToListAsync()
            .ConfigureAwait(false);

        if (auths.Count > 0)
        {
            foreach (var auth in auths)
                auth.Props.Status = "revoked";

            await _redb.SaveAsync(auths).ConfigureAwait(false);
        }

        return sessionCount;
    }

    /// <summary>Session info DTO for API responses.</summary>
    public sealed class SessionInfo
    {
        public long SessionId { get; set; }
        public long UserId { get; set; }
        public long ApplicationObjectId { get; set; }
        public string? ClientId { get; set; }
        public string? ApplicationName { get; set; }
        public string Status { get; set; } = "active";
        public DateTimeOffset? CreatedAt { get; set; }
        /// <summary>Client IP captured at session creation. <c>null</c> for non-HTTP transports.</summary>
        public string? IpAddress { get; set; }
        /// <summary>Raw <c>User-Agent</c> header at session creation. Truncated to 512 chars by extractor.</summary>
        public string? UserAgent { get; set; }
        /// <summary>Human-friendly device label (e.g. "Chrome 135 on Windows 10") parsed from <see cref="UserAgent"/>.</summary>
        public string? DeviceLabel { get; set; }

        /// <summary>S-track: last activity timestamp (refresh_token / cookie / userinfo). Null on legacy rows.</summary>
        public DateTimeOffset? LastAccessedAt { get; set; }

        /// <summary>S-track: label of the most recent activity that bumped <see cref="LastAccessedAt"/>.</summary>
        public string? LastAccessedBy { get; set; }
    }
}
