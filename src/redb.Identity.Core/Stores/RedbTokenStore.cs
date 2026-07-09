using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;

namespace redb.Identity.Core.Stores;

/// <summary>
/// OpenIddict token store backed by redb storage.
/// Entity type: <see cref="RedbObject{TokenProps}"/>.
/// Subject (GUID) → RedbObject.value_guid, CreationDate → date_create,
/// ExpirationDate → date_complete, RedemptionDate → date_begin.
/// </summary>
internal sealed class RedbTokenStore : IOpenIddictTokenStore<RedbObject<TokenProps>>
{
    /// <summary>Default batch size for prune / soft-delete operations.</summary>
    private const int PruneBatchSize = 500;

    private readonly IRedbService _redb;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly ILogger? _logger;

    // [STORE-DIAG] per-request call counters & cumulative ms (Scoped store).
    private int _fbidCalls, _fbrefCalls, _fbauthCalls;
    private long _fbidMs, _fbrefMs, _fbauthMs;

    // Per-request caches (Scoped store, lifetime = one HTTP request).
    // OpenIddict calls FindByIdAsync 2× per /connect/token for the same token id;
    // FindByReferenceIdAsync is hot on refresh_token rotation.
    // Caches null too — defends against repeated lookups for unknown ids.
    private readonly Dictionary<long, RedbObject<TokenProps>?> _idCache = new();
    private readonly Dictionary<string, RedbObject<TokenProps>?> _refCache = new(StringComparer.Ordinal);

    public RedbTokenStore(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion = null,
        ILogger<RedbTokenStore>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(redb);
        _redb = redb;
        _backgroundDeletion = backgroundDeletion;
        _logger = logger;
    }

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        return await _redb.Query<TokenProps>()
            .CountAsync()
            .ConfigureAwait(false);
    }

    public async ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RedbObject<TokenProps>>, IQueryable<TResult>> query,
        CancellationToken cancellationToken)
    {
        // OpenIddict managers do NOT call this internally — external code only.
        // Delegate to server-side CountAsync when the projected query is trivial.
        return await CountAsync(cancellationToken);
    }

    public async ValueTask CreateAsync(RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.id = await _redb.SaveAsync(token).ConfigureAwait(false);
        _idCache[token.id] = token;
        if (token.value_string is { } refId)
            _refCache[refId] = token;
    }

    public async ValueTask DeleteAsync(RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, token.id).ConfigureAwait(false);
        _idCache.Remove(token.id);
        if (token.value_string is { } refId)
            _refCache.Remove(refId);
    }

    public async IAsyncEnumerable<RedbObject<TokenProps>> FindAsync(
        string? subject, string? client,
        string? status, string? type,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var query = _redb.Query<TokenProps>();

        if (!string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var subjectGuid))
            query = query.WhereRedb(o => o.ValueGuid == subjectGuid);

        if (!string.IsNullOrEmpty(client) && long.TryParse(client, out var clientId))
            query = query.WhereRedb(o => o.ValueLong == clientId);

        if (!string.IsNullOrEmpty(status))
            query = query.Where(t => t.Status == status);

        if (!string.IsNullOrEmpty(type))
            query = query.Where(t => t.Type == type);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
            yield return result;
    }

    public async IAsyncEnumerable<RedbObject<TokenProps>> FindByApplicationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var appId))
            yield break;

        var results = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueLong == appId)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
            yield return result;
    }

    public async IAsyncEnumerable<RedbObject<TokenProps>> FindByAuthorizationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var authId))
            yield break;

        var sw = Stopwatch.GetTimestamp();
        var results = await _redb.Query<TokenProps>()
            .Where(t => t.AuthorizationObjectId == authId)
            .ToListAsync()
            .ConfigureAwait(false);
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbauthCalls;
        _fbauthMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Tok.FindByAuthId call#{N} ms={Ms} cum={Cum} count={Count} authId={AuthId}",
            n, ms, _fbauthMs, results.Count, identifier);

        foreach (var result in results)
            yield return result;
    }

    public async ValueTask<RedbObject<TokenProps>?> FindByIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var id))
            return null;

        if (_idCache.TryGetValue(id, out var cached))
        {
            var nh = ++_fbidCalls;
            _logger?.LogDebug("[STORE-DIAG] Tok.FindById call#{N} HIT cum={Cum} id={Id}",
                nh, _fbidMs, identifier);
            return cached;
        }

        var sw = Stopwatch.GetTimestamp();
        // Use Query<>(): it filters out soft-deleted objects (trash scheme).
        // LoadAsync<>() loads by primary key and ignores deletion state.
        var tok = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.Id == id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        _idCache[id] = tok;
        if (tok?.value_string is { } refId)
            _refCache[refId] = tok;
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbidCalls;
        _fbidMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Tok.FindById call#{N} MISS ms={Ms} cum={Cum} id={Id}",
            n, ms, _fbidMs, identifier);
        return tok;
    }

    public async ValueTask<RedbObject<TokenProps>?> FindByReferenceIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (_refCache.TryGetValue(identifier, out var cached))
        {
            var nh = ++_fbrefCalls;
            _logger?.LogDebug("[STORE-DIAG] Tok.FindByRef call#{N} HIT cum={Cum}", nh, _fbrefMs);
            return cached;
        }

        var sw = Stopwatch.GetTimestamp();
        var tok = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueString == identifier)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        _refCache[identifier] = tok;
        if (tok != null)
            _idCache[tok.id] = tok;
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbrefCalls;
        _fbrefMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Tok.FindByRef call#{N} MISS ms={Ms} cum={Cum} hit={Hit}",
            n, ms, _fbrefMs, tok != null);
        return tok;
    }

    public async IAsyncEnumerable<RedbObject<TokenProps>> FindBySubjectAsync(
        string subject, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(subject, out var subjectGuid))
            yield break;

        var results = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
            yield return result;
    }

    public ValueTask<string?> GetApplicationIdAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        var appId = token.value_long;
        return new(appId is not null and not 0 ? appId.Value.ToString() : null);
    }

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RedbObject<TokenProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<TokenProps>() directly.");
    }

    public ValueTask<string?> GetAuthorizationIdAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        var authId = token.Props.AuthorizationObjectId;
        return new(authId != 0 ? authId.ToString() : null);
    }

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.date_create);
    }

    public ValueTask<DateTimeOffset?> GetExpirationDateAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.date_complete);
    }

    public ValueTask<string?> GetIdAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.id.ToString());
    }

    public ValueTask<string?> GetPayloadAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.note);
    }

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var props = token.Props.Properties;
        if (props is null || props.Count == 0)
            return new(ImmutableDictionary<string, JsonElement>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        foreach (var (key, value) in props)
            builder[key] = JsonSerializer.Deserialize<JsonElement>(value);

        return new(builder.ToImmutable());
    }

    public ValueTask<DateTimeOffset?> GetRedemptionDateAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.date_begin);
    }

    public ValueTask<string?> GetReferenceIdAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.value_string);
    }

    public ValueTask<string?> GetStatusAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.Props.Status);
    }

    public ValueTask<string?> GetSubjectAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.value_guid?.ToString("D"));
    }

    public ValueTask<string?> GetTypeAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new(token.Props.Type);
    }

    public ValueTask<RedbObject<TokenProps>> InstantiateAsync(CancellationToken cancellationToken)
    {
        return new(new RedbObject<TokenProps> { Props = new TokenProps() });
    }

    public async IAsyncEnumerable<RedbObject<TokenProps>> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        IRedbQueryable<TokenProps> query = _redb.Query<TokenProps>().OrderByRedb<long>(o => o.Id);

        if (offset.HasValue)
            query = query.Skip(offset.Value);
        if (count.HasValue)
            query = query.Take(count.Value);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
            yield return result;
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RedbObject<TokenProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<TokenProps>() directly.");
    }

    public async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        // Step 1: collect IDs of non-valid tokens older than threshold (projection only, no Props load).
        // Newest-first ordering so a single PruneAsync call sees freshly-created Revoked/Expired tokens.
        var nonValidIds = await _redb.Query<TokenProps>()
            .Where(t => t.Status != OpenIddictConstants.Statuses.Valid)
            .WhereRedb(o => o.DateCreate < threshold)
            .OrderByDescendingRedb(o => o.DateCreate)
            .Take(PruneBatchSize)
            .Select(o => o.Id)
            .ToListAsync()
            .ConfigureAwait(false);

        // Step 2: collect tokens still flagged Valid but older than threshold whose authorization is no longer valid.
        // Newest-first to ensure recently-orphaned tokens are picked up promptly.
        var validCandidates = await _redb.Query<TokenProps>()
            .Where(t => t.Status == OpenIddictConstants.Statuses.Valid)
            .WhereRedb(o => o.DateCreate < threshold)
            .OrderByDescendingRedb(o => o.DateCreate)
            .Take(PruneBatchSize)
            .ToListAsync()
            .ConfigureAwait(false);

        var orphanTokenIds = new List<long>();
        if (validCandidates.Count > 0)
        {
            // Filter zero-AuthId tokens client-side (they reference no auth and shouldn't be pruned here).
            var authIds = validCandidates
                .Select(t => t.Props.AuthorizationObjectId)
                .Where(authId => authId != 0)
                .Distinct()
                .ToArray();

            // Bulk lookup: which auths are still Valid? Server-side WhereInRedb on _objects.Id + Where on Props.
            var validAuthIds = (await _redb.Query<AuthorizationProps>()
                .WhereInRedb(o => o.Id, authIds)
                .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
                .Select(o => o.Id)
                .ToListAsync()
                .ConfigureAwait(false)).ToHashSet();

            foreach (var t in validCandidates)
            {
                if (t.Props.AuthorizationObjectId == 0)
                    continue;
                if (!validAuthIds.Contains(t.Props.AuthorizationObjectId))
                    orphanTokenIds.Add(t.id);
            }
        }

        var toDelete = nonValidIds.Concat(orphanTokenIds).Distinct().ToList();
        if (toDelete.Count == 0)
            return 0;

        await SoftDeleteIdsAsync(toDelete).ConfigureAwait(false);
        // Evict the soft-deleted rows from the per-request caches so a later
        // FindByIdAsync / FindByReferenceIdAsync in the same request hits the DB —
        // Query<>() filters out trash so the lookup correctly returns null instead of
        // serving a stale pre-prune snapshot. We don't know which refIds belong to
        // which ids without an extra lookup, so clear the ref cache wholesale rather
        // than load each token; the trade-off is one extra DB roundtrip per ref-id
        // lookup post-prune, which is a rare path.
        foreach (var id in toDelete)
            _idCache.Remove(id);
        _refCache.Clear();
        return toDelete.Count;
    }

    public async ValueTask<long> RevokeAsync(
        string? subject, string? client, string? status, string? type,
        CancellationToken cancellationToken)
    {
        var query = _redb.Query<TokenProps>();

        if (!string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var subjectGuid))
            query = query.WhereRedb(o => o.ValueGuid == subjectGuid);

        if (!string.IsNullOrEmpty(client) && long.TryParse(client, out var clientId))
            query = query.WhereRedb(o => o.ValueLong == clientId);

        if (!string.IsNullOrEmpty(status))
            query = query.Where(t => t.Status == status);

        if (!string.IsNullOrEmpty(type))
            query = query.Where(t => t.Type == type);

        var targets = await query.ToListAsync().ConfigureAwait(false);
        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        // Single batch save — ChangeTracking diffs and updates only Status field.
        await _redb.SaveAsync(targets).ConfigureAwait(false);
        return targets.Count;
    }

    public async ValueTask<long> RevokeByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        if (!long.TryParse(identifier, out var appId))
            return 0;

        var targets = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueLong == appId)
            .ToListAsync()
            .ConfigureAwait(false);

        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        RefreshCachesAfterBulkUpdate(targets);
        return targets.Count;
    }

    public async ValueTask<long> RevokeByAuthorizationIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var authId))
            return 0;

        var targets = await _redb.Query<TokenProps>()
            .Where(t => t.AuthorizationObjectId == authId)
            .ToListAsync()
            .ConfigureAwait(false);

        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        RefreshCachesAfterBulkUpdate(targets);
        return targets.Count;
    }

    public async ValueTask<long> RevokeBySubjectAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(subject, out var subjectGuid))
            return 0;

        var targets = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .ToListAsync()
            .ConfigureAwait(false);

        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        RefreshCachesAfterBulkUpdate(targets);
        return targets.Count;
    }

    /// <summary>
    /// After a bulk mutation that bypassed FindByIdAsync (RevokeBy*, etc.), replace the
    /// per-request cache entries with the just-saved instances so later FindByIdAsync or
    /// FindByReferenceIdAsync calls in the same request observe the new state instead of
    /// returning the pre-mutation snapshot a previous CreateAsync or FindByIdAsync may
    /// have populated.
    /// </summary>
    private void RefreshCachesAfterBulkUpdate(IEnumerable<RedbObject<TokenProps>> targets)
    {
        foreach (var target in targets)
        {
            _idCache[target.id] = target;
            var refId = target.Props.ReferenceId;
            if (!string.IsNullOrEmpty(refId))
                _refCache[refId] = target;
        }
    }

    /// <summary>
    /// Identity-wide deletion helper indirection. Uses <see cref="IBackgroundDeletionService"/>
    /// when available; otherwise falls back to <c>SoftDeleteAsync</c> so the trash is still
    /// hidden from queries and picked up by the next BackgroundDeletionService orphan-recovery.
    /// </summary>
    private Task SoftDeleteIdsAsync(IEnumerable<long> ids)
        => IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, ids, PruneBatchSize);

    public ValueTask SetApplicationIdAsync(
        RedbObject<TokenProps> token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.value_long = !string.IsNullOrEmpty(identifier)
            && long.TryParse(identifier, out var appId) ? appId : null;
        return default;
    }

    public ValueTask SetAuthorizationIdAsync(
        RedbObject<TokenProps> token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.Props.AuthorizationObjectId = !string.IsNullOrEmpty(identifier)
            && long.TryParse(identifier, out var authId) ? authId : 0;
        return default;
    }

    public ValueTask SetCreationDateAsync(
        RedbObject<TokenProps> token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (date.HasValue)
            token.date_create = date.Value;
        return default;
    }

    public ValueTask SetExpirationDateAsync(
        RedbObject<TokenProps> token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.date_complete = date;
        return default;
    }

    public ValueTask SetPayloadAsync(
        RedbObject<TokenProps> token, string? payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.note = payload;
        return default;
    }

    public ValueTask SetPropertiesAsync(
        RedbObject<TokenProps> token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (properties is null || properties.IsEmpty)
        {
            token.Props.Properties = null;
            return default;
        }

        token.Props.Properties = properties.ToDictionary(
            kvp => kvp.Key, kvp => kvp.Value.GetRawText());
        return default;
    }

    public ValueTask SetRedemptionDateAsync(
        RedbObject<TokenProps> token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.date_begin = date;
        return default;
    }

    public ValueTask SetReferenceIdAsync(
        RedbObject<TokenProps> token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.value_string = identifier;
        return default;
    }

    public ValueTask SetStatusAsync(
        RedbObject<TokenProps> token, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.Props.Status = status;
        return default;
    }

    public ValueTask SetSubjectAsync(
        RedbObject<TokenProps> token, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        // Public sub is a GUID (per IdentityPrincipalBuilder). Store in value_guid so all
        // subject queries hit a single indexed column. The legacy bigint `key` linkage is
        // intentionally dropped — it pointed to _users._id, but with multi-instance
        // identity deployments that linkage is no longer stable across hosts.
        token.value_guid = !string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var g) ? g : null;
        return default;
    }

    public ValueTask SetTypeAsync(
        RedbObject<TokenProps> token, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        token.Props.Type = type;
        return default;
    }

    public async ValueTask UpdateAsync(
        RedbObject<TokenProps> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        // C11: cluster-safe single-use. Wrap Load+state-check+Save in a transaction with
        // SELECT ... FOR UPDATE on the token row. Two concurrent redeem attempts serialize
        // at the DB level; the loser observes that the row has already left the "valid"
        // state (e.g. Status=redeemed/revoked) and raises ConcurrencyException → OpenIddict
        // translates to invalid_grant.
        //
        // We do NOT rely on a generic hash compare because OpenIddict may invoke
        // UpdateAsync more than once per request (e.g. metadata touches that don't move
        // Status), allowing concurrent callers to pass an in-memory hash equality check
        // even though the row was already redeemed by another request.
        await _redb.Context.ExecuteAtomicAsync(async () =>
        {
            await _redb.LockForUpdateAsync(token.id).ConfigureAwait(false);

            var current = await _redb.LoadAsync<TokenProps>(token.id).ConfigureAwait(false);
            if (current is null)
                throw new OpenIddictExceptions.ConcurrencyException("The token was concurrently deleted.");

            // Single-use enforcement: only when the caller is REDEEMING (or REVOKING) a
            // token. If the row in the DB is no longer Valid, another request already won
            // the race, raise ConcurrencyException → invalid_grant. For all other status
            // transitions (Inactive → Valid for device-code verification, metadata-only
            // updates, Inactive → Inactive bumps, etc.) fall through to the generic
            // hash-based optimistic concurrency check below.
            var incomingStatus = token.Props.Status;
            var dbStatus = current.Props.Status;
            var consumingValid =
                string.Equals(incomingStatus, OpenIddictConstants.Statuses.Redeemed, StringComparison.Ordinal) ||
                string.Equals(incomingStatus, OpenIddictConstants.Statuses.Revoked, StringComparison.Ordinal);

            if (consumingValid && !string.Equals(dbStatus, OpenIddictConstants.Statuses.Valid, StringComparison.Ordinal))
            {
                throw new OpenIddictExceptions.ConcurrencyException(
                    "The token was concurrently updated and is no longer valid.");
            }

            // General optimistic concurrency: any other update path still requires that
            // the in-memory snapshot matches the DB row before persisting.
            if (current.hash != token.hash)
                throw new OpenIddictExceptions.ConcurrencyException("The token was concurrently updated.");

            await _redb.SaveAsync(token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }
}
