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
/// OpenIddict authorization store backed by redb storage.
/// Entity type: <see cref="RedbObject{AuthorizationProps}"/>.
/// Subject (GUID) → RedbObject.value_guid, CreationDate → RedbObject.date_create.
/// </summary>
internal sealed class RedbAuthorizationStore : IOpenIddictAuthorizationStore<RedbObject<AuthorizationProps>>
{
    /// <summary>Default batch size for prune / soft-delete operations.</summary>
    private const int PruneBatchSize = 500;

    private readonly IRedbService _redb;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly ILogger? _logger;

    // [STORE-DIAG] per-request call counters & cumulative ms (Scoped store).
    private int _fbidCalls, _fbappCalls, _fbsubCalls;
    private long _fbidMs, _fbappMs, _fbsubMs;

    // Per-request cache: store is Scoped (one HTTP request).
    // OpenIddict resolves authorization-id during token validation/issuance —
    // cache spares repeat PVT joins.
    private readonly Dictionary<long, RedbObject<AuthorizationProps>?> _idCache = new();

    public RedbAuthorizationStore(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion = null,
        ILogger<RedbAuthorizationStore>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(redb);
        _redb = redb;
        _backgroundDeletion = backgroundDeletion;
        _logger = logger;
    }

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        return await _redb.Query<AuthorizationProps>()
            .CountAsync()
            .ConfigureAwait(false);
    }

    public async ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RedbObject<AuthorizationProps>>, IQueryable<TResult>> query,
        CancellationToken cancellationToken)
    {
        // OpenIddict managers do NOT call this internally — external code only.
        // Delegate to server-side CountAsync when the projected query is trivial.
        return await CountAsync(cancellationToken);
    }

    public async ValueTask CreateAsync(RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        authorization.id = await _redb.SaveAsync(authorization).ConfigureAwait(false);
        _idCache[authorization.id] = authorization;
    }

    public async ValueTask DeleteAsync(RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        // Authorization drags child Tokens via cascade — never hard-delete on the request thread.
        await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, authorization.id).ConfigureAwait(false);
        _idCache.Remove(authorization.id);
    }

    public async IAsyncEnumerable<RedbObject<AuthorizationProps>> FindAsync(
        string? subject, string? client,
        string? status, string? type,
        ImmutableArray<string>? scopes, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var query = _redb.Query<AuthorizationProps>();

        if (!string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var subjectGuid))
            query = query.WhereRedb(o => o.ValueGuid == subjectGuid);

        if (!string.IsNullOrEmpty(client) && long.TryParse(client, out var clientId))
            query = query.Where(a => a.ApplicationObjectId == clientId);

        if (!string.IsNullOrEmpty(status))
            query = query.Where(a => a.Status == status);

        if (!string.IsNullOrEmpty(type))
            query = query.Where(a => a.Type == type);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
        {
            // Scope subset filter applied in memory (redb has no "contains all" operator)
            if (scopes is { IsDefaultOrEmpty: false } s)
            {
                var entityScopes = result.Props.Scopes ?? [];
                if (!s.All(scope => entityScopes.Contains(scope)))
                    continue;
            }

            yield return result;
        }
    }

    public async IAsyncEnumerable<RedbObject<AuthorizationProps>> FindByApplicationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var appId))
            yield break;

        var sw = Stopwatch.GetTimestamp();
        var results = await _redb.Query<AuthorizationProps>()
            .Where(a => a.ApplicationObjectId == appId)
            .ToListAsync()
            .ConfigureAwait(false);
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbappCalls;
        _fbappMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Auth.FindByAppId call#{N} ms={Ms} cum={Cum} count={Count} appId={AppId}",
            n, ms, _fbappMs, results.Count, identifier);

        foreach (var result in results)
            yield return result;
    }

    public async ValueTask<RedbObject<AuthorizationProps>?> FindByIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var id))
            return null;

        if (_idCache.TryGetValue(id, out var cached))
        {
            var nh = ++_fbidCalls;
            _logger?.LogDebug("[STORE-DIAG] Auth.FindById call#{N} HIT cum={Cum} id={Id}",
                nh, _fbidMs, identifier);
            return cached;
        }

        var sw = Stopwatch.GetTimestamp();
        // Use Query<>(): it filters out soft-deleted objects (trash scheme).
        // LoadAsync<>() loads by primary key and ignores deletion state.
        var auth = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Id == id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        _idCache[id] = auth;
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbidCalls;
        _fbidMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Auth.FindById call#{N} MISS ms={Ms} cum={Cum} id={Id}",
            n, ms, _fbidMs, identifier);
        return auth;
    }

    public async IAsyncEnumerable<RedbObject<AuthorizationProps>> FindBySubjectAsync(
        string subject, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(subject, out var subjectGuid))
            yield break;

        var sw = Stopwatch.GetTimestamp();
        var results = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .ToListAsync()
            .ConfigureAwait(false);
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbsubCalls;
        _fbsubMs += ms;
        _logger?.LogDebug("[STORE-DIAG] Auth.FindBySubject call#{N} ms={Ms} cum={Cum} count={Count} sub={Sub}",
            n, ms, _fbsubMs, results.Count, subject);

        foreach (var result in results)
            yield return result;
    }

    public ValueTask<string?> GetApplicationIdAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        var appId = authorization.Props.ApplicationObjectId;
        return new(appId != 0 ? appId.ToString() : null);
    }

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RedbObject<AuthorizationProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<AuthorizationProps>() directly.");
    }

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.date_create);
    }

    public ValueTask<string?> GetIdAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.id.ToString());
    }

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        var props = authorization.Props.Properties;
        if (props is null || props.Count == 0)
            return new(ImmutableDictionary<string, JsonElement>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        foreach (var (key, value) in props)
            builder[key] = JsonSerializer.Deserialize<JsonElement>(value);

        return new(builder.ToImmutable());
    }

    public ValueTask<ImmutableArray<string>> GetScopesAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.Props.Scopes?.ToImmutableArray() ?? []);
    }

    public ValueTask<string?> GetStatusAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.Props.Status);
    }

    public ValueTask<string?> GetSubjectAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.value_guid?.ToString("D"));
    }

    public ValueTask<string?> GetTypeAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(authorization.Props.Type);
    }

    public ValueTask<RedbObject<AuthorizationProps>> InstantiateAsync(CancellationToken cancellationToken)
    {
        return new(new RedbObject<AuthorizationProps> { Props = new AuthorizationProps() });
    }

    public async IAsyncEnumerable<RedbObject<AuthorizationProps>> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        IRedbQueryable<AuthorizationProps> query = _redb.Query<AuthorizationProps>().OrderByRedb<long>(o => o.Id);

        if (offset.HasValue)
            query = query.Skip(offset.Value);
        if (count.HasValue)
            query = query.Take(count.Value);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
            yield return result;
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RedbObject<AuthorizationProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<AuthorizationProps>() directly.");
    }

    public async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        // Find non-valid authorizations created before threshold (project IDs only)
        var candidateIds = await _redb.Query<AuthorizationProps>()
            .Where(a => a.Status != OpenIddictConstants.Statuses.Valid)
            .WhereRedb(o => o.DateCreate < threshold)
            .Take(PruneBatchSize)
            .Select(o => o.Id)
            .ToListAsync()
            .ConfigureAwait(false);

        if (candidateIds.Count == 0)
            return 0;

        // Exclude authorizations that still have tokens attached (server-side IDs only).
        var referencedAuthIds = (await _redb.Query<TokenProps>()
            .WhereIn(t => t.AuthorizationObjectId, candidateIds.ToArray())
            .Select(t => t.Props.AuthorizationObjectId)
            .Distinct()
            .ToListAsync()
            .ConfigureAwait(false)).ToHashSet();

        var toDelete = candidateIds.Where(id => !referencedAuthIds.Contains(id)).ToList();
        if (toDelete.Count == 0)
            return 0;

        await SoftDeleteIdsAsync(toDelete).ConfigureAwait(false);
        // Evict the soft-deleted rows from the per-request cache so a later FindByIdAsync
        // in the same request goes to the DB (where Query<>() now hides them as soft-deleted)
        // instead of returning a stale "valid" snapshot from before the prune.
        foreach (var id in toDelete)
            _idCache.Remove(id);
        return toDelete.Count;
    }

    public async ValueTask<long> RevokeAsync(
        string? subject, string? client, string? status, string? type,
        CancellationToken cancellationToken)
    {
        var query = _redb.Query<AuthorizationProps>();

        if (!string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var subjectGuid))
            query = query.WhereRedb(o => o.ValueGuid == subjectGuid);

        if (!string.IsNullOrEmpty(client) && long.TryParse(client, out var clientId))
            query = query.Where(a => a.ApplicationObjectId == clientId);

        if (!string.IsNullOrEmpty(status))
            query = query.Where(a => a.Status == status);

        if (!string.IsNullOrEmpty(type))
            query = query.Where(a => a.Type == type);

        var targets = await query.ToListAsync().ConfigureAwait(false);
        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        // Replace cache entries with the just-saved instances so that subsequent
        // FindByIdAsync in the same request observes Status=revoked. The previous cache
        // entry came in via CreateAsync and would otherwise serve the pre-revoke snapshot.
        foreach (var target in targets)
            _idCache[target.id] = target;
        return targets.Count;
    }

    public async ValueTask<long> RevokeByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var appId))
            return 0;

        var targets = await _redb.Query<AuthorizationProps>()
            .Where(a => a.ApplicationObjectId == appId)
            .ToListAsync()
            .ConfigureAwait(false);

        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        foreach (var target in targets)
            _idCache[target.id] = target;
        return targets.Count;
    }

    public async ValueTask<long> RevokeBySubjectAsync(
        string subject, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(subject, out var subjectGuid))
            return 0;

        var targets = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .ToListAsync()
            .ConfigureAwait(false);

        if (targets.Count == 0)
            return 0;

        foreach (var target in targets)
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;

        await _redb.SaveAsync(targets).ConfigureAwait(false);
        foreach (var target in targets)
            _idCache[target.id] = target;
        return targets.Count;
    }

    /// <summary>
    /// Identity-wide deletion helper indirection. Uses <see cref="IBackgroundDeletionService"/>
    /// when available; otherwise falls back to <c>SoftDeleteAsync</c> so the trash is still
    /// hidden from queries and picked up by the next BackgroundDeletionService orphan-recovery.
    /// </summary>
    private Task SoftDeleteIdsAsync(IEnumerable<long> ids)
        => IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, ids, PruneBatchSize);

    public ValueTask SetApplicationIdAsync(
        RedbObject<AuthorizationProps> authorization, string? identifier,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        authorization.Props.ApplicationObjectId = !string.IsNullOrEmpty(identifier)
            && long.TryParse(identifier, out var appId) ? appId : 0;
        return default;
    }

    public ValueTask SetCreationDateAsync(
        RedbObject<AuthorizationProps> authorization, DateTimeOffset? date,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        if (date.HasValue)
            authorization.date_create = date.Value;
        return default;
    }

    public ValueTask SetPropertiesAsync(
        RedbObject<AuthorizationProps> authorization,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        if (properties is null || properties.IsEmpty)
        {
            authorization.Props.Properties = null;
            return default;
        }

        authorization.Props.Properties = properties.ToDictionary(
            kvp => kvp.Key, kvp => kvp.Value.GetRawText());
        return default;
    }

    public ValueTask SetScopesAsync(
        RedbObject<AuthorizationProps> authorization,
        ImmutableArray<string> scopes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        authorization.Props.Scopes = scopes.IsDefaultOrEmpty ? null : [.. scopes];
        return default;
    }

    public ValueTask SetStatusAsync(
        RedbObject<AuthorizationProps> authorization, string? status,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        authorization.Props.Status = status;
        return default;
    }

    public ValueTask SetSubjectAsync(
        RedbObject<AuthorizationProps> authorization, string? subject,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        // Public sub is a GUID — store in value_guid (see RedbTokenStore.SetSubjectAsync).
        authorization.value_guid = !string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var g) ? g : null;
        return default;
    }

    public ValueTask SetTypeAsync(
        RedbObject<AuthorizationProps> authorization, string? type,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        authorization.Props.Type = type;
        return default;
    }

    public async ValueTask UpdateAsync(
        RedbObject<AuthorizationProps> authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        // C11: cluster-safe atomic update — see RedbTokenStore.UpdateAsync.
        await _redb.Context.ExecuteAtomicAsync(async () =>
        {
            await _redb.LockForUpdateAsync(authorization.id).ConfigureAwait(false);

            var current = await _redb.LoadAsync<AuthorizationProps>(authorization.id).ConfigureAwait(false);
            if (current is null)
                throw new OpenIddictExceptions.ConcurrencyException("The authorization was concurrently deleted.");

            if (current.hash != authorization.hash)
                throw new OpenIddictExceptions.ConcurrencyException("The authorization was concurrently updated.");

            await _redb.SaveAsync(authorization).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }
}
