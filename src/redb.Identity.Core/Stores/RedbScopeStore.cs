using System.Collections.Immutable;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;

namespace redb.Identity.Core.Stores;

/// <summary>
/// OpenIddict scope store backed by redb PROPS storage.
/// Entity type: <see cref="RedbObject{ScopeProps}"/>.
/// DisplayName → RedbObject.name.
/// </summary>
internal sealed class RedbScopeStore : IOpenIddictScopeStore<RedbObject<ScopeProps>>
{
    private readonly IRedbService _redb;
    private readonly IBackgroundDeletionService? _backgroundDeletion;

    public RedbScopeStore(IRedbService redb, IBackgroundDeletionService? backgroundDeletion = null)
    {
        ArgumentNullException.ThrowIfNull(redb);
        _redb = redb;
        _backgroundDeletion = backgroundDeletion;
    }

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        return await _redb.Query<ScopeProps>()
            .CountAsync()
            .ConfigureAwait(false);
    }

    public async ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RedbObject<ScopeProps>>, IQueryable<TResult>> query,
        CancellationToken cancellationToken)
    {
        // OpenIddict managers do NOT call this internally — external code only.
        // Delegate to server-side CountAsync when the projected query is trivial.
        return await CountAsync(cancellationToken);
    }

    public async ValueTask CreateAsync(RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.value_string = scope.Props.ScopeName;
        scope.id = await _redb.SaveAsync(scope).ConfigureAwait(false);
    }

    public async ValueTask DeleteAsync(RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, scope.id).ConfigureAwait(false);
    }

    public async ValueTask<RedbObject<ScopeProps>?> FindByIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var id))
            return null;

        // Use Query<>(): it filters out soft-deleted objects (trash scheme).
        // LoadAsync<>() loads by primary key and ignores deletion state.
        var scope = await _redb.Query<ScopeProps>()
            .WhereRedb(o => o.Id == id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (scope != null) scope.Hydrate();
        return scope;
    }

    public async ValueTask<RedbObject<ScopeProps>?> FindByNameAsync(
        string name, CancellationToken cancellationToken)
    {
        var scope = await _redb.Query<ScopeProps>()
            .WhereRedb(o => o.ValueString == name)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (scope != null) scope.Hydrate();
        return scope;
    }

    public async IAsyncEnumerable<RedbObject<ScopeProps>> FindByNamesAsync(
        ImmutableArray<string> names, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (names.IsDefaultOrEmpty)
            yield break;

        var results = await _redb.Query<ScopeProps>()
            .WhereRedb(o => names.Contains(o.ValueString!))
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
        {
            result.Hydrate();
            yield return result;
        }
    }

    public async IAsyncEnumerable<RedbObject<ScopeProps>> FindByResourceAsync(
        string resource, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Array.Contains — verified working in redb PROPS (see E050_ArrayContains)
        var results = await _redb.Query<ScopeProps>()
            .Where(s => s.Resources != null && s.Resources.Contains(resource))
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
            yield return result.Hydrate();
    }

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RedbObject<ScopeProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<ScopeProps>() directly.");
    }

    public ValueTask<string?> GetDescriptionAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new(scope.Props.Description);
    }

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var descs = scope.Props.Descriptions;
        if (descs is null || descs.Count == 0)
            return new(ImmutableDictionary<CultureInfo, string>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();
        foreach (var (key, value) in descs)
            builder[CultureInfo.GetCultureInfo(key)] = value;

        return new(builder.ToImmutable());
    }

    public ValueTask<string?> GetDisplayNameAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new(scope.name);
    }

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var names = scope.Props.DisplayNames;
        if (names is null || names.Count == 0)
            return new(ImmutableDictionary<CultureInfo, string>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();
        foreach (var (key, value) in names)
            builder[CultureInfo.GetCultureInfo(key)] = value;

        return new(builder.ToImmutable());
    }

    public ValueTask<string?> GetIdAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new(scope.id.ToString());
    }

    public ValueTask<string?> GetNameAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new(scope.value_string ?? scope.Props.ScopeName);
    }

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var props = scope.Props.Properties;
        if (props is null || props.Count == 0)
            return new(ImmutableDictionary<string, JsonElement>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        foreach (var (key, value) in props)
            builder[key] = JsonSerializer.Deserialize<JsonElement>(value);

        return new(builder.ToImmutable());
    }

    public ValueTask<ImmutableArray<string>> GetResourcesAsync(
        RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new(scope.Props.Resources?.ToImmutableArray() ?? []);
    }

    public ValueTask<RedbObject<ScopeProps>> InstantiateAsync(CancellationToken cancellationToken)
    {
        return new(new RedbObject<ScopeProps> { Props = new ScopeProps() });
    }

    public async IAsyncEnumerable<RedbObject<ScopeProps>> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        IRedbQueryable<ScopeProps> query = _redb.Query<ScopeProps>().OrderByRedb<long>(o => o.Id);

        if (offset.HasValue)
            query = query.Skip(offset.Value);
        if (count.HasValue)
            query = query.Take(count.Value);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
            yield return result.Hydrate();
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RedbObject<ScopeProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<ScopeProps>() directly.");
    }

    public ValueTask SetDescriptionAsync(
        RedbObject<ScopeProps> scope, string? description, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.Props.Description = description;
        return default;
    }

    public ValueTask SetDescriptionsAsync(
        RedbObject<ScopeProps> scope,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.Props.Descriptions = descriptions is null || descriptions.IsEmpty
            ? null
            : descriptions.ToDictionary(kvp => kvp.Key.Name, kvp => kvp.Value);
        return default;
    }

    public ValueTask SetDisplayNameAsync(
        RedbObject<ScopeProps> scope, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.name = name;
        return default;
    }

    public ValueTask SetDisplayNamesAsync(
        RedbObject<ScopeProps> scope,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.Props.DisplayNames = names is null || names.IsEmpty
            ? null
            : names.ToDictionary(kvp => kvp.Key.Name, kvp => kvp.Value);
        return default;
    }

    public ValueTask SetNameAsync(
        RedbObject<ScopeProps> scope, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.Props.ScopeName = name;
        scope.value_string = name;
        return default;
    }

    public ValueTask SetPropertiesAsync(
        RedbObject<ScopeProps> scope,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (properties is null || properties.IsEmpty)
        {
            scope.Props.Properties = null;
            return default;
        }

        scope.Props.Properties = properties.ToDictionary(
            kvp => kvp.Key, kvp => kvp.Value.GetRawText());
        return default;
    }

    public ValueTask SetResourcesAsync(
        RedbObject<ScopeProps> scope, ImmutableArray<string> resources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        scope.Props.Resources = resources.IsDefaultOrEmpty ? null : [.. resources];
        return default;
    }

    public async ValueTask UpdateAsync(RedbObject<ScopeProps> scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        // C11: cluster-safe atomic update — see RedbTokenStore.UpdateAsync.
        await _redb.Context.ExecuteAtomicAsync(async () =>
        {
            await _redb.LockForUpdateAsync(scope.id).ConfigureAwait(false);

            var current = await _redb.LoadAsync<ScopeProps>(scope.id).ConfigureAwait(false);
            if (current is null)
                throw new OpenIddictExceptions.ConcurrencyException("The scope was concurrently deleted.");

            if (current.hash != scope.hash)
                throw new OpenIddictExceptions.ConcurrencyException("The scope was concurrently updated.");

            scope.value_string = scope.Props.ScopeName;
            await _redb.SaveAsync(scope).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }
}
