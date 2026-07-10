using System.Linq.Expressions;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Query.Aggregation;
using redb.Core.Query.Grouping;
using redb.Core.Query.Window;
using redb.Identity.Core.Models;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Configures <see cref="IRedbService"/> mock to return a queryable over an in-memory list.
/// Usage: <c>MockRedbQuery.Setup(redb, items)</c>
/// </summary>
internal static class MockRedbQuery
{
    /// <summary>
    /// Makes <c>redb.Query&lt;TProps&gt;()</c> return a mock queryable over <paramref name="items"/>.
    /// The mock supports: Where, WhereRedb, OrderByRedb, Skip, Take, ToListAsync, CountAsync, FirstOrDefaultAsync, AnyAsync.
    /// </summary>
    public static void Setup<TProps>(IRedbService redb, List<RedbObject<TProps>> items)
        where TProps : class, new()
    {
        var queryable = new InMemoryRedbQueryable<TProps>(items);
        redb.Query<TProps>().Returns(_ => new InMemoryRedbQueryable<TProps>(items));
    }

    /// <summary>
    /// Creates a RedbObject with the given id, name, and props for testing.
    /// </summary>
    public static RedbObject<TProps> CreateObject<TProps>(long id, string name, TProps props)
        where TProps : class, new()
    {
        var obj = new RedbObject<TProps>(props)
        {
            Id = id,
            Name = name,
            DateCreate = DateTimeOffset.UtcNow,
            DateModify = DateTimeOffset.UtcNow
        };

        // Sync value_string for [RedbIgnore] identity fields
        obj.value_string = props switch
        {
            ApplicationProps a => a.ClientId,
            ScopeProps s => s.ScopeName,
            _ => null
        };

        return obj;
    }
}

/// <summary>
/// Minimal in-memory IRedbQueryable for unit tests.
/// Supports basic fluent operations used by management processors.
/// </summary>
internal class InMemoryRedbQueryable<TProps> : IRedbQueryable<TProps>, IOrderedRedbQueryable<TProps>
    where TProps : class, new()
{
    private IEnumerable<RedbObject<TProps>> _source;

    public InMemoryRedbQueryable(IEnumerable<RedbObject<TProps>> source) => _source = source;

    public IRedbQueryable<TProps> Where(Expression<Func<TProps, bool>> predicate)
    {
        var compiled = predicate.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.Where(o => compiled(o.Props)));
    }

    public IRedbQueryable<TProps> WhereRedb(Expression<Func<IRedbObject, bool>> predicate)
    {
        var compiled = predicate.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.Where(o => compiled(o)));
    }

    public IOrderedRedbQueryable<TProps> OrderBy<TKey>(Expression<Func<TProps, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.OrderBy(o => compiled(o.Props)));
    }

    public IOrderedRedbQueryable<TProps> OrderByDescending<TKey>(Expression<Func<TProps, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.OrderByDescending(o => compiled(o.Props)));
    }

    public IOrderedRedbQueryable<TProps> OrderByRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.OrderBy(o => compiled(o)));
    }

    public IOrderedRedbQueryable<TProps> OrderByDescendingRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbQueryable<TProps>(_source.OrderByDescending(o => compiled(o)));
    }

    public IRedbQueryable<TProps> Take(int count)
        => new InMemoryRedbQueryable<TProps>(_source.Take(count));

    public IRedbQueryable<TProps> Skip(int count)
        => new InMemoryRedbQueryable<TProps>(_source.Skip(count));

    public Task<List<RedbObject<TProps>>> ToListAsync()
        => Task.FromResult(_source.ToList());

    public Task<int> CountAsync()
        => Task.FromResult(_source.Count());

    public Task<RedbObject<TProps>?> FirstOrDefaultAsync()
        => Task.FromResult(_source.FirstOrDefault());

    public Task<RedbObject<TProps>?> FirstOrDefaultAsync(Expression<Func<TProps, bool>> predicate)
    {
        var compiled = predicate.Compile();
        return Task.FromResult(_source.FirstOrDefault(o => compiled(o.Props)));
    }

    public Task<bool> AnyAsync()
        => Task.FromResult(_source.Any());

    public Task<bool> AnyAsync(Expression<Func<TProps, bool>> predicate)
    {
        var compiled = predicate.Compile();
        return Task.FromResult(_source.Any(o => compiled(o.Props)));
    }

    // ── Not used by management processors but required by interface ──

    public IRedbQueryable<TProps> WhereIn<TValue>(Expression<Func<TProps, TValue>> selector, IEnumerable<TValue> values) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereInRedb<TValue>(Expression<Func<IRedbObject, TValue>> selector, IEnumerable<TValue> values) => throw new NotSupportedException();
    public Task<bool> AllAsync(Expression<Func<TProps, bool>> predicate) => throw new NotSupportedException();
    public IRedbProjectedQueryable<TResult> Select<TResult>(Expression<Func<RedbObject<TProps>, TResult>> selector)
    {
        var compiled = selector.Compile();
        return new InMemoryRedbProjectedQueryable<TResult>(_source.Select(compiled));
    }
    public IRedbQueryable<TProps> Distinct()
        => new InMemoryRedbQueryable<TProps>(_source.Distinct());
    public IRedbQueryable<TProps> DistinctRedb() => throw new NotSupportedException();
    public IRedbQueryable<TProps> DistinctBy<TKey>(Expression<Func<TProps, TKey>> keySelector) => throw new NotSupportedException();
    public IRedbQueryable<TProps> DistinctByRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WithMaxRecursionDepth(int depth) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WithLazyLoading(bool enabled = true) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereHasAncestor<TTarget>(Expression<Func<TTarget, bool>> ancestorCondition, int? maxDepth = null) where TTarget : class => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereHasDescendant<TTarget>(Expression<Func<TTarget, bool>> descendantCondition, int? maxDepth = null) where TTarget : class => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereLevel(int level) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereLevel(Expression<Func<int, bool>> levelCondition) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereRoots() => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereLeaves() => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereChildrenOf(long parentId) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereChildrenOf(IRedbObject parentObject) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereDescendantsOf(long ancestorId, int? maxDepth = null) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WhereDescendantsOf(IRedbObject ancestorObject, int? maxDepth = null) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WithMaxDepth(int depth) => throw new NotSupportedException();
    public IRedbQueryable<TProps> WithPropsDepth(int depth) => throw new NotSupportedException();
    public Task<List<TreeRedbObject<TProps>>> ToTreeListAsync() => throw new NotSupportedException();
    public Task<List<ITreeRedbObject>> ToRootListAsync() => throw new NotSupportedException();
    public Task<List<TreeRedbObject<TProps>>> ToFlatListAsync() => throw new NotSupportedException();
    public Task<int> DeleteAsync() => throw new NotSupportedException();
    public Task<decimal> SumAsync<TField>(Expression<Func<TProps, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<decimal> AverageAsync<TField>(Expression<Func<TProps, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TField?> MinAsync<TField>(Expression<Func<TProps, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TField?> MaxAsync<TField>(Expression<Func<TProps, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<FieldStatistics<TField>> GetStatisticsAsync<TField>(Expression<Func<TProps, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TResult> AggregateAsync<TResult>(Expression<Func<RedbObject<TProps>, TResult>> selector) => throw new NotSupportedException();
    public Task<decimal> SumRedbAsync<TField>(Expression<Func<IRedbObject, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<decimal> AverageRedbAsync<TField>(Expression<Func<IRedbObject, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TField?> MinRedbAsync<TField>(Expression<Func<IRedbObject, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TField?> MaxRedbAsync<TField>(Expression<Func<IRedbObject, TField>> selector) where TField : struct => throw new NotSupportedException();
    public Task<TResult> AggregateRedbAsync<TResult>(Expression<Func<IRedbObject, TResult>> selector) => throw new NotSupportedException();
    public IRedbGroupedQueryable<TKey, TProps> GroupBy<TKey>(Expression<Func<TProps, TKey>> keySelector) => throw new NotSupportedException();
    public IRedbGroupedQueryable<TKey, TProps> GroupByRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector) => throw new NotSupportedException();
    public IRedbGroupedQueryable<TKey, TItem> GroupByArray<TItem, TKey>(Expression<Func<TProps, IEnumerable<TItem>>> arraySelector, Expression<Func<TItem, TKey>> keySelector) where TItem : class, new() => throw new NotSupportedException();
    public IRedbWindowedQueryable<TProps> WithWindow(Action<IWindowSpec<TProps>> windowConfig) => throw new NotSupportedException();
    public string ToSqlString() => throw new NotSupportedException();
    public Task<string> ToSqlStringAsync() => throw new NotSupportedException();
    public Task<string> ToFilterJsonAsync() => throw new NotSupportedException();

    // IOrderedRedbQueryable
    public IOrderedRedbQueryable<TProps> ThenBy<TKey>(Expression<Func<TProps, TKey>> keySelector) => throw new NotSupportedException();
    public IOrderedRedbQueryable<TProps> ThenByDescending<TKey>(Expression<Func<TProps, TKey>> keySelector) => throw new NotSupportedException();
    public IOrderedRedbQueryable<TProps> ThenByRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector) => throw new NotSupportedException();
    public IOrderedRedbQueryable<TProps> ThenByDescendingRedb<TKey>(Expression<Func<IRedbObject, TKey>> keySelector) => throw new NotSupportedException();
}

/// <summary>
/// In-memory projected queryable for unit tests. Supports Distinct, Take, ToListAsync.
/// </summary>
internal class InMemoryRedbProjectedQueryable<TResult> : IRedbProjectedQueryable<TResult>
{
    private IEnumerable<TResult> _source;

    public InMemoryRedbProjectedQueryable(IEnumerable<TResult> source) => _source = source;

    public IRedbProjectedQueryable<TResult> Where(Expression<Func<TResult, bool>> predicate)
    {
        var compiled = predicate.Compile();
        return new InMemoryRedbProjectedQueryable<TResult>(_source.Where(compiled));
    }

    public IRedbProjectedQueryable<TResult> OrderBy<TKey>(Expression<Func<TResult, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbProjectedQueryable<TResult>(_source.OrderBy(compiled));
    }

    public IRedbProjectedQueryable<TResult> OrderByDescending<TKey>(Expression<Func<TResult, TKey>> keySelector)
    {
        var compiled = keySelector.Compile();
        return new InMemoryRedbProjectedQueryable<TResult>(_source.OrderByDescending(compiled));
    }

    public IRedbProjectedQueryable<TResult> Take(int count)
        => new InMemoryRedbProjectedQueryable<TResult>(_source.Take(count));

    public IRedbProjectedQueryable<TResult> Skip(int count)
        => new InMemoryRedbProjectedQueryable<TResult>(_source.Skip(count));

    public IRedbProjectedQueryable<TResult> Distinct()
        => new InMemoryRedbProjectedQueryable<TResult>(_source.Distinct());

    public Task<List<TResult>> ToListAsync()
        => Task.FromResult(_source.ToList());

    public Task<int> CountAsync()
        => Task.FromResult(_source.Count());

    public Task<TResult?> FirstOrDefaultAsync()
        => Task.FromResult(_source.FirstOrDefault());

    public Task<string> GetProjectionInfoAsync()
        => Task.FromResult("in-memory-projection");
}
