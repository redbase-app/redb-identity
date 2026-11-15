using System.Collections.Concurrent;
using System.Transactions;
using redb.Core;
using redb.Identity.Core.Security;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Wraps the password history store of the production fixture and refuses the overloads that open a scope of
/// their own while an ambient transaction is active, that is, inside a transacted route. In a deployment that
/// scope's connection is a second one inside the route's transaction, which promotes it to a distributed
/// transaction, and stock PostgreSQL (max_prepared_transactions = 0) refuses it. In this test host the second
/// connection does not show, so the rule is checked here instead of by the database.
/// </summary>
public sealed class InRouteTransactionHistoryStoreGuard(IPasswordHistoryStore inner) : IPasswordHistoryStore
{
    /// <summary>Every refused call, also those a caller swallowed (history recording does).</summary>
    public static ConcurrentQueue<string> Violations { get; } = new();

    public Task<bool> IsRecentlyUsedAsync(long userId, string password, int count, CancellationToken ct)
    {
        Refuse(nameof(IsRecentlyUsedAsync));
        return inner.IsRecentlyUsedAsync(userId, password, count, ct);
    }

    public Task<bool> IsRecentlyUsedAsync(IRedbService redb, long userId, string password, int count, CancellationToken ct)
        => inner.IsRecentlyUsedAsync(redb, userId, password, count, ct);

    public Task RecordAsync(long userId, string password, int keep, CancellationToken ct)
    {
        Refuse(nameof(RecordAsync));
        return inner.RecordAsync(userId, password, keep, ct);
    }

    private static void Refuse(string method)
    {
        if (Transaction.Current is null) return;
        var message = $"IPasswordHistoryStore.{method} without the exchange's IRedbService inside a route transaction";
        Violations.Enqueue(message);
        throw new InvalidOperationException(message);
    }
}
