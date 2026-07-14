using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Carries the <see cref="IExchange"/> that a per-exchange Identity DI scope was opened for.
/// <para>
/// This is the missing link that lets everything inside the isolated Identity child container —
/// most importantly the OpenIddict stores (<c>RedbTokenStore</c>, <c>RedbAuthorizationStore</c>, …) —
/// write on the <b>same</b> <c>IRedbService</c>, and therefore the same DB connection, that a
/// route-level redb transaction was opened on.
/// </para>
/// <para>
/// <b>Why it is needed at all.</b> In the <c>.tpkg</c> topology the route-context host provider does
/// not carry Identity's registrations (that is the point of module isolation), so Identity resolves
/// its services from a child container. Until now every child scope also opened its <b>own</b> host
/// scope for <see cref="redb.Core.IRedbService"/> — a <b>second</b> connection. A route-level
/// transaction runs on the exchange-cached connection, so the stores were writing outside it: no
/// atomicity, and — because the second connection blocks on the row locks the first one holds while
/// the first awaits the call that opened the second — a deadlock that only cleared on the 30s
/// transaction timeout. See <c>doc/PERF_RULES.md</c>, rule 1.
/// </para>
/// <para>
/// Scoped. Set once by whoever opens the scope (see <c>IdentityRouteContextExtensions</c>), read by
/// <c>HostRedbScope</c>. Deliberately <b>not</b> an <c>AsyncLocal</c>: the scope is created
/// explicitly and lives for exactly one exchange, so an explicit holder is simpler, deterministic,
/// and cannot leak across tasks.
/// </para>
/// </summary>
internal sealed class IdentityExchangeAccessor
{
    /// <summary>
    /// The exchange this scope belongs to, or <c>null</c> when the scope was opened outside a route
    /// (hosted services, cleanup timers, schema init, diagnostics). In that case there is no
    /// ambient transaction to join and the caller falls back to its own host scope.
    /// </summary>
    public IExchange? Exchange { get; set; }
}
