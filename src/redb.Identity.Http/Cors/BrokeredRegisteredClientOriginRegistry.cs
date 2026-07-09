using System.Collections.Immutable;
using redb.Identity.Contracts.Cors;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Http.Cors;

/// <summary>
/// Phase 9e. <see cref="IRegisteredClientOriginRegistry"/> implementation backed by
/// the cross-context broker call to <c>direct-vm://identity-cors-check</c>.
/// <para>
/// Registered in the HTTP-facade child container when the host root has no Core registry
/// (i.e. the .tpkg boot path of <see cref="redb.Identity.Http.Module.IdentityHttpModuleHost"/>).
/// In test-fixture mode the Core registry is reachable via DI and the bridge is bypassed.
/// </para>
/// <para>
/// <b>Design notes:</b>
/// <list type="bullet">
///   <item><see cref="GetAllowedOriginsAsync"/> returns an empty set — the snapshot lives
///   in Core and is never materialised on the Http side. Diagnostics callers must hit
///   Core directly via the management API.</item>
///   <item><see cref="Invalidate"/> is a no-op — Core invalidates its own snapshot on
///   application mutations; the broker call always sees the freshest data.</item>
///   <item>No client-side cache (per Phase 9 §3 decision: MVP without cache; add TTL +
///   invalidation broadcast in Phase 10).</item>
/// </list>
/// </para>
/// </summary>
public sealed class BrokeredRegisteredClientOriginRegistry : IRegisteredClientOriginRegistry
{
    private readonly IRouteContext _routeContext;
    private IProducerTemplate? _producer;
    private readonly object _producerLock = new();

    public BrokeredRegisteredClientOriginRegistry(IRouteContext routeContext)
    {
        _routeContext = routeContext ?? throw new ArgumentNullException(nameof(routeContext));
    }

    public async ValueTask<bool> IsAllowedAsync(string? origin, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(origin)) return false;

        var producer = EnsureProducer();
        var response = await producer
            .RequestBody<CorsCheckResponse>(IdentityEndpoints.CorsCheck, new CorsCheckRequest { Origin = origin })
            .ConfigureAwait(false);
        return response?.Allowed ?? false;
    }

    public ValueTask<ImmutableHashSet<string>> GetAllowedOriginsAsync(CancellationToken ct = default)
        => new(ImmutableHashSet<string>.Empty);

    public void Invalidate() { /* no-op: Core owns the snapshot */ }

    private IProducerTemplate EnsureProducer()
    {
        if (_producer is { IsStarted: true }) return _producer;
        lock (_producerLock)
        {
            if (_producer is { IsStarted: true }) return _producer;
            var p = new ProducerTemplate(_routeContext);
            p.Start();
            _producer = p;
            return _producer;
        }
    }
}
