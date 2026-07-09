using redb.Identity.Contracts.Mfa;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Http.Mfa;

/// <summary>
/// Phase 9e. <see cref="IMfaStateInspector"/> implementation backed by the cross-context
/// broker call to <c>direct-vm://identity-mfa-methods-from-state</c>.
/// <para>
/// Registered in the HTTP-facade child container when the host root has no Core inspector
/// (i.e. the .tpkg boot path). The synchronous interface is bridged to the async broker
/// via <see cref="ValueTask{TResult}.AsTask"/> + <c>GetAwaiter().GetResult()</c>; this
/// path runs only when rendering the MFA UI page, not on the verify hot path.
/// </para>
/// </summary>
public sealed class BrokeredMfaStateInspector : IMfaStateInspector
{
    private readonly IRouteContext _routeContext;
    private IProducerTemplate? _producer;
    private readonly object _producerLock = new();

    public BrokeredMfaStateInspector(IRouteContext routeContext)
    {
        _routeContext = routeContext ?? throw new ArgumentNullException(nameof(routeContext));
    }

    public string[]? TryGetMethods(string? protectedState)
    {
        if (string.IsNullOrEmpty(protectedState)) return null;

        try
        {
            var producer = EnsureProducer();
            var response = producer
                .RequestBody<MfaMethodsFromStateResponse>(
                    IdentityEndpoints.MfaMethodsFromState,
                    new MfaMethodsFromStateRequest { MfaState = protectedState })
                .GetAwaiter().GetResult();
            return response is { Success: true, Methods.Length: > 0 } ? response.Methods : null;
        }
        catch
        {
            // Mirrors Core MfaStateProtector behaviour: any decryption / transport
            // failure surfaces as «no known methods» — UI falls back to the TOTP form.
            return null;
        }
    }

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
