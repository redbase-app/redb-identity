using redb.Identity.Contracts.Endpoints;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Http.Endpoints;

/// <summary>
/// Phase 9e. Validates an unauthenticated <c>post_logout_redirect_uri</c> by issuing a
/// cross-context broker call to <c>direct-vm://identity-validate-post-logout</c>. Returns
/// true when at least one registered OAuth client lists the URI as a post-logout target.
/// <para>
/// Replaces the previous direct dependency on <see cref="OpenIddict.Abstractions.IOpenIddictApplicationManager"/>
/// in <c>HttpIdentityProcessors.HandlePostLogoutRedirect</c>; the validator is now passed
/// in as a delegate so the facade has zero knowledge of OpenIddict types.
/// </para>
/// </summary>
public sealed class BrokeredPostLogoutRedirectValidator
{
    private readonly IRouteContext _routeContext;
    private IProducerTemplate? _producer;
    private readonly object _producerLock = new();

    public BrokeredPostLogoutRedirectValidator(IRouteContext routeContext)
    {
        _routeContext = routeContext ?? throw new ArgumentNullException(nameof(routeContext));
    }

    public async Task<bool> IsAllowedAsync(string redirectUri, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(redirectUri)) return false;

        var producer = EnsureProducer();
        var response = await producer
            .RequestBody<ValidatePostLogoutRedirectResponse>(
                IdentityEndpoints.ValidatePostLogoutRedirect,
                new ValidatePostLogoutRedirectRequest { RedirectUri = redirectUri })
            .ConfigureAwait(false);
        return response?.Allowed ?? false;
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
