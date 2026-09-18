using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// The gate at the entrance of every management, self-service and SCIM route: the exchange carries the
/// management context a facade attaches after validating a bearer, or it is refused.
/// <para>
/// The core routes are transport-agnostic and never see a token themselves. The HTTP, gRPC and SOAP
/// facades all take the same path: validate the bearer on <see cref="IdentityEndpoints.AuthManagement"/>
/// (<see cref="ManagementBearerAuthProcessor"/>), which leaves <c>identity:management-scopes</c> and
/// its siblings on the exchange, then forward. <c>direct-vm</c> is a transport like the others, not a
/// trust level: in a Tsak worker the registry is shared by every module in the process, so an exchange
/// that arrives without the context is not "internal and trusted" — nobody authenticated it. It is
/// refused here, before any business processor, idempotency cache or transaction sees it.
/// </para>
/// <para>
/// There is deliberately no in-process bypass and no option to declare one. A module that needs the
/// management surface obtains a context the way the facades do: a token (client credentials with the
/// scopes it needs) validated on <see cref="IdentityEndpoints.AuthManagement"/>. Trust is a property
/// of the exchange, established by that hop — never inferred from the transport, and never from the
/// absence of something.
/// </para>
/// <para>
/// The refusal is <see cref="ManagementProblem.Forbidden"/> — the same generic 403 every gate on this
/// surface produces — plus a warning on the security log naming the route and the operation, so a
/// caller reaching the core without a context is visible instead of silently admitted.
/// </para>
/// </summary>
internal sealed class RequireManagementContextProcessor : IProcessor
{
    /// <summary>Set by <see cref="ManagementBearerAuthProcessor"/> from the validated token's scopes.</summary>
    internal const string ScopesProperty = "identity:management-scopes";

    private readonly ILogger _logger;

    public RequireManagementContextProcessor(ILogger? logger = null)
        => _logger = logger ?? NullLogger.Instance;

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (exchange.Properties.TryGetValue(ScopesProperty, out var raw) && raw is string[] { Length: > 0 })
            return Task.CompletedTask;

        exchange.In.Headers.TryGetValue("operation", out var operation);
        _logger.LogWarning(
            "Management route reached without a management context and refused: route={RouteId} operation={Operation}. " +
            "The caller did not come through a facade. In-process callers obtain a context the same way the facades do: " +
            "validate a bearer on {AuthHop}.",
            exchange.RouteId, operation, IdentityEndpoints.AuthManagement);

        ManagementProblem.Forbidden(exchange, "The request carries no management authorization.");
        return Task.CompletedTask;
    }
}
