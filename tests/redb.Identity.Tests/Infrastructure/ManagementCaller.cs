using redb.Identity.Contracts.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Who a fixture stands in for when it sends straight to a core management route.
/// <para>
/// The core routes (<c>direct-vm://identity-manage-*</c>, <c>identity-me-*</c>, <c>identity-scim-*</c>,
/// <c>identity-revoked-sids</c>) never see a bearer token themselves: a facade validates it on the
/// <c>identity-auth-management</c> hop and forwards the exchange with the <c>identity:management-*</c>
/// properties attached. A fixture that sends to those routes directly is therefore playing the facade,
/// and has to say which caller it plays — the routes refuse an exchange that carries no management
/// context at all, whatever transport it arrived on.
/// </para>
/// </summary>
public enum ManagementCaller
{
    /// <summary>A facade that validated a bearer carrying <c>identity:manage</c>: may target any user.</summary>
    Admin,

    /// <summary>
    /// No management context at all — what an in-process caller that never went through a facade looks
    /// like. Only for tests that probe the gate itself.
    /// </summary>
    None,
}

public static class ManagementCallerContext
{
    public const string ScopesProperty = "identity:management-scopes";

    /// <summary>
    /// Attaches what <c>ManagementBearerAuthProcessor</c> would have attached for <paramref name="caller"/>.
    /// </summary>
    public static T Apply<T>(T exchange, ManagementCaller caller) where T : IExchange
    {
        switch (caller)
        {
            case ManagementCaller.Admin:
                exchange.Properties[ScopesProperty] = new[] { IdentityScopes.Manage };
                break;
            case ManagementCaller.None:
                exchange.Properties.Remove(ScopesProperty);
                break;
        }

        return exchange;
    }
}
