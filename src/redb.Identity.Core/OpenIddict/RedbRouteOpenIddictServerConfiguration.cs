using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Registers the redb.Route Extract/Apply handlers in the OpenIddict Server pipeline.
/// Single source of truth: <see cref="RedbRouteOpenIddictServerBuilderExtensions.HandlerDescriptors"/>.
/// </summary>
internal sealed class RedbRouteOpenIddictServerConfiguration
    : IPostConfigureOptions<OpenIddictServerOptions>
{
    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        foreach (var descriptor in RedbRouteOpenIddictServerBuilderExtensions.HandlerDescriptors)
            options.Handlers.Add(descriptor);

        // CRITICAL: OpenIddictServerDispatcher iterates options.Handlers in INSERTION
        // ORDER (per its source comment: "sorted during options initialization for
        // performance reasons"). It relies on the list being pre-sorted by Order; it
        // does NOT re-sort at dispatch time. Since our IPostConfigureOptions runs
        // AFTER OpenIddict's own (which sorted the 272 built-ins), we must re-sort
        // here, otherwise our handlers are appended to the tail and the dispatcher
        // will short-circuit (e.g. via Exchange.ApplyTokenResponse<ProcessSignInContext>
        // at order 500_000) long before reaching them.
        options.Handlers.Sort((a, b) => a.Order.CompareTo(b.Order));
    }
}
