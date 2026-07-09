using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Exposes the configuration methods for the redb.Route OpenIddict Server host adapter.
/// Obtained via <see cref="RedbRouteOpenIddictServerBuilderExtensions.UseRedbRoute"/>.
/// </summary>
public sealed class RedbRouteOpenIddictServerBuilder
{
    public RedbRouteOpenIddictServerBuilder(OpenIddictServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        Builder = builder;
    }

    /// <summary>
    /// Gets the underlying <see cref="OpenIddictServerBuilder"/>.
    /// </summary>
    public OpenIddictServerBuilder Builder { get; }

    /// <summary>
    /// Disables the transport security (HTTPS) requirement.
    /// Should only be used in development or when TLS is terminated at a reverse proxy.
    /// </summary>
    public RedbRouteOpenIddictServerBuilder DisableTransportSecurityRequirement()
    {
        Builder.Services.Configure<RedbRouteOpenIddictServerOptions>(
            options => options.DisableTransportSecurityRequirement = true);
        return this;
    }
}
