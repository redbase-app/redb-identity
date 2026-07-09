
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Extensions;

namespace redb.Identity.Core.Serialization;

/// <summary>
/// Registers <see cref="IdentityCodecProfiles"/> into the route context's
/// <see cref="IDataFormatRegistry"/> at engine-start time.
/// <para>
/// Runs through the <see cref="IRouteContextConfigurator"/> pattern so the profile
/// registration happens <b>after</b> <see cref="RouteContext"/> has materialised its
/// internal service map (registry is context-local, not DI-resolved). Adding via
/// <c>services.AddSingleton&lt;IRouteContextConfigurator&gt;(...)</c> in
/// <c>AddRedbIdentityServer</c> is sufficient; no additional wiring required.
/// </para>
/// <para>
/// Only media-type-addressable profiles (<c>application/scim+json</c>,
/// <c>application/problem+json</c>) are registered. The OAuth profile
/// (<see cref="IdentityCodecProfiles.OAuthJson"/>) is invoked by callers directly to
/// insulate OAuth/OIDC wire format from app-level registry reconfiguration
/// (<c>ConfigureJsonCodec</c> must never affect RFC 6749 responses).
/// </para>
/// </summary>
internal sealed class IdentityCodecProfilesConfigurator : IRouteContextConfigurator
{
    public void Configure(RouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var registry = context.GetService<IDataFormatRegistry>()
            ?? throw new InvalidOperationException(
                "IDataFormatRegistry is not available on the route context. " +
                "Ensure redb.Route is registered before redb.Identity.");

        IdentityCodecProfiles.RegisterInto(registry);
    }
}
