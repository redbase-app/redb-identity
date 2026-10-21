using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// RFC 8707 resource indicators: a <c>resource</c> parameter must name a resource the server knows.
/// <para>
/// OpenIddict 7 checks the parameter against the static <c>OpenIddictServerOptions.Resources</c> set
/// (<c>RegisterResources</c>). In redb.Identity the resources are the <c>Resources</c> of the scopes,
/// kept in redb and edited at runtime through the management API, so a set fixed at startup would go
/// stale. The static check is turned off (<c>DisableResourceValidation</c>) and these handlers take its
/// place, in its slot, against the scope store: a resource is known when at least one scope lists it.
/// </para>
/// <para>
/// The rest of OpenIddict's resource handling stays built in: the format check (absolute URI, no
/// fragment) and the client permission check (<c>rsrc:</c> + resource on the application).
/// </para>
/// </summary>
internal static class ValidateResourcesAgainstScopes
{
    internal static async ValueTask<bool> RejectUnknownAsync(
        BaseValidatingContext context, OpenIddictRequest request,
        IServiceProvider sp, ILogger logger)
    {
        var requested = request.GetResources();
        if (requested.IsDefaultOrEmpty)
            return false;

        // Degraded mode (no core, no stores: the unit-test and embedded configurations) has no scope
        // manager. With no scope store no resource is known, so a requested one is rejected.
        var scopes = sp.GetService<IOpenIddictScopeManager>();

        foreach (var resource in requested)
        {
            var known = false;
            if (scopes is not null)
            {
                await foreach (var _ in scopes.FindByResourceAsync(resource))
                {
                    known = true;
                    break;
                }
            }

            if (known)
                continue;

            logger.LogInformation("Rejected resource {Resource}: no scope lists it", resource);
            context.Reject(
                error: Errors.InvalidTarget,
                description: OpenIddictResources.FormatID2190(Parameters.Resource),
                uri: OpenIddictResources.FormatID8000(OpenIddictResources.ID2190));
            return true;
        }

        return false;
    }
}

/// <summary>Authorization endpoint slot of <see cref="ValidateResourcesAgainstScopes"/>.</summary>
internal sealed class ValidateAuthorizationResourcesHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<ValidateAuthorizationResourcesHandler> _logger;

    public ValidateAuthorizationResourcesHandler(IServiceProvider sp, ILogger<ValidateAuthorizationResourcesHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ValidateAuthorizationResourcesHandler>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateResources.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        await ValidateResourcesAgainstScopes.RejectUnknownAsync(context, context.Request, _sp, _logger);
    }
}

/// <summary>Pushed authorization endpoint slot of <see cref="ValidateResourcesAgainstScopes"/>.</summary>
internal sealed class ValidatePushedAuthorizationResourcesHandler : IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<ValidatePushedAuthorizationResourcesHandler> _logger;

    public ValidatePushedAuthorizationResourcesHandler(IServiceProvider sp, ILogger<ValidatePushedAuthorizationResourcesHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ValidatePushedAuthorizationRequestContext>()
            .UseScopedHandler<ValidatePushedAuthorizationResourcesHandler>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidatePushedResources.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        await ValidateResourcesAgainstScopes.RejectUnknownAsync(context, context.Request, _sp, _logger);
    }
}

/// <summary>Token endpoint (token exchange) slot of <see cref="ValidateResourcesAgainstScopes"/>.</summary>
internal sealed class ValidateTokenResourcesHandler : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<ValidateTokenResourcesHandler> _logger;

    public ValidateTokenResourcesHandler(IServiceProvider sp, ILogger<ValidateTokenResourcesHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<ValidateTokenResourcesHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateResources.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        await ValidateResourcesAgainstScopes.RejectUnknownAsync(context, context.Request, _sp, _logger);
    }
}
