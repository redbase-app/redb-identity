using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Services;

/// <summary>
/// Startup seeder that ensures the canonical Web Console OIDC client (default
/// <c>identity-web</c>) exists in the OpenIddict application store. Sister to
/// <see cref="SeedAdminPasswordHostedService"/> — together they make a fresh
/// install runnable end-to-end with no manual bootstrap step:
/// <list type="bullet">
///   <item><see cref="SeedAdminPasswordHostedService"/> hashes the default
///   password for the seeded <c>admin</c> user.</item>
///   <item>This service registers the OIDC client so the Web BFF can complete
///   <c>/connect/authorize</c>.</item>
/// </list>
/// Behaviour:
/// <list type="bullet">
///   <item>Resolves <see cref="IOpenIddictApplicationManager"/> via a transient scope.</item>
///   <item>Looks up the client by <see cref="SeedWebClientOptions.ClientId"/>.</item>
///   <item>If found → no-op (idempotent across restarts; respects clients
///   created by bootstrap-admin / dynamic registration / management API).</item>
///   <item>Otherwise creates a Public client (or Confidential when a
///   <see cref="SeedWebClientOptions.ClientSecret"/> is supplied) with
///   <c>authorization_code</c> + <c>refresh_token</c> + PKCE-required.</item>
/// </list>
/// Convenience for fresh dev/demo deployments only — production should disable
/// this and provision clients explicitly via the management API.
/// <para>
/// Implemented as an <see cref="IRouteLifecycleListener"/> hooked into
/// <see cref="IRouteLifecycleListener.OnContextStarting"/> — Tsak modules have
/// no generic <c>IHost</c>, so route-context lifecycle is the canonical startup
/// extension point.
/// </para>
/// </summary>
public sealed class SeedWebClientHostedService : IRouteLifecycleListener
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<SeedWebClientHostedService> _logger;

    public SeedWebClientHostedService(
        IServiceProvider serviceProvider,
        IOptions<RedbIdentityOptions> options,
        ILogger<SeedWebClientHostedService> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task OnContextStarting(IRouteContext context, CancellationToken cancellationToken)
    {
        var seed = _options.Value.SeedWebClient;
        if (!seed.Enabled)
        {
            _logger.LogDebug("SeedWebClient disabled — skipping default OIDC client seeding");
            return;
        }

        if (string.IsNullOrWhiteSpace(seed.ClientId))
        {
            _logger.LogWarning("SeedWebClient enabled but ClientId is empty — skipping");
            return;
        }

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var existing = await manager
                .FindByClientIdAsync(seed.ClientId, cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null)
            {
                _logger.LogDebug(
                    "SeedWebClient: OIDC client '{ClientId}' already exists — leaving untouched",
                    seed.ClientId);
                return;
            }

            var isPublic = string.IsNullOrEmpty(seed.ClientSecret);
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = seed.ClientId,
                ClientSecret = isPublic ? null : seed.ClientSecret,
                ClientType = isPublic
                    ? OpenIddictConstants.ClientTypes.Public
                    : OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = seed.DisplayName,
                ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
            };

            foreach (var uri in seed.RedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                    descriptor.RedirectUris.Add(parsed);
                else
                    _logger.LogWarning("SeedWebClient: skipping invalid RedirectUri '{Uri}'", uri);
            }

            foreach (var uri in seed.PostLogoutRedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                    descriptor.PostLogoutRedirectUris.Add(parsed);
                else
                    _logger.LogWarning("SeedWebClient: skipping invalid PostLogoutRedirectUri '{Uri}'", uri);
            }

            // Endpoint + grant + response permissions required for code+PKCE+refresh.
            var permissions = new List<string>
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
            };

            // Map scope names to the appropriate OpenIddict permission constants.
            // Standard OIDC scopes have dedicated permission constants; everything
            // else goes through the generic Scope: prefix.
            foreach (var s in seed.Scopes)
            {
                var perm = s switch
                {
                    "openid"         => OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                    "profile"        => OpenIddictConstants.Permissions.Scopes.Profile,
                    "email"          => OpenIddictConstants.Permissions.Scopes.Email,
                    "roles"          => OpenIddictConstants.Permissions.Scopes.Roles,
                    "phone"          => OpenIddictConstants.Permissions.Scopes.Phone,
                    "address"        => OpenIddictConstants.Permissions.Scopes.Address,
                    "offline_access" => OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                    _                => OpenIddictConstants.Permissions.Prefixes.Scope + s,
                };
                permissions.Add(perm);
            }

            foreach (var p in permissions)
                descriptor.Permissions.Add(p);

            // PKCE is mandatory for public clients (and best-practice for confidential).
            descriptor.Requirements.Add(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);

            await manager.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "SeedWebClient: registered OIDC client '{ClientId}' ({ClientType}) with {RedirectCount} redirect uri(s) and scopes [{Scopes}]",
                seed.ClientId,
                isPublic ? "public" : "confidential",
                seed.RedirectUris.Count,
                string.Join(", ", seed.Scopes));
        }
        catch (Exception ex)
        {
            // Never fail host startup over the convenience seeder. Operators can
            // always provision the client manually via the management API or the
            // bootstrap-admin endpoint.
            _logger.LogError(ex,
                "SeedWebClient: unexpected failure while seeding OIDC client '{ClientId}'",
                _options.Value.SeedWebClient.ClientId);
        }
    }
}
