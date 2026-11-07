using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Services;

/// <summary>
/// W6-0 — sister of <see cref="SeedWebClientHostedService"/>. Ensures the
/// <c>client_credentials</c> backchannel service-account OpenIddict application
/// exists on host startup. The Web BFF uses this account to publish
/// (<c>POST /api/v1/identity/revoked-sids</c>) and poll
/// (<c>GET /api/v1/identity/revoked-sids/since</c>) the cluster-wide revoked-sids
/// list for backchannel logout.
/// <para>
/// Behaviour:
/// <list type="bullet">
///   <item>No-op when <see cref="SeedBackchannelClientOptions.Enabled"/> is <c>false</c>.</item>
///   <item>No-op when the application already exists (idempotent across restarts).</item>
///   <item>Logs and skips when <see cref="SeedBackchannelClientOptions.ClientSecret"/> is empty —
///         <c>client_credentials</c> requires a confidential client (RFC 6749 §4.4).</item>
///   <item>Never throws — operators can always provision the client manually via the
///         management API.</item>
/// </list>
/// </para>
/// </summary>
public sealed class SeedBackchannelClientHostedService : IRouteLifecycleListener
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<SeedBackchannelClientHostedService> _logger;

    public SeedBackchannelClientHostedService(
        IServiceProvider serviceProvider,
        IOptions<RedbIdentityOptions> options,
        ILogger<SeedBackchannelClientHostedService> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task OnContextStarting(IRouteContext context, CancellationToken cancellationToken)
    {
        var seed = _options.Value.SeedBackchannelClient;
        if (!seed.Enabled)
        {
            _logger.LogDebug("SeedBackchannelClient disabled — skipping");
            return;
        }
        if (string.IsNullOrWhiteSpace(seed.ClientId))
        {
            _logger.LogWarning("SeedBackchannelClient enabled but ClientId is empty — skipping");
            return;
        }
        if (string.IsNullOrEmpty(seed.ClientSecret))
        {
            _logger.LogWarning(
                "SeedBackchannelClient enabled but ClientSecret is empty — client_credentials requires a confidential client. Skipping.");
            return;
        }

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var existing = await manager.FindByClientIdAsync(seed.ClientId, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                _logger.LogDebug(
                    "SeedBackchannelClient: client '{ClientId}' already exists — leaving untouched",
                    seed.ClientId);
                return;
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = seed.ClientId,
                ClientSecret = seed.ClientSecret,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = seed.DisplayName,
                ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
            };

            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            foreach (var s in seed.Scopes)
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + s);

            await manager.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "SeedBackchannelClient: registered backchannel service account '{ClientId}' with scopes [{Scopes}]",
                seed.ClientId, string.Join(", ", seed.Scopes));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "SeedBackchannelClient: unexpected failure while seeding client '{ClientId}'",
                _options.Value.SeedBackchannelClient.ClientId);
        }
    }
}
