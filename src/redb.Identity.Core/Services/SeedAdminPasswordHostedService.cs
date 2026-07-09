using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Services;

/// <summary>
/// Startup seeder that ensures the well-known <c>admin</c> user from the base
/// redb SQL seed (<c>_users.id = 1</c>, <c>login = "admin"</c>, empty password)
/// has a usable password on a fresh install. Behaviour:
/// <list type="bullet">
///   <item>Resolves <see cref="IRedbService"/> through a transient scope.</item>
///   <item>Looks up user by <see cref="SeedAdminOptions.Login"/>.</item>
///   <item>If the user is <b>missing</b> or already has a non-empty password →
///   no-op (idempotent across restarts and respects passwords set via
///   bootstrap-admin / management API).</item>
///   <item>Otherwise hashes <see cref="SeedAdminOptions.Password"/> via the
///   configured <see cref="redb.Core.Security.IPasswordHasher"/> chain and
///   persists it via <see cref="redb.Core.Providers.IUserProvider.SetPasswordAsync"/>.</item>
/// </list>
/// Always logs a loud <c>WARNING</c> on startup when the configured password is
/// the documented default <c>admin</c>, regardless of whether a write was needed.
/// <para>
/// Implemented as an <see cref="IRouteLifecycleListener"/> hooked into
/// <see cref="IRouteLifecycleListener.OnContextStarting"/> rather than an
/// <c>IHostedService</c> because Tsak hosts modules without a generic <c>IHost</c>;
/// route-context lifecycle hooks are the canonical startup extension point and
/// fire on every cold-start AND on every hot-reload of the .tpkg module.
/// </para>
/// </summary>
public sealed class SeedAdminPasswordHostedService : IRouteLifecycleListener
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<SeedAdminPasswordHostedService> _logger;

    public SeedAdminPasswordHostedService(
        IServiceProvider serviceProvider,
        IOptions<RedbIdentityOptions> options,
        ILogger<SeedAdminPasswordHostedService> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task OnContextStarting(IRouteContext context, CancellationToken cancellationToken)
    {
        var seed = _options.Value.SeedAdmin;
        if (!seed.Enabled)
        {
            _logger.LogDebug("SeedAdmin disabled — skipping default-password seeding");
            return;
        }

        if (string.IsNullOrWhiteSpace(seed.Login) || string.IsNullOrEmpty(seed.Password))
        {
            _logger.LogWarning(
                "SeedAdmin enabled but Login/Password is empty — skipping (login='{Login}')",
                seed.Login);
            return;
        }

        WarnIfDefaultPassword(seed);

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

            var user = await redb.UserProvider.GetUserByLoginAsync(seed.Login).ConfigureAwait(false);
            if (user is null)
            {
                _logger.LogInformation(
                    "SeedAdmin: user '{Login}' not found in _users — nothing to seed",
                    seed.Login);
                return;
            }

            if (!string.IsNullOrEmpty(user.Password))
            {
                _logger.LogDebug(
                    "SeedAdmin: user '{Login}' (id={Id}) already has a stored password — leaving untouched",
                    seed.Login, user.Id);
                return;
            }

            var ok = await redb.UserProvider
                .SetPasswordAsync(user, seed.Password, currentUser: user)
                .ConfigureAwait(false);

            if (ok)
            {
                _logger.LogInformation(
                    "SeedAdmin: hashed and stored default password for user '{Login}' (id={Id})",
                    seed.Login, user.Id);
            }
            else
            {
                _logger.LogWarning(
                    "SeedAdmin: SetPasswordAsync returned false for user '{Login}' (id={Id})",
                    seed.Login, user.Id);
            }
        }
        catch (Exception ex)
        {
            // Never fail host startup over the convenience seeder. Worst case: the
            // operator hits the bootstrap-admin endpoint or sets the password manually.
            _logger.LogError(ex,
                "SeedAdmin: unexpected failure while seeding password for user '{Login}'",
                seed.Login);
        }
    }

    private void WarnIfDefaultPassword(SeedAdminOptions seed)
    {
        if (!string.Equals(seed.Password, SeedAdminOptions.DefaultPassword, StringComparison.Ordinal))
            return;

        _logger.LogWarning(
            "============================================================");
        _logger.LogWarning(
            "  SECURITY WARNING: SeedAdmin password for '{Login}' is the");
        _logger.LogWarning(
            "  documented default ('admin'). This is intended for FRESH");
        _logger.LogWarning(
            "  development installs only. Rotate it via the management API");
        _logger.LogWarning(
            "  or set Identity:SeedAdmin:Password before exposing this");
        _logger.LogWarning(
            "  host to untrusted networks.");
        _logger.LogWarning(
            "============================================================");
    }
}
