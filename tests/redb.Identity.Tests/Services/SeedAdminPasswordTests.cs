using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Security;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Security;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// <c>Identity:SeedAdmin:Password</c> on a database shared with the Tsak dashboard.
/// <para>
/// In cluster mode the dashboard signs in against the same <c>_users</c> table and, at its own start,
/// gives an admin with an empty password its configured password (admin/admin by default), BCrypt
/// hashed. It starts before <c>identity.core</c>, so the seeder used to find a non-empty password and
/// leave the default in place: the configured password never took effect. The seeder now replaces the
/// stored password while it is still the default, and leaves any other password alone.
/// </para>
/// Two service providers over one database: one with the plain BCrypt hasher writes the admin as the
/// dashboard does, the other with Identity's hasher runs the seeder.
/// </summary>
[Collection("PostgresCollection")]
public class SeedAdminPasswordTests : IAsyncLifetime
{
    private const string ConfiguredPassword = "Seed-Configured-42!";

    private ServiceProvider _dashboard = null!;
    private ServiceProvider _identity = null!;
    private IRedbService _dashboardRedb = null!;
    private IRedbService _identityRedb = null!;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var dashboardServices = new ServiceCollection();
        dashboardServices.AddSingleton<IPasswordHasher>(new BcryptPasswordHasher());
        dashboardServices.AddRedbForTests(pgCs);
        _dashboard = dashboardServices.BuildServiceProvider();
        _dashboardRedb = _dashboard.GetRequiredService<IRedbService>();
        await _dashboardRedb.InitializeAsync(ensureCreated: true);

        // Identity's hashing chain: Argon2id for new hashes, BCrypt still verified. Light Argon2id
        // parameters keep the test fast; the format is the same.
        var identityServices = new ServiceCollection();
        identityServices.AddSingleton<IPasswordHasher>(new MultiFormatPasswordHasher(
            new Argon2idPasswordHasher(memoryKib: 1024, iterations: 1, parallelism: 1),
            new BcryptPasswordHasher()));
        identityServices.AddRedbForTests(pgCs);
        _identity = identityServices.BuildServiceProvider();
        _identityRedb = _identity.GetRequiredService<IRedbService>();
        await _identityRedb.InitializeAsync(ensureCreated: true);
    }

    public async Task DisposeAsync()
    {
        await _identity.DisposeAsync();
        await _dashboard.DisposeAsync();
    }

    [Fact]
    public async Task The_configured_password_replaces_the_default_the_dashboard_wrote()
    {
        var login = await CreateAdminAsync(storedPassword: SeedAdminOptions.DefaultPassword);

        await RunSeederAsync(login);

        (await _identityRedb.UserProvider.ValidateUserAsync(login, ConfiguredPassword))
            .Should().NotBeNull("the stored password was still the default, so the configured one applies");
        (await _identityRedb.UserProvider.ValidateUserAsync(login, SeedAdminOptions.DefaultPassword))
            .Should().BeNull("the default must be gone");
    }

    [Fact]
    public async Task A_password_the_operator_changed_is_left_alone()
    {
        const string operatorPassword = "Operator-Changed-7!";
        var login = await CreateAdminAsync(storedPassword: operatorPassword);
        var hashBefore = (await _identityRedb.UserProvider.GetUserByLoginAsync(login))!.Password;

        await RunSeederAsync(login);

        (await _identityRedb.UserProvider.GetUserByLoginAsync(login))!.Password
            .Should().Be(hashBefore, "a password other than the default belongs to the operator");
        (await _identityRedb.UserProvider.ValidateUserAsync(login, operatorPassword))
            .Should().NotBeNull();
        (await _identityRedb.UserProvider.ValidateUserAsync(login, ConfiguredPassword))
            .Should().BeNull("the seed must not overwrite a changed password");
    }

    /// <summary>
    /// The dashboard's write: a user with a BCrypt-hashed password. A unique login stands in for
    /// <c>admin</c> so the shared test database keeps its own admin untouched.
    /// </summary>
    private async Task<string> CreateAdminAsync(string storedPassword)
    {
        var login = "seed_admin_" + Guid.NewGuid().ToString("N")[..8];
        var user = await _dashboardRedb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = "Initial-Pass-1234!",
            Name = login,
        });
        (await _dashboardRedb.UserProvider.SetPasswordAsync(user, storedPassword)).Should().BeTrue();

        (await _identityRedb.UserProvider.GetUserByLoginAsync(login))!.Password
            .Should().StartWith("$2", "the dashboard hashes with BCrypt");
        return login;
    }

    private Task RunSeederAsync(string login)
    {
        var options = Options.Create(new RedbIdentityOptions
        {
            SeedAdmin = new SeedAdminOptions { Enabled = true, Login = login, Password = ConfiguredPassword },
        });
        var seeder = new SeedAdminPasswordHostedService(
            _identity, options, NullLogger<SeedAdminPasswordHostedService>.Instance);
        return seeder.OnContextStarting(null!, CancellationToken.None);
    }
}
