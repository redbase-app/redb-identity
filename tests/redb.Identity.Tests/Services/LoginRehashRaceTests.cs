using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// The upgrade-on-login rehash against a password that changed underneath it.
/// <para>
/// The rehash runs detached, seconds after the login that scheduled it: Argon2id is slow by design,
/// <c>Task.Run</c> adds scheduling, the fresh scope adds a connection. An admin reset fits into that
/// window comfortably — and when the rehash lands last, it writes the <b>pre-login</b> password over
/// the freshly set one. The account silently reverts to exactly the credential the operator was
/// trying to retire, while the reset call has already answered success.
/// </para>
/// <para>
/// Found on a live worker: nine resets out of nine lost when a login preceded them, three of three
/// kept without one; every "lost" row still held the old hash. Not provider-specific — pure timing.
/// </para>
/// </summary>
[Collection("PostgresCollection")]
public class LoginRehashRaceTests : IAsyncLifetime
{
    private ServiceProvider _provider = null!;
    private IRedbService _redb = null!;

    public async Task InitializeAsync()
    {
        // Same connection source as every other provider-matrix test: appsettings.json
        // (REDB_POSTGRES_CS / REDB_PROVIDER still override inside AddRedbForTests). A hard-coded
        // fallback pointed at a database that exists on no machine and only went unnoticed because
        // the SQLite runs ignore the PostgreSQL string altogether.
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var services = new ServiceCollection();
        services.AddRedbForTests(pgCs);
        _provider = services.BuildServiceProvider();

        _redb = _provider.GetRequiredService<IRedbService>();
        await _redb.InitializeAsync(ensureCreated: true);
    }

    public async Task DisposeAsync() => await _provider.DisposeAsync();

    [Fact]
    public async Task A_rehash_scheduled_before_a_reset_must_not_undo_the_reset()
    {
        var login = "rehash_race_" + Guid.NewGuid().ToString("N")[..8];
        const string oldPassword = "OldOldPass1234!";
        const string newPassword = "NewNewPass5678!";

        var user = await _redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = oldPassword,
            Name = login,
        });

        // The login happened here: the hash the rehash task captured is the one stored right now.
        var hashAtLogin = (await _redb.UserProvider.GetUserByIdAsync(user.Id))!.Password;

        // The admin reset lands while the rehash is still queued.
        (await _redb.UserProvider.SetPasswordAsync(user, newPassword)).Should().BeTrue();

        // Now the detached rehash catches up, still holding the pre-login plaintext.
        var wrote = await LoginService.RehashPasswordIfUnchangedAsync(
            _redb, user.Id, oldPassword, hashAtLogin, logger: null);

        wrote.Should().BeFalse("the stored hash is no longer the one this login verified");

        // The observable truth, transport-independent: the new password authenticates, the old
        // one does not. Before the guard existed, both assertions failed at once.
        (await _redb.UserProvider.ValidateUserAsync(login, newPassword))
            .Should().NotBeNull("the admin reset must survive the rehash");
        (await _redb.UserProvider.ValidateUserAsync(login, oldPassword))
            .Should().BeNull("the retired password must stay retired");
    }

    /// <summary>
    /// The other half of the same guard: an untouched hash must still be rehashed — the guard may
    /// only stop the overwrite, not the upgrade itself.
    /// </summary>
    [Fact]
    public async Task An_unchanged_hash_is_still_rehashed()
    {
        var login = "rehash_ok_" + Guid.NewGuid().ToString("N")[..8];
        const string password = "OldOldPass1234!";

        var user = await _redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = password,
            Name = login,
        });

        var hashAtLogin = (await _redb.UserProvider.GetUserByIdAsync(user.Id))!.Password;

        var wrote = await LoginService.RehashPasswordIfUnchangedAsync(
            _redb, user.Id, password, hashAtLogin, logger: null);

        wrote.Should().BeTrue("nothing changed underneath, so the upgrade must proceed");
        (await _redb.UserProvider.ValidateUserAsync(login, password))
            .Should().NotBeNull("a rehash must never lock the user out");
    }
}
