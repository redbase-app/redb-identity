using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using redb.Core.Models.Configuration;
using redb.Identity.Core;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Core.Configuration;
using redb.Postgres.Pro.Extensions;
using Xunit;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Configuration;

/// <summary>
/// G12 / A3 — production-mode signing-keys guard.
/// <para>
/// Verifies the bootstrap-time contract enforced in
/// <c>RedbIdentityServiceExtensions.AddRedbIdentityServer</c>:
/// <list type="bullet">
///   <item>If no signing credentials are configured AND
///         <see cref="RedbIdentityOptions.AllowEphemeralKeys"/> is <c>false</c>,
///         building the OpenIddict server options MUST throw — ephemeral keys split
///         the JWKS across cluster replicas and invalidate every live token on
///         restart, which is unacceptable in production.</item>
///   <item>The same configuration with <c>AllowEphemeralKeys = true</c> must succeed
///         (Development / test scenarios opt in explicitly).</item>
///   <item>Persistent <see cref="RedbIdentityOptions.SigningCredentials"/> always
///         succeed irrespective of the flag.</item>
/// </list>
/// </para>
/// <para>
/// We resolve <see cref="IOptionsMonitor{TOptions}"/> for
/// <see cref="OpenIddictServerOptions"/> because the OpenIddict configuration delegate
/// (which contains the throw) runs lazily at first options resolution, not at DI
/// container construction time.
/// </para>
/// </summary>
public sealed class SigningKeysBootstrapTests
{
    [Fact]
    public void NoSigningCreds_AllowEphemeralFalse_ThrowsAtBootstrap()
    {
        // The signing-keys throw fires inside the OpenIddict server-options builder
        // delegate, which OpenIddict invokes synchronously inside AddServer(...) — so
        // the exception surfaces at AddRedbIdentityServer call time (eager), not at
        // first IOptions resolution. We therefore wrap BuildIdentitySp itself.
        var act = () => BuildIdentitySp(new RedbIdentityOptions
        {
            AllowEphemeralKeys = false,
            DisableAccessTokenEncryption = true, // skip the parallel encryption-keys throw
            // SigningCredentials intentionally empty
        });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*ephemeral*",
                "production-mode bootstrap with no persistent signing credentials must " +
                "fail loudly per A3 — silently falling back to ephemeral keys would " +
                "split JWKS across cluster replicas (different kid per node).");
    }

    [Fact]
    public void NoSigningCreds_AllowEphemeralTrue_BootstrapSucceeds()
    {
        var sp = BuildIdentitySp(new RedbIdentityOptions
        {
            AllowEphemeralKeys = true,           // explicit dev opt-in
            DisableAccessTokenEncryption = true,
        });

        var act = () => sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        act.Should().NotThrow(
            "explicit AllowEphemeralKeys=true is the documented Development / test " +
            "opt-in and must succeed without persistent keys.");

        var opts = sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        opts.SigningCredentials.Should().NotBeEmpty(
            "ephemeral keys must still produce at least one signing credential so " +
            "the server can issue tokens in dev mode.");
    }

    [Fact]
    public void NoSigningCreds_EncryptionRequired_NoEphemeral_AlsoThrows()
    {
        // Symmetric guard: when access-token encryption is on AND no encryption creds
        // are configured AND ephemeral is disallowed, bootstrap must also fail rather
        // than silently degrading. Same eager-throw site as the signing variant.
        var act = () => BuildIdentitySp(new RedbIdentityOptions
        {
            AllowEphemeralKeys = false,
            DisableAccessTokenEncryption = false, // encryption required
        });

        act.Should().Throw<InvalidOperationException>(
            "production-mode access-token encryption without persistent encryption " +
            "credentials must fail at bootstrap (A3 symmetric guard).");
    }

    private static ServiceProvider BuildIdentitySp(RedbIdentityOptions opts)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // Identity bootstrap requires a redb backend. Use Postgres but with a fake
        // CS — we never resolve IRedbService in these tests, only OpenIddict server
        // options, so no DB connection is opened.
        services.AddRedbForTests("Host=127.0.0.1;Port=1;Database=fake;Username=fake;Password=fake");

        services.AddRedbIdentityServer(opts);
        return services.BuildServiceProvider();
    }
}
