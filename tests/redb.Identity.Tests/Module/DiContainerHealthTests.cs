using System;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Postgres.Pro.Extensions;
using redb.Route.Components;
using redb.Route.Core;
using Xunit;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Module;

/// <summary>
/// E7 — DI lifetimes audit. Locks the contract that the production Identity
/// bootstrap (<see cref="RedbIdentityServiceExtensions.AddRedbIdentityServer"/>) is
/// free of captive dependencies — <see cref="ServiceProviderOptions.ValidateOnBuild"/>
/// instantiates one of every registered service through a probe scope and throws
/// <see cref="AggregateException"/> if any Singleton's constructor pulls a Scoped
/// service. Without this guard a captive-dep regression slips in silently and
/// only manifests as request-pipeline state corruption under load.
/// </summary>
public class DiContainerHealthTests
{
    [Fact]
    public void AddRedbIdentityServer_HasNoCaptiveDependencies()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        // Same connection-string lookup as ProductionBootstrapFixture. Falls back to a
        // dummy DSN if Postgres is unreachable — ValidateOnBuild does NOT open the
        // connection, so the actual DSN doesn't matter for DI graph validation.
        var config = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var cs = "Host=localhost;Port=1;Database=fake;Username=fake;Password=fake";
        services.AddRedbForTests(cs);
        services.AddSingleton<SharedVmRegistry>();

        var options = new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test.local/"),
            AllowEphemeralKeys = true,
        };
        services.AddSingleton(Options.Create(options));
        services.AddRedbIdentityServer(options);

        // The act: BuildServiceProvider with ValidateOnBuild=true. Throws AggregateException
        // listing every service whose ctor cannot be satisfied — captive deps, missing
        // registrations, ambiguous overloads.
        var act = () => services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        act.Should().NotThrow("AddRedbIdentityServer must be free of captive dependencies");
    }
}
