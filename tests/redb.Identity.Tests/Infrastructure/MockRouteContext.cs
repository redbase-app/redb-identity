using NSubstitute;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Route.Abstractions;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Creates a mock <see cref="IRouteContext"/> that resolves the given <see cref="IRedbService"/>
/// via <c>context.GetService&lt;IRedbService&gt;()</c> (used by <c>GetRedbService()</c> extension).
/// </summary>
internal static class MockRouteContext
{
    public static IRouteContext Create(IRedbService redb)
    {
        var context = Substitute.For<IRouteContext>();
        context.GetService<IRedbService>().Returns(redb);
        // NSubstitute auto-mocks interface return types — pin GetFromRegistry to null so
        // GetIdentityService falls through to the host SP instead of an empty auto-mocked scope.
        context.GetFromRegistry<IServiceScopeFactory>(Arg.Any<string>()).Returns((IServiceScopeFactory?)null);
        return context;
    }

    /// <summary>
    /// Creates a mock <see cref="IRouteContext"/> that also exposes a service provider via
    /// <c>context.GetServiceProvider()</c>. Use when the processor under test resolves
    /// additional services (e.g. <c>IOpenIddictApplicationManager</c>) from the SP.
    /// </summary>
    public static IRouteContext CreateWithServices(IRedbService redb, params (Type, object)[] services)
    {
        var context = Substitute.For<IRouteContext>();
        context.GetService<IRedbService>().Returns(redb);
        // NSubstitute auto-mocks interface return types — pin GetFromRegistry to null so
        // GetIdentityService falls through to the host SP instead of an empty auto-mocked scope.
        context.GetFromRegistry<IServiceScopeFactory>(Arg.Any<string>()).Returns((IServiceScopeFactory?)null);

        var sc = new ServiceCollection();
        sc.AddSingleton(redb);
        foreach (var (type, instance) in services)
            sc.AddSingleton(type, instance);
        var sp = sc.BuildServiceProvider();
        context.GetServiceProvider().Returns(sp);
        return context;
    }
}
