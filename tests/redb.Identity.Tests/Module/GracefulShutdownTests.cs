using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Module;

/// <summary>
/// F2 — graceful shutdown contract for the Identity route context.
/// </summary>
public class GracefulShutdownTests
{
    [Fact]
    public async Task ContextStop_InvokesStoppingThenStopped_OnAllListeners()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        await using var ctx = new RouteContext(sp, "graceful-shutdown-test");

        var listener = Substitute.For<IRouteLifecycleListener>();
        ctx.AddLifecycleListener(listener);

        await ctx.Start();
        ctx.IsStarted.Should().BeTrue();

        await ctx.Stop();

        Received.InOrder(() =>
        {
            listener.OnContextStopping(ctx, Arg.Any<CancellationToken>());
            listener.OnContextStopped(ctx, Arg.Any<CancellationToken>());
        });
    }

    [Fact]
    public async Task ContextStop_PropagatesProvidedCancellationToken()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        await using var ctx = new RouteContext(sp, "graceful-shutdown-ct-test");

        CancellationToken capturedStopping = default;
        CancellationToken capturedStopped = default;
        var listener = Substitute.For<IRouteLifecycleListener>();
        listener.OnContextStopping(Arg.Any<IRouteContext>(), Arg.Do<CancellationToken>(t => capturedStopping = t))
                .Returns(Task.CompletedTask);
        listener.OnContextStopped(Arg.Any<IRouteContext>(), Arg.Do<CancellationToken>(t => capturedStopped = t))
                .Returns(Task.CompletedTask);
        ctx.AddLifecycleListener(listener);

        await ctx.Start();

        using var cts = new CancellationTokenSource();
        await ctx.Stop(cts.Token);

        capturedStopping.Should().Be(cts.Token);
        capturedStopped.Should().Be(cts.Token);
    }

    [Fact]
    public async Task ContextStop_WhenListenerThrows_StillStops()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        await using var ctx = new RouteContext(sp, "graceful-shutdown-throw-test");

        var crashing = Substitute.For<IRouteLifecycleListener>();
        crashing.OnContextStopping(Arg.Any<IRouteContext>(), Arg.Any<CancellationToken>())
                .Returns<Task>(_ => throw new InvalidOperationException("boom"));

        ctx.AddLifecycleListener(crashing);

        await ctx.Start();

        try
        {
            await ctx.Stop();
        }
        catch (InvalidOperationException)
        {
        }

        ctx.IsStarted.Should().BeFalse();
    }
}