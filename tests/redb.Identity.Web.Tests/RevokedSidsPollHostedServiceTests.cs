using System.Net;
using System.Net.Sockets;
using AwesomeAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Identity.Client.Backchannel;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Web.Configuration;
using redb.Identity.Web.Services;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// The revoked-SIDs poll while the Identity host is still starting: the full image starts the host and
/// the web server together, and the first poll used to land before the host answered, a warning on every
/// start and a minute until the next try.
/// </summary>
public sealed class RevokedSidsPollHostedServiceTests
{
    [Fact]
    public async Task A_host_still_starting_is_retried_soon_and_logged_without_a_warning()
    {
        var client = Substitute.For<IBackchannelIdentityClient>();
        var calls = 0;
        var answered = new TaskCompletionSource();
        client.GetRevokedSidsSinceAsync(Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                    throw new HttpRequestException("Connection refused", new SocketException((int)SocketError.ConnectionRefused));
                answered.TrySetResult();
                return Task.FromResult(new RevokedSidsSinceResponse());
            });
        var log = new ListLogger();
        var service = new RevokedSidsPollHostedService(client, new RevokedSidsCache(), Options(TimeSpan.FromMinutes(5)), log);

        await service.StartAsync(CancellationToken.None);
        var finished = await Task.WhenAny(answered.Task, Task.Delay(TimeSpan.FromSeconds(15)));
        await service.StopAsync(CancellationToken.None);

        finished.Should().Be(answered.Task, "the second try comes after the short bootstrap retry, not after the 5 minute interval");
        log.Entries.Should().NotContain(e => e.Level >= LogLevel.Warning);
        log.Entries.Should().Contain(e => e.Level == LogLevel.Information && e.Message.Contains("not reachable yet"));
    }

    [Fact]
    public void Only_a_failure_without_an_HTTP_answer_counts_as_unreachable()
    {
        RevokedSidsPollHostedService.IsUnreachable(new HttpRequestException("refused", new SocketException()))
            .Should().BeTrue();
        RevokedSidsPollHostedService.IsUnreachable(new HttpRequestException("denied", null, HttpStatusCode.Unauthorized))
            .Should().BeFalse("a refused secret is an answer and stays a warning");
        RevokedSidsPollHostedService.IsUnreachable(new InvalidOperationException("no token"))
            .Should().BeFalse();
    }

    private static IOptions<IdentityWebOptions> Options(TimeSpan interval)
    {
        var options = new IdentityWebOptions();
        options.BackchannelClient.ClientSecret = "backchannel-secret-for-the-test";
        options.RevokedSids.PollInterval = interval;
        return Microsoft.Extensions.Options.Options.Create(options);
    }

    private sealed class ListLogger : ILogger<RevokedSidsPollHostedService>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
                Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
