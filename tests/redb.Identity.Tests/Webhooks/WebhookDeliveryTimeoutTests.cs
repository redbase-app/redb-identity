using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Webhooks;

/// <summary>
/// A delivery waits for the subscriber no longer than the subscription's own timeoutMs, the value the
/// management API stores and returns; a subscriber that answers later is a failed attempt and the
/// retry policy of the subscription takes over.
/// </summary>
[Collection("ProductionHttp")]
public class WebhookDeliveryTimeoutTests
{
    private readonly ProductionHttpFixture _fx;

    public WebhookDeliveryTimeoutTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task ASubscriberThatAnswersLate_TimesOutAtTheSubscriptionsValue_AndIsRetried()
    {
        // The subscriber answers after four seconds; the subscription allows half a second.
        var answerDelay = TimeSpan.FromSeconds(4);
        await using var subscriber = new LateSubscriber(answerDelay);

        using var created = await SendAsync(HttpMethod.Post, "/api/v1/identity/webhooks", new
        {
            url = $"http://127.0.0.1:{subscriber.Port}/hook",
            displayName = "late-" + Guid.NewGuid().ToString("N")[..8],
            eventTypeFilter = "*",
            timeoutMs = 500,
            maxAttempts = 2,
            retryBackoffMs = 100,
        });
        var createdBody = await created.Content.ReadAsStringAsync();
        ((int)created.StatusCode).Should().BeInRange(200, 299, createdBody);
        var subscriptionId = JsonDocument.Parse(createdBody).RootElement.GetProperty("id").ToString();

        try
        {
            // Any management change emits an event; a new group is the simplest one.
            using var group = await SendAsync(HttpMethod.Post, "/api/v1/identity/groups",
                new { name = "webhook-timeout-" + Guid.NewGuid().ToString("N")[..12] });
            ((int)group.StatusCode).Should().BeInRange(200, 299, await group.Content.ReadAsStringAsync());

            // The second attempt of the same delivery must arrive well before the first could have been
            // answered: half a second of timeout plus a tenth of backoff, against four seconds.
            var second = await subscriber.WaitForAttemptAsync(attempt: 2, within: TimeSpan.FromSeconds(3));
            second.Should().NotBeNull("the first attempt must time out at 500 ms and be retried");

            var first = subscriber.Arrivals.First(a => a.DeliveryId == second!.DeliveryId && a.Attempt == 1);
            (second!.At - first.At).Should().BeLessThan(TimeSpan.FromSeconds(2.5));
        }
        finally
        {
            using var removed = await SendAsync(HttpMethod.Delete, $"/api/v1/identity/webhooks/{subscriptionId}", null);
        }
    }

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return _fx.Http.SendAsync(request);
    }

    private sealed record Arrival(string DeliveryId, int Attempt, TimeSpan At);

    /// <summary>A bare HTTP endpoint that records each request's delivery headers and answers late.</summary>
    private sealed class LateSubscriber : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly TimeSpan _answerDelay;

        public ConcurrentQueue<Arrival> Arrivals { get; } = new();
        public int Port { get; }

        public LateSubscriber(TimeSpan answerDelay)
        {
            _answerDelay = answerDelay;
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = AcceptAsync();
        }

        public async Task<Arrival?> WaitForAttemptAsync(int attempt, TimeSpan within)
        {
            var deadline = _clock.Elapsed + within;
            while (_clock.Elapsed < deadline)
            {
                if (Arrivals.FirstOrDefault(a => a.Attempt == attempt) is { } found) return found;
                await Task.Delay(50);
            }
            return null;
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _ = ServeAsync(client);
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var stream = client.GetStream();
                    var buffer = new byte[16 * 1024];
                    var read = 0;
                    string head;
                    do
                    {
                        var n = await stream.ReadAsync(buffer.AsMemory(read), _stop.Token);
                        if (n == 0) return;
                        read += n;
                        head = Encoding.ASCII.GetString(buffer, 0, read);
                    } while (!head.Contains("\r\n\r\n") && read < buffer.Length);

                    Arrivals.Enqueue(new Arrival(
                        Header(head, "X-RedbIdentity-Delivery") ?? "",
                        int.TryParse(Header(head, "X-RedbIdentity-Attempt"), out var attempt) ? attempt : 0,
                        _clock.Elapsed));

                    await Task.Delay(_answerDelay, _stop.Token);
                    var answer = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(answer, _stop.Token);
                }
                catch (OperationCanceledException) { }
                catch (IOException) { }
                catch (SocketException) { }
            }
        }

        private static string? Header(string head, string name)
        {
            foreach (var line in head.Split("\r\n"))
            {
                if (line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
                    return line[(name.Length + 1)..].Trim();
            }
            return null;
        }

        public ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            return ValueTask.CompletedTask;
        }
    }
}
