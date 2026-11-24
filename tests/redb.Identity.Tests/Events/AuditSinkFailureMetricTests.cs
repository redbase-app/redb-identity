using System.Diagnostics.Metrics;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Events;

/// <summary>
/// An audit row that could not be written does not stop the event, but it must not vanish into a log
/// line either: the failure is counted on the Identity meter, tagged with the event type.
/// </summary>
public class AuditSinkFailureMetricTests
{
    [Fact]
    public async Task AFailedAuditWrite_IsCounted_AndTheEventGoesOn()
    {
        var failures = new List<(long Value, string? EventType)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == IdentityMetrics.MeterName && instrument.Name == "identity.audit.write_failures")
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            string? eventType = null;
            foreach (var tag in tags)
                if (tag.Key == "event_type") eventType = tag.Value?.ToString();
            lock (failures) failures.Add((value, eventType));
        });

        // A host with the Identity meter and no redb at all: the write cannot succeed.
        var services = new ServiceCollection();
        services.AddSingleton<IdentityMetrics>();
        await using var provider = services.BuildServiceProvider();
        listener.Start();

        await using var context = new RouteContext(provider, "audit-sink-failure");
        var processor = new AuditRelationalSinkProcessor(context, NullLogger.Instance);

        var exchange = new Exchange(new Message());
        exchange.Out = new Message();
        exchange.Out.Headers["event_type"] = "UserCreated";

        var act = async () => await processor.Process(exchange);

        await act.Should().NotThrowAsync("audit persistence must never stop the originating flow");
        lock (failures)
        {
            failures.Should().ContainSingle();
            failures[0].Value.Should().Be(1);
            failures[0].EventType.Should().Be("UserCreated");
        }
    }
}
