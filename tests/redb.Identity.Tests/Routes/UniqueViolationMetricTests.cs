using System.Data.Common;
using System.Diagnostics.Metrics;
using AwesomeAssertions;
using redb.Core.Exceptions;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Routes;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// The README lists <c>identity.unique_violation</c> among the metrics. A unique violation that the
/// builder-level handlers turn into a 409 must add to it, tagged with what collided when that is known.
/// </summary>
public class UniqueViolationMetricTests
{
    [Fact]
    public void ATypedViolation_IsAnswered409_AndCountedWithItsSchemeAndProperty()
    {
        using var metrics = new IdentityMetrics();
        var seen = Listen(out var listener);
        using var _ = listener;

        var exchange = new Exchange(new Message())
        {
            Exception = new RedbUniqueViolationException(
                schemeId: 42, schemeName: "identity.application", structureId: 7, propertyName: "ClientId",
                constraintName: "UIX__values__structure_unique", detail: null,
                cause: new FakeDbException("duplicate key value violates unique constraint")),
        };

        IdentityCoreRouteBuilder.AnswerDuplicate(exchange, metrics);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(409);
        seen.Should().ContainSingle();
        seen[0].Value.Should().Be(1);
        seen[0].Tags["scheme"].Should().Be("identity.application");
        seen[0].Tags["column"].Should().Be("ClientId");
    }

    [Fact]
    public void ADriverViolationOfTheEmailIndex_IsCountedAsTheUsersEmail()
    {
        using var metrics = new IdentityMetrics();
        var seen = Listen(out var listener);
        using var _ = listener;

        var exchange = new Exchange(new Message())
        {
            Exception = new FakeDbException("duplicate key value violates unique constraint \"UX_users_email\""),
        };

        IdentityCoreRouteBuilder.AnswerDuplicate(exchange, metrics);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(409);
        seen.Should().ContainSingle();
        seen[0].Tags["scheme"].Should().Be("_users");
        seen[0].Tags["column"].Should().Be("_email");
    }

    [Fact]
    public void AViolationWhoseKeyIsNotKnown_IsStillCounted()
    {
        using var metrics = new IdentityMetrics();
        var seen = Listen(out var listener);
        using var _ = listener;

        var exchange = new Exchange(new Message())
        {
            Exception = new FakeDbException("duplicate key value violates unique constraint \"_users__login_key\""),
        };

        IdentityCoreRouteBuilder.AnswerDuplicate(exchange, metrics);

        seen.Should().ContainSingle();
        seen[0].Tags["scheme"].Should().Be("unknown");
        seen[0].Tags["column"].Should().Be("unknown");
    }

    private static List<(long Value, Dictionary<string, string?> Tags)> Listen(out MeterListener listener)
    {
        var seen = new List<(long, Dictionary<string, string?>)>();
        listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == IdentityMetrics.MeterName && instrument.Name == "identity.unique_violation")
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            var map = new Dictionary<string, string?>();
            foreach (var tag in tags) map[tag.Key] = tag.Value?.ToString();
            lock (seen) seen.Add((value, map));
        });
        listener.Start();
        return seen;
    }

    private sealed class FakeDbException(string message) : DbException(message);
}
