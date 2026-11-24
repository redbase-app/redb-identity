using AwesomeAssertions;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Every operation of <see cref="IdempotencySecretOperations.All"/>, against the database of the fixture: the first
/// answer, which carries the secret, is recorded without its body, and a second call with the same key gets
/// <c>{"replayed":true,"secretWithheld":true,...}</c> instead of the secret, without running the operation again. An
/// operation off the list still has its answer stored and replayed as before.
/// </summary>
[Collection("ProductionHttp")]
public class IdempotencySecretOperationsTests
{
    private const string Secret = "one-time-secret-value-7f3a";

    private readonly ProductionHttpFixture _fx;

    public IdempotencySecretOperationsTests(ProductionHttpFixture fx) => _fx = fx;

    public static TheoryData<string, string> SecretOperations()
    {
        var data = new TheoryData<string, string>();
        foreach (var (scope, operation) in IdempotencySecretOperations.All)
            data.Add(scope, operation);
        return data;
    }

    [Theory]
    [MemberData(nameof(SecretOperations))]
    public async Task The_answer_is_neither_stored_nor_replayed(string scope, string operation)
    {
        var key = "secret-" + Guid.NewGuid().ToString("N");

        var first = await RunAsync(scope, operation, key);
        first.BusinessRan.Should().BeTrue();

        var record = await RecordAsync(scope, operation, key);
        record.SecretWithheld.Should().BeTrue();
        record.ResponseBody.Should().BeNull("the answer carried a one-time secret");

        var second = await RunAsync(scope, operation, key);
        second.BusinessRan.Should().BeFalse("a repeat does not run the operation again");
        second.Replayed.Should().BeTrue();
        var body = second.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["secretWithheld"].Should().Be(true);
        body["replayed"].Should().Be(true);
        body.Values.Should().NotContain(Secret);
    }

    [Fact]
    public async Task An_operation_off_the_list_is_stored_and_replayed_as_before()
    {
        var key = "plain-" + Guid.NewGuid().ToString("N");

        await RunAsync("manage-apps", "update", key);
        var record = await RecordAsync("manage-apps", "update", key);
        record.SecretWithheld.Should().BeFalse();
        record.ResponseBody.Should().Contain(Secret);

        var second = await RunAsync("manage-apps", "update", key);
        second.BusinessRan.Should().BeFalse();
        second.Replayed.Should().BeTrue();
        second.Body.ToString().Should().Contain(Secret);
    }

    private async Task<(bool BusinessRan, bool Replayed, object? Body)> RunAsync(string scope, string operation, string key)
    {
        var context = new RouteContext(_fx.ServiceProvider, "idempotency-secret-test");
        var options = new IdempotencyOptions { Enabled = true };

        var exchange = new Exchange(new Message { Body = new Dictionary<string, object?>() });
        exchange.In.Headers["Idempotency-Key"] = key;
        exchange.In.Headers["operation"] = operation;
        exchange.Properties["identity:management-subject"] = "idempotency-secret-admin";

        await new IdempotencyProcessor(context, null, scope, options).Process(exchange);
        if (exchange.Properties.TryGetValue("idempotency:cache-hit", out var hit) && hit is true)
        {
            var replayed = exchange.Out!.Headers.TryGetValue("Idempotency-Replayed", out var r) && r as string == "true";
            return (false, replayed, exchange.Out.Body);
        }

        // The business step: an answer that carries the secret.
        exchange.Out = new Message { Body = new Dictionary<string, object?> { ["id"] = 1, ["secret"] = Secret } };
        await new IdempotencyCaptureProcessor(context, null, options).Process(exchange);
        return (true, false, exchange.Out.Body);
    }

    private Task<IdempotencyRecordProps> RecordAsync(string scope, string operation, string key) => _fx.UseRedbAsync(async redb =>
    {
        var records = await redb.Query<IdempotencyRecordProps>()
            .Where(p => p.IdempotencyKey == key)
            .ToListAsync();
        return records.Should().ContainSingle(r => r.Props.Scope == scope && r.Props.Operation == operation).Subject.Props;
    });
}
