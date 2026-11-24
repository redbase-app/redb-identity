using AwesomeAssertions;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Cleanup;

/// <summary>
/// The cleanup of expired idempotency records against the database of the fixture (SQLite, PostgreSQL or SQL Server
/// by REDB_PROVIDER): records past their time to live go, live ones stay, a run goes batch after batch, a dry run
/// counts and removes nothing, and a record stored the old way with a secret in its body goes once it expires.
/// </summary>
[Collection("ProductionHttp")]
public class IdempotencyRecordCleanupTests
{
    private readonly ProductionHttpFixture _fx;

    public IdempotencyRecordCleanupTests(ProductionHttpFixture fx) => _fx = fx;

    private static System.Text.Json.JsonElement Json(object? body) => System.Text.Json.JsonSerializer.SerializeToElement(body);

    [Fact]
    public async Task Expired_records_go_batch_after_batch_and_live_ones_stay()
    {
        var tag = Guid.NewGuid().ToString("N")[..10];
        var expired = Enumerable.Range(0, 5).Select(i => $"{tag}-expired-{i}").ToList();
        var live = Enumerable.Range(0, 2).Select(i => $"{tag}-live-{i}").ToList();
        foreach (var key in expired) await StoreAsync(key, TimeSpan.FromMinutes(-5), """{"success":true}""");
        foreach (var key in live) await StoreAsync(key, TimeSpan.FromHours(1), """{"success":true}""");

        var result = await RunAsync(batchSize: 2, dryRun: false);

        Json(result).GetProperty("prunedIdempotencyRecords").GetInt32()
            .Should().BeGreaterThanOrEqualTo(5, "five expired records of this test, in three batches of two");
        (await KeysLeftAsync(tag)).Should().BeEquivalentTo(live);
    }

    [Fact]
    public async Task A_dry_run_counts_the_expired_records_and_removes_nothing()
    {
        var tag = Guid.NewGuid().ToString("N")[..10];
        await StoreAsync($"{tag}-expired-0", TimeSpan.FromMinutes(-5), """{"success":true}""");
        await StoreAsync($"{tag}-expired-1", TimeSpan.FromMinutes(-5), """{"success":true}""");

        var preview = Json(await RunAsync(batchSize: 500, dryRun: true));

        preview.GetProperty("dryRun").GetBoolean().Should().BeTrue();
        preview.GetProperty("wouldPruneIdempotencyRecords").GetInt32().Should().BeGreaterThanOrEqualTo(2);
        (await KeysLeftAsync(tag)).Should().HaveCount(2, "a dry run changes nothing");
        await RunAsync(batchSize: 500, dryRun: false);
    }

    [Fact]
    public async Task A_record_stored_the_old_way_with_a_secret_goes_once_it_expires()
    {
        var tag = Guid.NewGuid().ToString("N")[..10];
        var key = $"{tag}-old";
        await StoreAsync(key, TimeSpan.FromMinutes(1), """{"id":1,"hmacSecret":"old-way-secret"}""");

        await RunAsync(batchSize: 500, dryRun: false);
        (await KeysLeftAsync(tag)).Should().ContainSingle("the record is still inside its time to live");

        await ExpireAsync(key);
        await RunAsync(batchSize: 500, dryRun: false);
        (await KeysLeftAsync(tag)).Should().BeEmpty("once expired, the record and the secret in it are gone");
    }

    private Task StoreAsync(string key, TimeSpan ttl, string body) => _fx.UseRedbAsync(async redb =>
    {
        var name = $"idem:cleanup-test:create:anon:{key}";
        await redb.SaveAsync(new RedbObject<IdempotencyRecordProps>
        {
            name = name,
            ValueUnique = IdempotencyKeyHash.Sha256Hex(name),
            date_complete = DateTimeOffset.UtcNow.Add(ttl),
            Props = new IdempotencyRecordProps
            {
                Scope = "cleanup-test",
                Operation = "create",
                CallerSubject = "anon",
                IdempotencyKey = key,
                StatusCode = 200,
                ResponseBody = body,
            },
        });
    });

    private Task ExpireAsync(string key) => _fx.UseRedbAsync(async redb =>
    {
        var record = (await redb.Query<IdempotencyRecordProps>().Where(r => r.IdempotencyKey == key).ToListAsync()).Single();
        record.date_complete = DateTimeOffset.UtcNow.AddMinutes(-1);
        await redb.SaveAsync(record);
    });

    private Task<List<string>> KeysLeftAsync(string tag) => _fx.UseRedbAsync(async redb =>
        (await redb.Query<IdempotencyRecordProps>().Where(r => r.Scope == "cleanup-test").ToListAsync())
            .Select(r => r.Props.IdempotencyKey!)
            .Where(k => k.StartsWith(tag, StringComparison.Ordinal))
            .ToList());

    private Task<object?> RunAsync(int batchSize, bool dryRun) => _fx.UseRedbAsync(async redb =>
    {
        var processor = new IdempotencyRecordCleanupProcessor(
            MockRouteContext.Create(redb),
            Options.Create(new RedbIdentityOptions { IdempotencyCleanupBatchSize = batchSize }));
        var exchange = new TestExchange();
        if (dryRun) exchange.In.Body = new Dictionary<string, object?> { ["dryRun"] = true };
        await processor.Process(exchange);
        return exchange.Out!.Body;
    });
}
