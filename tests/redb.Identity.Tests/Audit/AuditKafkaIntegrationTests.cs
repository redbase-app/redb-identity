using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Confluent.Kafka;
using Confluent.Kafka.Admin;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Core.Models.Entities;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.DataProtection;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Postgres.Pro.Extensions;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Kafka;
using redb.Route.Processors;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for Kafka audit target.
/// Requires Kafka at localhost:29092.
/// </summary>
public class AuditKafkaIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string KafkaBrokers = "localhost:29092";
    private const string KafkaTopic = "identity-audit-test";

    private const string KafkaUri =
        "kafka://" + KafkaTopic + "?brokers=" + KafkaBrokers;

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public async Task InitializeAsync()
    {
        // Delete topic if exists (best-effort cleanup via Kafka AdminClient)
        try
        {
            using var adminClient = new AdminClientBuilder(new AdminClientConfig { BootstrapServers = KafkaBrokers }).Build();
            await adminClient.DeleteTopicsAsync([KafkaTopic]);
            await Task.Delay(1000);
        }
        catch (DeleteTopicsException ex) when (ex.Results.All(r => r.Error.Code == ErrorCode.UnknownTopicOrPart))
        {
            // Expected on first run when the topic hasn't been created yet.
            Console.Error.WriteLine($"Kafka DeleteTopics skipped (topic not yet created): {ex.Message}");
        }
        catch (Exception ex)
        {
            // Unexpected admin failures must remain visible \u2014 don't silently swallow.
            Console.Error.WriteLine($"Kafka DeleteTopics failed: {ex.GetType().Name}: {ex.Message}");
        }

        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres") ?? PgConnString;

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddRedbForTests(cs);

        services.AddSingleton<SharedVmRegistry>();

        var identityOptions = new RedbIdentityOptions
        {
            TokenThrottleMaxPerPeriod = 1000,
            Issuer = new Uri("https://identity.test.local/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true
        };
        services.AddSingleton(Options.Create(identityOptions));

        var auditOptions = new IdentityAuditOptions
        {
            Enabled = true,
            Filter = "*",
            Targets =
            [
                new AuditTarget { Name = "kafka-audit", Enabled = true, Uri = KafkaUri }
            ]
        };
        services.AddSingleton(Options.Create(auditOptions));

        services.AddRedbIdentityServer(identityOptions);

        _sp = services.BuildServiceProvider();

        var redb = _sp.GetRequiredService<IRedbService>();
        try { await redb.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back to parameterless overload: {ex.GetType().Name}: {ex.Message}");
            await redb.InitializeAsync();
        }

        await redb.SyncSchemeAsync<ApplicationProps>();
        await redb.SyncSchemeAsync<AuthorizationProps>();
        await redb.SyncSchemeAsync<ScopeProps>();
        await redb.SyncSchemeAsync<TokenProps>();
        await redb.SyncSchemeAsync<UserProps>();
        await redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await redb.SyncSchemeAsync<SessionProps>();
        await redb.SyncSchemeAsync<MfaProps>();
        await redb.InitializeTypeRegistryAsync();

        _ctx = new RouteContext(_sp, "audit-kafka-test");
        _ctx.AddComponent(new KafkaComponent());

        _ctx.AddRoutes(new IdentityCoreRouteBuilder(
            _sp,
            Options.Create(identityOptions),
            Options.Create(auditOptions)));

        await _ctx.Start();
    }

    public async Task DisposeAsync()
    {
        if (_ctx != null) await _ctx.Stop();
        if (_sp != null) await _sp.DisposeAsync();
    }

    private async Task<List<string>> ConsumeMessages(int expected, int timeoutMs = 15000)
    {
        var groupId = $"audit-verify-{Guid.NewGuid():N}";
        var uri = EndpointUriParser.Parse(
            $"kafka://{KafkaTopic}?brokers={KafkaBrokers}&groupId={groupId}&autoOffsetReset=Earliest");
        var component = new KafkaComponent();
        var endpoint = (KafkaEndpoint)component.CreateEndpoint(uri);

        var results = new ConcurrentBag<string>();
        var allReceived = new TaskCompletionSource();

        var processor = new DelegateProcessor((exchange, _) =>
        {
            var body = exchange.In.Body switch
            {
                byte[] bytes => Encoding.UTF8.GetString(bytes),
                string s => s,
                _ => exchange.In.Body?.ToString() ?? ""
            };
            results.Add(body);
            if (results.Count >= expected)
                allReceived.TrySetResult();
            return Task.CompletedTask;
        });

        var consumer = endpoint.CreateConsumer(processor);
        await consumer.Start();

        await Task.WhenAny(allReceived.Task, Task.Delay(timeoutMs));

        await consumer.Stop();
        await endpoint.Stop();

        return results.ToList();
    }

    [Fact]
    public async Task DirectEventSend_PublishesToTopic()
    {
        var message = new Message();
        message.Headers["client_id"] = "kafka-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestKafkaDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "kafka-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        var messages = await ConsumeMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestKafkaDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPublished()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"kafka-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestKafkaMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        var messages = await ConsumeMessages(3);
        messages.Should().HaveCount(3);
    }

    [Fact]
    public async Task EventMessage_ContainsIdentityEventPayload()
    {
        var message = new Message();
        message.Headers["client_id"] = "kafka-fields-client";
        message.Headers["user_id"] = "user-88";
        message.Headers["ip_address"] = "172.16.0.10";
        message.Headers["user_agent"] = "KafkaTestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestKafkaFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "kafka-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        var messages = await ConsumeMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestKafkaFields");
        evt.GetProperty("clientId").GetString().Should().Be("kafka-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-88");
        evt.GetProperty("ipAddress").GetString().Should().Be("172.16.0.10");
        evt.GetProperty("userAgent").GetString().Should().Be("KafkaTestAgent/1.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
