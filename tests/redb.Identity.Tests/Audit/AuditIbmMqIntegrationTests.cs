using System.Text;
using System.Text.Json;
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
using redb.Route.IbmMq;
using redb.Route.Processors;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for IBM MQ (WMQ) audit target.
/// Requires IBM MQ at localhost:1414 (channel=DEV.APP.SVRCONN, QM=QM1, user=app, password=admin).
/// </summary>
public class AuditIbmMqIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string WmqHost = "localhost";
    private const int WmqPort = 1414;
    private const string WmqChannel = "DEV.APP.SVRCONN";
    private const string WmqQueueManager = "QM1";
    private const string WmqUser = "app";
    private const string WmqPassword = "admin";
    private const string WmqQueue = "DEV.QUEUE.3";

    private string WmqUri =>
        "wmq:" + WmqQueue + "?host=" + WmqHost + "&port=" + WmqPort
        + "&channel=" + WmqChannel + "&queueManager=" + WmqQueueManager
        + "&user=" + WmqUser + "&password=" + WmqPassword;

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public async Task InitializeAsync()
    {
        // Drain any leftover messages from previous test runs
        await DrainQueue();

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
                new AuditTarget { Name = "wmq-audit", Enabled = true, Uri = WmqUri }
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

        _ctx = new RouteContext(_sp, "audit-wmq-test");
        _ctx.AddComponent(new IbmMqComponent());

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

    private async Task DrainQueue()
    {
        try
        {
            var uri = EndpointUriParser.Parse(WmqUri + "&waitInterval=1000");
            var component = new IbmMqComponent();
            var endpoint = (IbmMqEndpoint)component.CreateEndpoint(uri);

            var processor = new DelegateProcessor((_, _) => Task.CompletedTask);
            var consumer = endpoint.CreateConsumer(processor);
            await consumer.Start();
            await Task.Delay(2000);
            await consumer.Stop();
            await endpoint.Stop();
        }
        catch (Exception ex)
        {
            // Best-effort drain: queue may be empty / missing on first run, or MQ may be unreachable.
            // Surface the failure rather than silently swallow so a misconfigured broker is visible.
            Console.Error.WriteLine($"DrainQueue best-effort failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task<List<string>> ReceiveMessages(int expected, int timeoutMs = 15000)
    {
        var uri = EndpointUriParser.Parse(WmqUri + "&waitInterval=5000");
        var component = new IbmMqComponent();
        var endpoint = (IbmMqEndpoint)component.CreateEndpoint(uri);

        var results = new System.Collections.Concurrent.ConcurrentBag<string>();
        var allReceived = new TaskCompletionSource();

        var processor = new DelegateProcessor(async (exchange, _) =>
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
        });

        var consumer = endpoint.CreateConsumer(processor);
        await consumer.Start();

        await Task.WhenAny(allReceived.Task, Task.Delay(timeoutMs));

        await consumer.Stop();
        await endpoint.Stop();

        return results.ToList();
    }

    [Fact]
    public async Task DirectEventSend_PublishesToQueue()
    {
        var message = new Message();
        message.Headers["client_id"] = "wmq-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestWmqDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "wmq-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        await Task.Delay(500);

        var messages = await ReceiveMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestWmqDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPublished()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"wmq-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestWmqMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var ep = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = ep.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        await Task.Delay(500);

        var messages = await ReceiveMessages(3);
        messages.Should().HaveCount(3);
    }

    [Fact]
    public async Task EventMessage_ContainsIdentityEventPayload()
    {
        var message = new Message();
        message.Headers["client_id"] = "wmq-fields-client";
        message.Headers["user_id"] = "user-99";
        message.Headers["ip_address"] = "172.16.0.1";
        message.Headers["user_agent"] = "WmqTestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestWmqFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "wmq-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        await Task.Delay(500);

        var messages = await ReceiveMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestWmqFields");
        evt.GetProperty("clientId").GetString().Should().Be("wmq-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-99");
        evt.GetProperty("ipAddress").GetString().Should().Be("172.16.0.1");
        evt.GetProperty("userAgent").GetString().Should().Be("WmqTestAgent/1.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
