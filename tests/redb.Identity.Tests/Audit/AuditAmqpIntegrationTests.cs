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
using redb.Route.Amqp;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Processors;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for AMQP 1.0 audit target (ActiveMQ Artemis).
/// Requires Artemis at localhost:5673 (admin/admin).
/// </summary>
public class AuditAmqpIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string AmqpHost = "localhost";
    private const int AmqpPort = 5673;
    private const string AmqpUser = "admin";
    private const string AmqpPassword = "admin";
    private readonly string _amqpQueue = $"identity-audit-{Guid.NewGuid():N}";

    private string AmqpUri =>
        "amqp://" + _amqpQueue + "?host=" + AmqpHost + "&port=" + AmqpPort
        + "&user=" + AmqpUser + "&password=" + AmqpPassword;

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public async Task InitializeAsync()
    {
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
                new AuditTarget { Name = "amqp-audit", Enabled = true, Uri = AmqpUri }
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

        _ctx = new RouteContext(_sp, "audit-amqp-test");
        _ctx.AddComponent(new AmqpComponent());

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

    private async Task<List<string>> ReceiveMessages(int expected, int timeoutMs = 10000)
    {
        var uri = EndpointUriParser.Parse(AmqpUri);
        var component = new AmqpComponent();
        var endpoint = (AmqpEndpoint)component.CreateEndpoint(uri);

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
        var message = new redb.Route.Core.Message();
        message.Headers["client_id"] = "amqp-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestAmqpDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "amqp-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        await Task.Delay(500);

        var messages = await ReceiveMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestAmqpDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPublished()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new redb.Route.Core.Message();
            message.Headers["client_id"] = $"amqp-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestAmqpMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
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
        var message = new redb.Route.Core.Message();
        message.Headers["client_id"] = "amqp-fields-client";
        message.Headers["user_id"] = "user-66";
        message.Headers["ip_address"] = "10.20.0.1";
        message.Headers["user_agent"] = "AmqpTestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestAmqpFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "amqp-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        await Task.Delay(500);

        var messages = await ReceiveMessages(1);
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(messages[0]);
        evt.GetProperty("eventType").GetString().Should().Be("TestAmqpFields");
        evt.GetProperty("clientId").GetString().Should().Be("amqp-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-66");
        evt.GetProperty("ipAddress").GetString().Should().Be("10.20.0.1");
        evt.GetProperty("userAgent").GetString().Should().Be("AmqpTestAgent/1.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
