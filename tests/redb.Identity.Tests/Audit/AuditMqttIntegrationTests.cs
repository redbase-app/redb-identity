using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MQTTnet;
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
using redb.Route.MqttNet;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for MQTT audit target.
/// Requires Mosquitto at localhost:11883.
/// </summary>
public class AuditMqttIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string MqttServer = "localhost";
    private const int MqttPort = 11883;
    private const string MqttTopic = "identity/audit/test";

    private static readonly string MqttUri =
        "mqtt://" + MqttTopic + "?mode=Publish&server=" + MqttServer + "&port=" + MqttPort + "&qos=1";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private IMqttClient _subscriber = null!;
    private readonly ConcurrentBag<string> _received = new();
    private readonly SemaphoreSlim _signal = new(0);

    public async Task InitializeAsync()
    {
        // Set up MQTT subscriber BEFORE sending events
        var factory = new MqttClientFactory();
        _subscriber = factory.CreateMqttClient();

        var opts = new MqttClientOptionsBuilder()
            .WithTcpServer(MqttServer, MqttPort)
            .WithClientId($"audit-verify-{Guid.NewGuid():N}")
            .Build();

        _subscriber.ApplicationMessageReceivedAsync += args =>
        {
            var payload = args.ApplicationMessage.ConvertPayloadToString();
            _received.Add(payload);
            _signal.Release();
            return Task.CompletedTask;
        };

        await _subscriber.ConnectAsync(opts);
        await _subscriber.SubscribeAsync(MqttTopic);

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
                new AuditTarget { Name = "mqtt-audit", Enabled = true, Uri = MqttUri }
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

        _ctx = new RouteContext(_sp, "audit-mqtt-test");
        _ctx.AddComponent(new MqttComponent());

        _ctx.AddRoutes(new IdentityCoreRouteBuilder(
            _sp,
            Options.Create(identityOptions),
            Options.Create(auditOptions)));

        await _ctx.Start();
    }

    public async Task DisposeAsync()
    {
        if (_ctx != null) await _ctx.Stop();
        if (_subscriber is { IsConnected: true })
        {
            await _subscriber.UnsubscribeAsync(MqttTopic);
            await _subscriber.DisconnectAsync();
        }
        _subscriber?.Dispose();
        if (_sp != null) await _sp.DisposeAsync();
        _signal.Dispose();
    }

    private async Task WaitForMessages(int count, int timeoutMs = 5000)
    {
        for (int i = 0; i < count; i++)
            await _signal.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs));
    }

    [Fact]
    public async Task DirectEventSend_PublishesToTopic()
    {
        var message = new Message();
        message.Headers["client_id"] = "mqtt-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestMqttDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "mqtt-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        await WaitForMessages(1);

        _received.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(_received.First());
        evt.GetProperty("eventType").GetString().Should().Be("TestMqttDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPublished()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"mqtt-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestMqttMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        await WaitForMessages(3);

        _received.Should().HaveCount(3);
    }

    [Fact]
    public async Task EventMessage_ContainsIdentityEventPayload()
    {
        var message = new Message();
        message.Headers["client_id"] = "mqtt-fields-client";
        message.Headers["user_id"] = "user-55";
        message.Headers["ip_address"] = "192.168.10.5";
        message.Headers["user_agent"] = "MqttTestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestMqttFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "mqtt-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        await WaitForMessages(1);

        _received.Should().HaveCountGreaterOrEqualTo(1);

        var evt = JsonSerializer.Deserialize<JsonElement>(_received.First());
        evt.GetProperty("eventType").GetString().Should().Be("TestMqttFields");
        evt.GetProperty("clientId").GetString().Should().Be("mqtt-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-55");
        evt.GetProperty("ipAddress").GetString().Should().Be("192.168.10.5");
        evt.GetProperty("userAgent").GetString().Should().Be("MqttTestAgent/1.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
