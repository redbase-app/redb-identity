using System.Net.Http.Headers;
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
using redb.Route.RabbitMQ;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for RabbitMQ audit target.
/// Requires RabbitMQ at localhost:5672 (management at 15672, admin/admin).
/// </summary>
public class AuditRabbitMqIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string RabbitQueue = "identity-audit-test";

    private const string RabbitUri =
        "rabbitmq://" + RabbitQueue
        + "?host=localhost&port=5672&username=admin&password=admin&declare=true";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private readonly HttpClient _http = new();

    public async Task InitializeAsync()
    {
        // Purge queue via management API (if exists)
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:admin")));
        try
        {
            using var resp = await _http.DeleteAsync($"http://localhost:15672/api/queues/%2f/{RabbitQueue}/contents");
            if (!resp.IsSuccessStatusCode && resp.StatusCode != System.Net.HttpStatusCode.NotFound)
            {
                Console.Error.WriteLine($"RabbitMQ queue purge returned {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
            }
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"RabbitMQ queue purge failed (mgmt API unreachable?): {ex.Message}");
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
                new AuditTarget { Name = "rabbitmq-audit", Enabled = true, Uri = RabbitUri }
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

        _ctx = new RouteContext(_sp, "audit-rabbitmq-test");
        _ctx.AddComponent(new RabbitMQComponent());

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
        _http.Dispose();
    }

    /// <summary>
    /// Get messages from queue via RabbitMQ Management API (non-destructive peek).
    /// </summary>
    private async Task<List<JsonElement>> GetQueueMessages(int count = 10)
    {
        var body = JsonSerializer.Serialize(new
        {
            count,
            ackmode = "ack_requeue_false",
            encoding = "auto"
        });

        var response = await _http.PostAsync(
            $"http://localhost:15672/api/queues/%2f/{RabbitQueue}/get",
            new StringContent(body, Encoding.UTF8, "application/json"));

        if (!response.IsSuccessStatusCode) return [];

        var json = await response.Content.ReadAsStringAsync();
        var messages = JsonDocument.Parse(json).RootElement;

        if (messages.ValueKind != JsonValueKind.Array) return [];

        return messages.EnumerateArray().ToList();
    }

    [Fact]
    public async Task DirectEventSend_PublishesToQueue()
    {
        var message = new Message();
        message.Headers["client_id"] = "rmq-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestRmqDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "rmq-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        await Task.Delay(500); // RabbitMQ publish is async

        var messages = await GetQueueMessages();
        messages.Should().HaveCountGreaterOrEqualTo(1);

        // Decode payload — it's base64 or raw string
        var payload = messages[0].GetProperty("payload").GetString();
        payload.Should().NotBeNullOrEmpty();

        var evt = JsonSerializer.Deserialize<JsonElement>(payload!);
        evt.GetProperty("eventType").GetString().Should().Be("TestRmqDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPublished()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"rmq-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestRmqMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        await Task.Delay(500);

        var messages = await GetQueueMessages();
        messages.Should().HaveCount(3);
    }

    [Fact]
    public async Task EventMessage_ContainsIdentityEventPayload()
    {
        var message = new Message();
        message.Headers["client_id"] = "rmq-fields-client";
        message.Headers["user_id"] = "user-77";
        message.Headers["ip_address"] = "192.168.1.50";
        message.Headers["user_agent"] = "RmqTestAgent/2.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestRmqFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "rmq-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        await Task.Delay(500);

        var messages = await GetQueueMessages();
        messages.Should().HaveCountGreaterOrEqualTo(1);

        var payload = messages[0].GetProperty("payload").GetString()!;
        var evt = JsonSerializer.Deserialize<JsonElement>(payload);
        evt.GetProperty("eventType").GetString().Should().Be("TestRmqFields");
        evt.GetProperty("clientId").GetString().Should().Be("rmq-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-77");
        evt.GetProperty("ipAddress").GetString().Should().Be("192.168.1.50");
        evt.GetProperty("userAgent").GetString().Should().Be("RmqTestAgent/2.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
