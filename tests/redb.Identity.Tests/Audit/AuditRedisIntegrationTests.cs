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
using redb.Route.Redis;
using StackExchange.Redis;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for Redis audit target (LPUSH to a list).
/// Requires Redis at localhost:6379.
/// </summary>
public class AuditRedisIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string RedisConnString = "localhost:6379";
    private const string RedisKey = "identity-audit-test";

    private const string RedisUri =
        "redis:LPUSH:" + RedisKey + "?connectionString=" + RedisConnString;

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private ConnectionMultiplexer _redis = null!;

    public async Task InitializeAsync()
    {
        _redis = await ConnectionMultiplexer.ConnectAsync(RedisConnString);
        await _redis.GetDatabase().KeyDeleteAsync(RedisKey);

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
                new AuditTarget { Name = "redis-audit", Enabled = true, Uri = RedisUri }
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

        _ctx = new RouteContext(_sp, "audit-redis-test");
        _ctx.AddComponent(new RedisComponent());

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
        if (_redis != null) await _redis.DisposeAsync();
    }

    [Fact]
    public async Task DirectEventSend_PushesToList()
    {
        var message = new Message();
        message.Headers["client_id"] = "redis-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestRedisDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "redis-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        await Task.Delay(300);

        var db = _redis.GetDatabase();
        var length = await db.ListLengthAsync(RedisKey);
        length.Should().BeGreaterOrEqualTo(1);

        var value = await db.ListGetByIndexAsync(RedisKey, 0);
        value.HasValue.Should().BeTrue();

        var evt = JsonSerializer.Deserialize<JsonElement>(value.ToString());
        evt.GetProperty("eventType").GetString().Should().Be("TestRedisDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllPushed()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"redis-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestRedisMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["idx"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        await Task.Delay(300);

        var db = _redis.GetDatabase();
        var length = await db.ListLengthAsync(RedisKey);
        length.Should().Be(3);
    }

    [Fact]
    public async Task EventMessage_ContainsIdentityEventPayload()
    {
        var message = new Message();
        message.Headers["client_id"] = "redis-fields-client";
        message.Headers["user_id"] = "user-99";
        message.Headers["ip_address"] = "10.10.0.1";
        message.Headers["user_agent"] = "RedisTestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestRedisFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "redis-check" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        await Task.Delay(300);

        var db = _redis.GetDatabase();
        var value = await db.ListGetByIndexAsync(RedisKey, 0);
        value.HasValue.Should().BeTrue();

        var evt = JsonSerializer.Deserialize<JsonElement>(value.ToString());
        evt.GetProperty("eventType").GetString().Should().Be("TestRedisFields");
        evt.GetProperty("clientId").GetString().Should().Be("redis-fields-client");
        evt.GetProperty("userId").GetString().Should().Be("user-99");
        evt.GetProperty("ipAddress").GetString().Should().Be("10.10.0.1");
        evt.GetProperty("userAgent").GetString().Should().Be("RedisTestAgent/1.0");
        evt.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
