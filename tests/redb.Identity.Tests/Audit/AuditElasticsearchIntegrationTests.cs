using System.Net.Http.Json;
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
using redb.Route.Elasticsearch;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for Elasticsearch audit target.
/// Requires Elasticsearch at localhost:9200.
/// </summary>
public class AuditElasticsearchIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string EsNodes = "http://localhost:9200";
    private const string EsIndex = "identity-audit-test";

    private const string EsUri =
        "es://" + EsIndex + "?nodes=" + EsNodes + "&refresh=wait_for";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private readonly HttpClient _http = new();

    public async Task InitializeAsync()
    {
        // Clean ES index
        try
        {
            // ES returns 404 when the index doesn't exist \u2014 that is the expected first-run state.
            using var resp = await _http.DeleteAsync($"{EsNodes}/{EsIndex}");
            if (!resp.IsSuccessStatusCode && resp.StatusCode != System.Net.HttpStatusCode.NotFound)
            {
                Console.Error.WriteLine($"ES index delete returned {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
            }
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"ES index delete failed (server unreachable?): {ex.Message}");
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
                new AuditTarget { Name = "es-audit", Enabled = true, Uri = EsUri }
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

        _ctx = new RouteContext(_sp, "audit-es-test");
        _ctx.AddComponent(new ElasticsearchComponent());

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

    private async Task<JsonElement?> SearchEsIndex(string? eventType = null)
    {
        var query = eventType is not null
            ? "{\"query\":{\"term\":{\"eventType.keyword\":\"" + eventType + "\"}}}"
            : "{\"query\":{\"match_all\":{}}}";

        var response = await _http.PostAsync(
            $"{EsNodes}/{EsIndex}/_search",
            new StringContent(query, System.Text.Encoding.UTF8, "application/json"));

        if (!response.IsSuccessStatusCode) return null;

        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement;
    }

    [Fact]
    public async Task DirectEventSend_IndexesDocument()
    {
        var message = new Message();
        message.Headers["client_id"] = "es-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestEsDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "es-test" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        var result = await SearchEsIndex("TestEsDirect");
        result.Should().NotBeNull();

        var hits = result!.Value.GetProperty("hits").GetProperty("hits");
        hits.GetArrayLength().Should().BeGreaterOrEqualTo(1);

        var source = hits[0].GetProperty("_source");
        source.GetProperty("eventType").GetString().Should().Be("TestEsDirect");
    }

    [Fact]
    public async Task MultipleEvents_AllIndexed()
    {
        for (int i = 0; i < 3; i++)
        {
            var message = new Message();
            message.Headers["client_id"] = $"es-multi-{i}";

            var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
            exchange.Properties["identity-event-type"] = "TestEsMulti";
            exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["index"] = i };

            var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
            var producer = endpoint.CreateProducer();
            await producer.Start();
            await producer.Process(exchange);

            exchange.Exception.Should().BeNull();
        }

        var result = await SearchEsIndex("TestEsMulti");
        result.Should().NotBeNull();

        var hits = result!.Value.GetProperty("hits").GetProperty("hits");
        hits.GetArrayLength().Should().Be(3);
    }

    [Fact]
    public async Task EventDocument_ContainsAllFields()
    {
        var message = new Message();
        message.Headers["client_id"] = "es-fields-client";
        message.Headers["user_id"] = "user-42";
        message.Headers["ip_address"] = "10.0.0.5";
        message.Headers["user_agent"] = "TestAgent/1.0";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestEsFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["action"] = "verify" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        var result = await SearchEsIndex("TestEsFields");
        result.Should().NotBeNull();

        var hits = result!.Value.GetProperty("hits").GetProperty("hits");
        hits.GetArrayLength().Should().BeGreaterOrEqualTo(1);

        var source = hits[0].GetProperty("_source");
        source.GetProperty("eventType").GetString().Should().Be("TestEsFields");
        source.GetProperty("clientId").GetString().Should().Be("es-fields-client");
        source.GetProperty("userId").GetString().Should().Be("user-42");
        source.GetProperty("ipAddress").GetString().Should().Be("10.0.0.5");
        source.GetProperty("userAgent").GetString().Should().Be("TestAgent/1.0");
        source.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
    }
}
