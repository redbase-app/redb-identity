using System.Data.Common;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Scopes;
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
using redb.Route.Sql;
using redb.Route.Sql.Connection;
using Xunit;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Audit;

/// <summary>
/// Integration tests for the audit multicast subsystem.
/// Uses real PostgreSQL with the <c>identity_audit_log</c> table.
/// </summary>
public class AuditSqlIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private const string SqlInsertUri =
        "sql:INSERT INTO identity_audit_log(event_id, event_type, \"timestamp\", user_id, client_id, ip_address, user_agent, details) "
        + "VALUES(@event_id, @event_type, @timestamp, @user_id, @client_id, @ip_address, @user_agent, @details::jsonb)"
        + "?dataSource=identity-audit-pg&outputType=None"
        + "&param.event_id=${header.event_id}"
        + "&param.event_type=${header.event_type}"
        + "&param.timestamp=${header.timestamp}"
        + "&param.user_id=${header.user_id}"
        + "&param.client_id=${header.client_id}"
        + "&param.ip_address=${header.ip_address}"
        + "&param.user_agent=${header.user_agent}"
        + "&param.details=${header.details}";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private ProducerTemplate _producer = null!;

    public async Task InitializeAsync()
    {
        DbProviderFactories.RegisterFactory("Npgsql", NpgsqlFactory.Instance);

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
                new AuditTarget
                {
                    Name = "pg-audit",
                    Enabled = true,
                    Uri = SqlInsertUri
                }
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

        // Clean audit table before tests (create if missing — keeps tests
        // self-contained on a freshly seeded dev DB).
        await using (var conn = new NpgsqlConnection(cs))
        {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS identity_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    event_id     UUID NOT NULL,
    event_type   VARCHAR(100) NOT NULL,
    ""timestamp"" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      VARCHAR(50),
    client_id    VARCHAR(200),
    ip_address   VARCHAR(50),
    user_agent   VARCHAR(500),
    details      JSONB,
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);
DELETE FROM identity_audit_log;";
            await cmd.ExecuteNonQueryAsync();
        }

        _ctx = new RouteContext(_sp, "audit-integration-test");
        _ctx.AddComponent(new SqlComponent());
        _ctx.AddToRegistry("identity-audit-pg", (ISqlConnectionFactory)new SqlConnectionFactory(
            new SqlConnectionOptions
            {
                ConnectionString = cs,
                ProviderName = "Npgsql"
            }));

        _ctx.AddRoutes(new IdentityCoreRouteBuilder(
            _sp,
            Options.Create(identityOptions),
            Options.Create(auditOptions)));

        await _ctx.Start();

        _producer = new ProducerTemplate(_ctx);
        _producer.Start();
    }

    public async Task DisposeAsync()
    {
        _producer?.Stop();
        if (_ctx != null) await _ctx.Stop();
        if (_sp != null) await _sp.DisposeAsync();
    }

    private async Task<Exchange> SendScope(string operation, object body)
    {
        var message = new Message { Body = body };
        message.Headers["operation"] = operation;

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOut };
        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.ManageScopes);
        var producer = endpoint.CreateProducer();
        await producer.Process(exchange);
        return exchange;
    }

    private async Task<List<Dictionary<string, object?>>> QueryAuditRows(string? eventType = null)
    {
        await using var conn = new NpgsqlConnection(PgConnString);
        await conn.OpenAsync();

        var sql = "SELECT event_id, event_type, \"timestamp\", user_id, client_id, ip_address, user_agent, details::text FROM identity_audit_log";
        if (eventType is not null)
        {
            sql += " WHERE event_type = @et";
        }
        sql += " ORDER BY id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (eventType is not null)
            cmd.Parameters.AddWithValue("et", eventType);
        await using var reader = await cmd.ExecuteReaderAsync();

        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    [Fact]
    public async Task BareSql_InsertAuditRow()
    {
        // Bypass Events route entirely — send directly to the SQL endpoint
        var sqlEndpoint = _ctx.GetEndpoint(SqlInsertUri);
        var sqlProducer = sqlEndpoint.CreateProducer();
        await sqlProducer.Start();

        var msg = new Message();
        msg.Body = "{}"; // JSON body
        msg.Headers["event_id"] = Guid.NewGuid();
        msg.Headers["event_type"] = "BareSqlTest";
        msg.Headers["timestamp"] = DateTimeOffset.UtcNow;
        msg.Headers["user_id"] = DBNull.Value;
        msg.Headers["client_id"] = "bare-client";
        msg.Headers["ip_address"] = DBNull.Value;
        msg.Headers["user_agent"] = DBNull.Value;
        msg.Headers["details"] = "{}";

        var exchange = new Exchange(msg) { Pattern = ExchangePattern.InOnly };
        await sqlProducer.Process(exchange);

        exchange.Exception.Should().BeNull("SQL INSERT should succeed: {0}", exchange.Exception?.Message);

        var rows = await QueryAuditRows("BareSqlTest");
        rows.Should().ContainSingle();
    }

    [Fact]
    public async Task DirectEventSend_WritesAuditRow()
    {
        // Send directly to the Events endpoint, bypassing WireTap
        var message = new Message();
        message.Headers["client_id"] = "direct-test-client";

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestDirect";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "direct" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        // Check that the processor ran: In should have the headers after Out→In merge
        exchange.In.Headers.Should().ContainKey("event_type", "EventDispatchProcessor should set Out headers which get merged to In");
        exchange.Exception.Should().BeNull("Events route should not throw: {0}", exchange.Exception?.ToString());

        // Multicast is synchronous in the pipeline — no delay needed
        var rows = await QueryAuditRows("TestDirect");
        rows.Should().ContainSingle();
        rows[0]["event_type"].Should().Be("TestDirect");
        rows[0]["client_id"].Should().Be("direct-test-client");
    }

    [Fact]
    public async Task ScopeCreated_WritesAuditRow()
    {
        var scopeName = "audit-create-" + Guid.NewGuid().ToString("N")[..8];
        var exchange = await SendScope("create",
            new CreateScopeRequest { Name = scopeName, DisplayName = "Audit Test" });

        exchange.Exception.Should().BeNull();

        // WireTap is fire-and-forget — small delay for async processing
        await Task.Delay(500);

        var rows = await QueryAuditRows("ScopeCreated");
        rows.Should().HaveCountGreaterOrEqualTo(1);
        rows.Last()["event_type"].Should().Be("ScopeCreated");
        rows.Last()["event_id"].Should().NotBeNull();
    }

    [Fact]
    public async Task Event_NullFields_WrittenAsDbNull()
    {
        // Send event without user_id or client_id — verify nulls in DB
        var message = new Message();
        // No user_id or client_id headers

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOnly };
        exchange.Properties["identity-event-type"] = "TestNullFields";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["info"] = "nulls" };

        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.Events);
        var producer = endpoint.CreateProducer();
        await producer.Start();
        await producer.Process(exchange);

        exchange.Exception.Should().BeNull();

        var rows = await QueryAuditRows("TestNullFields");
        rows.Should().ContainSingle();
        rows[0]["user_id"].Should().BeNull();
        rows[0]["client_id"].Should().BeNull();
        rows[0]["ip_address"].Should().BeNull();
        rows[0]["user_agent"].Should().BeNull();
    }

    [Fact]
    public async Task AuditRow_ContainsEventIdAndTimestamp()
    {
        var scopeName = "audit-ts-" + Guid.NewGuid().ToString("N")[..8];
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);

        var exchange = await SendScope("create",
            new CreateScopeRequest { Name = scopeName, DisplayName = "TS Test" });
        exchange.Exception.Should().BeNull();

        await Task.Delay(500);

        var rows = await QueryAuditRows("ScopeCreated");
        rows.Should().HaveCountGreaterOrEqualTo(1);

        var row = rows.Last();
        row["event_id"].Should().NotBeNull();
        var rawTs = row["timestamp"];
        var ts = rawTs is DateTimeOffset dto ? dto : new DateTimeOffset((DateTime)rawTs!);
        ts.Should().BeAfter(before);
    }

    [Fact]
    public async Task MultipleEvents_AllWritten()
    {
        // Clean slate for this test
        await using (var conn = new NpgsqlConnection(PgConnString))
        {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM identity_audit_log";
            await cmd.ExecuteNonQueryAsync();
        }

        // Create 3 scopes → 3 ScopeCreated events
        for (int i = 0; i < 3; i++)
        {
            var exchange = await SendScope("create",
                new CreateScopeRequest
                {
                    Name = $"audit-multi-{i}-{Guid.NewGuid():N}"[..30],
                    DisplayName = $"Multi {i}"
                });
            exchange.Exception.Should().BeNull();
        }

        // WireTap is fire-and-forget — poll until all 3 rows appear (up to 5 s)
        List<Dictionary<string, object?>> rows = [];
        for (var attempt = 0; attempt < 10; attempt++)
        {
            await Task.Delay(500);
            rows = await QueryAuditRows("ScopeCreated");
            if (rows.Count >= 3) break;
        }
        rows.Should().HaveCount(3);

        // All event_ids should be unique
        var eventIds = rows.Select(r => r["event_id"]).ToHashSet();
        eventIds.Should().HaveCount(3);
    }
}
