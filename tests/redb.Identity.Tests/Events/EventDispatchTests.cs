using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using redb.Identity.Contracts.Events;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Events;

public class EventDispatchTests
{
    private readonly ILogger _logger = Substitute.For<ILogger>();
    private readonly EventDispatchProcessor _processor;

    public EventDispatchTests()
    {
        _processor = new EventDispatchProcessor(_logger);
    }

    private static IdentityEvent DeserializeEvent(IExchange exchange)
    {
        // Body now carries the typed IdentityEvent directly — wire-encoding happens at
        // the transport boundary (.Marshal step or content-type-aware producer).
        return exchange.Out!.Body.Should().BeOfType<IdentityEvent>().Subject;
    }

    [Fact]
    public async Task TokenIssued_CreatesTypedEvent()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?>
        {
            ["clientId"] = "my-app",
            ["grantType"] = "client_credentials"
        };
        exchange.In.Headers["client_id"] = "my-app";

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.EventType.Should().Be("TokenIssued");
        evt.ClientId.Should().Be("my-app");
        evt.Details.Should().ContainKey("clientId");
        exchange.Out!.Headers["event-type"].Should().Be("TokenIssued");
    }

    [Fact]
    public async Task ClientRegistered_CreatesTypedEvent()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "ClientRegistered";
        exchange.Properties["identity-event-data"] = new { ClientId = "new-app" };

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.EventType.Should().Be("ClientRegistered");
        evt.Details.Should().ContainKey("ClientId");
    }

    [Fact]
    public async Task NoEventType_NoOp()
    {
        var exchange = new TestExchange();

        await _processor.Process(exchange);

        exchange.Out.Should().BeNull();
    }

    [Fact]
    public async Task Event_ContainsTimestamp()
    {
        var before = DateTimeOffset.UtcNow;
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "UserCreated";

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.Timestamp.Should().BeOnOrAfter(before);
        evt.Timestamp.Should().BeOnOrBefore(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Event_PicksUpActorHeaders()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "PasswordChanged";
        exchange.In.Headers["client_id"] = "admin-panel";
        exchange.In.Headers["user_id"] = "42";

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.ClientId.Should().Be("admin-panel");
        evt.UserId.Should().Be("42");
    }

    [Fact]
    public async Task Event_NullData_DetailsIsNull()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "ScopeDeleted";

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.Details.Should().BeNull();
    }

    // ── Audit-specific tests ──

    [Fact]
    public async Task Event_PicksUpIpAddressAndUserAgent()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";
        exchange.In.Headers["ip_address"] = "192.168.1.100";
        exchange.In.Headers["user_agent"] = "Mozilla/5.0";

        await _processor.Process(exchange);

        var evt = DeserializeEvent(exchange);
        evt.IpAddress.Should().Be("192.168.1.100");
        evt.UserAgent.Should().Be("Mozilla/5.0");
    }

    [Fact]
    public async Task Event_SetsSqlParamHeaders()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "UserCreated";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?>
        {
            ["Login"] = "testuser"
        };
        exchange.In.Headers["client_id"] = "admin";
        exchange.In.Headers["user_id"] = "7";
        exchange.In.Headers["ip_address"] = "10.0.0.1";
        exchange.In.Headers["user_agent"] = "curl/8.0";

        await _processor.Process(exchange);

        exchange.Out!.Headers["event_id"].Should().NotBeNull();
        exchange.Out.Headers["event_type"].Should().Be("UserCreated");
        exchange.Out.Headers["timestamp"].Should().BeOfType<DateTimeOffset>();
        exchange.Out.Headers["user_id"].Should().Be("7");
        exchange.Out.Headers["client_id"].Should().Be("admin");
        exchange.Out.Headers["ip_address"].Should().Be("10.0.0.1");
        exchange.Out.Headers["user_agent"].Should().Be("curl/8.0");
        exchange.Out.Headers["details"].Should().BeOfType<string>()
            .Which.Should().Contain("Login");
    }

    [Fact]
    public async Task Event_NullFields_SetDbNull()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "ScopeDeleted";
        // No user_id, client_id, ip_address, user_agent, details

        await _processor.Process(exchange);

        exchange.Out!.Headers["user_id"].Should().Be(DBNull.Value);
        exchange.Out.Headers["client_id"].Should().Be(DBNull.Value);
        exchange.Out.Headers["ip_address"].Should().Be(DBNull.Value);
        exchange.Out.Headers["user_agent"].Should().Be(DBNull.Value);
        exchange.Out.Headers["details"].Should().Be(DBNull.Value);
    }

    [Fact]
    public async Task Filter_WildcardAllowsAll()
    {
        var opts = new IdentityAuditOptions { Enabled = true, Filter = "*" };
        var processor = new EventDispatchProcessor(_logger, opts);
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";

        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
    }

    [Fact]
    public async Task Filter_WhitelistAllowsMatching()
    {
        var opts = new IdentityAuditOptions { Enabled = true, Filter = "TokenIssued,UserLoggedOut" };
        var processor = new EventDispatchProcessor(_logger, opts);
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";

        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
    }

    [Fact]
    public async Task Filter_WhitelistBlocksNonMatching()
    {
        var opts = new IdentityAuditOptions { Enabled = true, Filter = "TokenIssued,UserLoggedOut" };
        var processor = new EventDispatchProcessor(_logger, opts);
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "ScopeCreated";

        await processor.Process(exchange);

        exchange.Out.Should().BeNull();
    }

    [Fact]
    public async Task Filter_DisabledAudit_NoFiltering()
    {
        var opts = new IdentityAuditOptions { Enabled = false, Filter = "TokenIssued" };
        var processor = new EventDispatchProcessor(_logger, opts);
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "ScopeCreated";

        await processor.Process(exchange);

        // When audit is disabled, filter is not applied — events still flow for ILogger
        exchange.Out.Should().NotBeNull();
    }

    [Fact]
    public async Task BodyIsTypedIdentityEvent()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";
        exchange.In.Headers["client_id"] = "app1";

        await _processor.Process(exchange);

        // Core MUST NOT pre-serialise: Body is the typed IdentityEvent;
        // ContentType="application/json" hints downstream marshallers.
        var evt = exchange.Out!.Body.Should().BeOfType<IdentityEvent>().Subject;
        evt.EventType.Should().Be("TokenIssued");
        evt.ClientId.Should().Be("app1");
        exchange.Out!.ContentType.Should().Be("application/json");
    }
}
