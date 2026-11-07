using System.Text.Json;
using AwesomeAssertions;
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
        exchange.IsStopped.Should().BeTrue("the raw request copy must not reach the sink, webhooks or targets");
    }

    // ── What leaves the dispatcher: the event and its own headers, nothing of the request ──

    private static readonly string[] EventHeaders =
        ["event-type", "event_id", "event_type", "timestamp", "user_id", "client_id", "ip_address", "user_agent", "details"];

    /// <summary>The WireTap copy of a client-credentials POST /connect/token, as the HTTP facade hands it over.</summary>
    private static TestExchange TokenRequestCopy()
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "TokenIssued";
        exchange.Properties["identity-event-data"] = new Dictionary<string, object?> { ["GrantType"] = "client_credentials" };
        exchange.In.Body = "grant_type=client_credentials&client_id=app1&client_secret=s3cret";
        exchange.In.Headers["redbHttp.Method"] = "POST";
        exchange.In.Headers["redbHttp.Path"] = "/connect/token";
        exchange.In.Headers["redbHttp.Url"] = "https://id.example/connect/token";
        exchange.In.Headers["redbHttp.RemoteAddress"] = "10.1.2.3";
        exchange.In.Headers["Host"] = "id.example";
        exchange.In.Headers["Content-Length"] = "64";
        exchange.In.Headers["Cookie"] = ".redb.session=abc";
        exchange.In.Headers["Authorization"] = "Bearer eyJhbGciOi.token.sig";
        exchange.In.Headers["User-Agent"] = "curl/8.0";
        exchange.In.Headers["grant_type"] = "client_credentials";
        exchange.In.Headers["client_id"] = "app1";
        exchange.In.Headers["client_secret"] = "s3cret";
        // The business route's response is on Out of the copy.
        exchange.Out = new TestMessage { Body = "{\"access_token\":\"eyJhbGciOi.token.sig\"}" };
        exchange.Out.Headers["Set-Cookie"] = ".redb.session=abc";
        return exchange;
    }

    [Fact]
    public async Task TokenRequest_EventCarriesOnlyEventHeaders()
    {
        var exchange = TokenRequestCopy();

        await _processor.Process(exchange);

        exchange.IsStopped.Should().BeFalse();
        exchange.In.Headers.Should().BeEmpty("the request's headers must not survive into the event exchange");
        exchange.In.Body.Should().BeNull();
        exchange.Out!.Headers.Keys.Should().BeEquivalentTo(EventHeaders);
        exchange.Out.Body.Should().BeOfType<IdentityEvent>();

        // What the request contributed is the event's own fields, taken before the request was dropped.
        exchange.Out.Headers["client_id"].Should().Be("app1");
        exchange.Out.Headers["ip_address"].Should().Be("10.1.2.3");
        exchange.Out.Headers["user_agent"].Should().Be("curl/8.0");
        JsonSerializer.Serialize(exchange.Out.Body).Should().NotContain("s3cret").And.NotContain("eyJhbGciOi");
    }

    [Fact]
    public async Task TokenRequest_ThroughThePipeline_NextStepSeesOnlyTheEvent()
    {
        // The events route is a pipeline: dispatch, then sink / webhooks / multicast. The pipeline merges
        // Out headers into In, so this is where the request's headers used to ride along.
        IMessage? seen = null;
        var pipeline = new redb.Route.Processors.PipelineProcessor();
        pipeline.Add(_processor);
        pipeline.Add(new CaptureProcessor(m => seen = m));

        await pipeline.Process(TokenRequestCopy());

        seen.Should().NotBeNull();
        seen!.Headers.Keys.Should().BeEquivalentTo(EventHeaders);
        seen.Body.Should().BeOfType<IdentityEvent>();
    }

    [Fact]
    public async Task NoEventType_PipelineGoesNoFurther()
    {
        var reached = false;
        var pipeline = new redb.Route.Processors.PipelineProcessor();
        pipeline.Add(_processor);
        pipeline.Add(new CaptureProcessor(_ => reached = true));

        var exchange = TokenRequestCopy();
        exchange.Properties.Remove("identity-event-type");
        await pipeline.Process(exchange);

        reached.Should().BeFalse("a request copy without an event must not be delivered anywhere");
    }

    private sealed class CaptureProcessor(Action<IMessage> capture) : IProcessor
    {
        public Task Process(IExchange exchange, CancellationToken ct = default)
        {
            capture(exchange.In);
            return Task.CompletedTask;
        }
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
        exchange.IsStopped.Should().BeTrue();
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
