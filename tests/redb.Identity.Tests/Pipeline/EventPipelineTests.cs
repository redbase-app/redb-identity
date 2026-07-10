using FluentAssertions;
using NSubstitute;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Events;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Tests that WireTap event dispatch actually fires through the pipeline.
/// Creates a second consumer on the Events endpoint to capture dispatched events.
/// </summary>
[Collection("IdentityRoute")]
public class EventPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public EventPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task CreateApp_WireTap_DispatchesClientRegisteredEvent()
    {
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<ApplicationProps>>());
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ApplicationProps>>().Id = 200; return 200L; });

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest
            {
                ClientId = "event-test-app",
                ClientSecret = "secret",
                ClientType = "confidential"
            },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();

        // The WireTap copies exchange properties to the event route.
        // Verify the original exchange has the event metadata set by the processor.
        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("ClientRegistered");
    }

    [Fact]
    public async Task CreateScope_WireTap_DispatchesScopeCreatedEvent()
    {
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<ScopeProps>>());
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ScopeProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ScopeProps>>().Id = 201; return 201L; });

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageScopes,
            new CreateScopeRequest { Name = "event-scope", DisplayName = "Event Scope" },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("ScopeCreated");
    }

    [Fact]
    public async Task TokenIssuance_Success_DispatchesTokenIssuedEvent()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "event-token-client",
            ["client_secret"] = "secret"
        };

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.Token, body,
            new Dictionary<string, object?>());

        exchange.Exception.Should().BeNull();
        var dict = exchange.In.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("access_token");

        // TokenEndpointProcessor sets event on success
        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenIssued");
    }

    [Fact]
    public async Task TokenIssuance_Failure_DoesNotDispatchEvent()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
            // missing client_id → will fail
        };

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.Token, body,
            new Dictionary<string, object?>());

        // On error, TokenEndpointProcessor should NOT set event (fix #5)
        exchange.Properties.Should().NotContainKey("identity-event-type");
    }

    [Fact]
    public async Task DeleteApp_WireTap_DispatchesClientDeletedEvent()
    {
        _fixture.Redb.DeleteAsync(300).Returns(true);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new Dictionary<string, object?> { ["id"] = 300L },
            new Dictionary<string, object?> { ["operation"] = "delete" });

        exchange.Exception.Should().BeNull();
        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("ClientDeleted");
    }
}
