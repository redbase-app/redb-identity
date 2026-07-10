using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// H3-SSO unit tests for <see cref="MeSessionsProcessor"/>. Covers the caller-id
/// precondition paths (missing / non-positive) which reject <b>before</b>
/// touching any redb service, so no DB or <c>IRouteContext</c> is required.
/// Full happy-path list/revoke and ownership-mismatch flows are covered by the
/// integration suite where a real service is wired.
/// </summary>
public sealed class MeSessionsProcessorTests
{
    private static Exchange BuildExchange(long? userId, string operation)
    {
        var ex = new Exchange(new Message { Body = new Dictionary<string, object?>() });
        ex.In.Headers["operation"] = operation;
        if (userId is not null)
            ex.Properties["identity:management-user-id"] = userId.Value;
        return ex;
    }

    [Fact]
    public async Task MissingSubject_Returns401()
    {
        // IRouteContext is not reached — the subject check short-circuits first.
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: null, operation: "list");

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        ex.IsStopped.Should().BeTrue();
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("invalid_token");
    }

    [Fact]
    public async Task NonPositiveSubject_Returns401()
    {
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 0, operation: "list");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task RevokeCurrent_MissingSidClaim_Returns400_SidUnavailable()
    {
        // Caller is authenticated (subject present) but the token has no sid claim
        // (e.g. client_credentials grant). revoke-current is inapplicable → 400.
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 42, operation: "revoke-current");

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("sid_unavailable");
    }

    [Fact]
    public async Task RevokeCurrent_NonNumericSid_Returns400()
    {
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 42, operation: "revoke-current");
        ex.Properties["identity:management-sid"] = "not-a-number";

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
    }

    [Fact]
    public async Task RevokeOthers_MissingSubject_Returns401()
    {
        // Same subject-precondition as every other operation — no token, no API.
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: null, operation: "revoke-others");

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("invalid_token");
    }

    [Fact]
    public async Task RevokeOthers_MissingSidClaim_DoesNotReject400()
    {
        // CRITICAL contract: unlike revoke-current, revoke-others MUST NOT 400 when sid
        // is absent — the processor falls through and revokes ALL sessions of the caller.
        //
        // This unit test only covers the *precondition gate*: the processor must NOT
        // short-circuit with a 400/sid_unavailable response. To prove the gate let through
        // we drive the processor with a null IRouteContext and assert two facts:
        //   1. Process(...) throws ArgumentNullException from RedbRouteExtensions
        //      .GetRedbService(...) (ThrowIfNull guard at the entry).
        //   2. The exchange was NOT stopped before the throw — i.e. no Reject(400) ran.
        // A regression that re-introduces the sid_unavailable check for revoke-others
        // would either set Out+IsStopped=true and return (no throw at all), violating #1,
        // or reach Reject before throwing, violating #2.
        //
        // The full happy-path (list → revoke-each → audit event) requires a wired
        // SessionService and is covered by the integration suite (see STATUS W-6 backlog).
        var sut = new MeSessionsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 42, operation: "revoke-others");

        var act = async () => await sut.Process(ex);

        await act.Should().ThrowAsync<ArgumentNullException>();
        ex.IsStopped.Should().BeFalse("revoke-others must not reject 400 for tokens without a sid claim");
    }
}
