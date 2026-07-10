using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Audit;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class AuditClientTests
{
    [Fact]
    public async Task QueryAudit_GET_default_offset_count()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new AuditQueryResponse { Total = 0, Count = 50, Items = [] }));
        await fx.Client.QueryAuditAsync(new AuditQueryRequest());
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/audit?offset=0&count=50");
    }

    [Fact]
    public async Task QueryAudit_GET_full_filter_serialized()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new AuditQueryResponse { Total = 0, Count = 25, Items = [] }));
        var filter = new AuditQueryRequest
        {
            EventType = "user.login",
            Category = "authentication",
            UserId = "alice",
            ClientId = "client-x",
            From = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero),
            To = new DateTimeOffset(2026, 5, 2, 0, 0, 0, TimeSpan.Zero),
            Offset = 0,
            Count = 25,
        };
        await fx.Client.QueryAuditAsync(filter);

        var qs = fx.Handler.Requests.Single().RequestUri!.PathAndQuery;
        qs.Should().StartWith("/api/v1/identity/audit?")
          .And.Contain("eventType=user.login")
          .And.Contain("category=authentication")
          .And.Contain("userId=alice")
          .And.Contain("clientId=client-x")
          .And.Contain("from=")
          .And.Contain("to=")
          .And.Contain("offset=0")
          .And.Contain("count=25");
    }

    [Fact]
    public async Task QueryAudit_parses_AuditQueryResponse_DTO()
    {
        var dto = new AuditQueryResponse
        {
            Total = 1, Offset = 0, Count = 25,
            Items = [new AuditQueryItem { EventId = "e1", EventType = "x", Category = "y", Timestamp = DateTimeOffset.UnixEpoch }]
        };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(dto));
        var result = await fx.Client.QueryAuditAsync(new AuditQueryRequest { Count = 25 });
        result.Items.Should().ContainSingle().Which.EventId.Should().Be("e1");
    }
}
