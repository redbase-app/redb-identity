using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Sessions;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class RevokedSidsClientTests
{
    private const string Base = "/api/v1/identity/revoked-sids";

    [Fact]
    public async Task AddRevokedSid_POSTs_request_body_with_all_fields()
    {
        HttpRequestMessage? captured = null;
        var fx = new IdentityClientFixture(req =>
        {
            captured = req;
            var entry = new RevokedSidEntry
            {
                Sid = "s1", Sub = "u1", ClientId = "c1",
                RevokedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(8)
            };
            return TestKit.FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK, IdentityClientFixture.Json(entry));
        });

        var expires = DateTimeOffset.UtcNow.AddHours(2);
        var result = await fx.Client.AddRevokedSidAsync("s1", "u1", "c1", expires);

        captured!.Method.Should().Be(HttpMethod.Post);
        captured.RequestUri!.AbsolutePath.Should().Be(Base);

        var bodyJson = await captured.Content!.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(bodyJson);
        doc.RootElement.GetProperty("sid").GetString().Should().Be("s1");
        doc.RootElement.GetProperty("sub").GetString().Should().Be("u1");
        doc.RootElement.GetProperty("clientId").GetString().Should().Be("c1");
        doc.RootElement.GetProperty("expiresAt").GetString().Should().NotBeNullOrEmpty();

        result.Sid.Should().Be("s1");
        result.Sub.Should().Be("u1");
    }

    [Fact]
    public async Task AddRevokedSid_with_sub_only_omits_sid()
    {
        HttpRequestMessage? captured = null;
        var fx = new IdentityClientFixture(req =>
        {
            captured = req;
            var entry = new RevokedSidEntry
            {
                Sub = "u1",
                RevokedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(8)
            };
            return FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK, IdentityClientFixture.Json(entry));
        });

        await fx.Client.AddRevokedSidAsync(sid: null, sub: "u1", clientId: null);

        var bodyJson = await captured!.Content!.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(bodyJson);
        doc.RootElement.GetProperty("sid").ValueKind.Should().Be(JsonValueKind.Null);
        doc.RootElement.GetProperty("sub").GetString().Should().Be("u1");
    }

    [Fact]
    public async Task GetRevokedSidsSince_GETs_without_cursor_when_null()
    {
        HttpRequestMessage? captured = null;
        var fx = new IdentityClientFixture(req =>
        {
            captured = req;
            return FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK,
                IdentityClientFixture.Json(new RevokedSidsSinceResponse
                {
                    Entries = new(),
                    NextCursor = DateTimeOffset.UtcNow,
                    ServerTime = DateTimeOffset.UtcNow
                }));
        });

        var resp = await fx.Client.GetRevokedSidsSinceAsync(cursor: null);

        captured!.Method.Should().Be(HttpMethod.Get);
        captured.RequestUri!.PathAndQuery.Should().Be($"{Base}/since");
        resp.Entries.Should().BeEmpty();
    }

    [Fact]
    public async Task GetRevokedSidsSince_with_cursor_url_encodes_iso_timestamp()
    {
        HttpRequestMessage? captured = null;
        var fx = new IdentityClientFixture(req =>
        {
            captured = req;
            return FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK,
                IdentityClientFixture.Json(new RevokedSidsSinceResponse
                {
                    Entries = new()
                    {
                        new RevokedSidEntry
                        {
                            Sid = "s1",
                            RevokedAt = DateTimeOffset.UtcNow,
                            ExpiresAt = DateTimeOffset.UtcNow.AddHours(8)
                        }
                    },
                    NextCursor = DateTimeOffset.UtcNow,
                    ServerTime = DateTimeOffset.UtcNow
                }));
        });

        var cursor = new DateTimeOffset(2025, 4, 1, 12, 30, 0, TimeSpan.Zero);
        var resp = await fx.Client.GetRevokedSidsSinceAsync(cursor);

        captured!.RequestUri!.AbsolutePath.Should().Be($"{Base}/since");
        captured.RequestUri.Query.Should().Contain("cursor=");
        // Round-trip the encoded cursor to verify it parses back to the same instant.
        var rawCursor = System.Web.HttpUtility.ParseQueryString(captured.RequestUri.Query)["cursor"];
        DateTimeOffset.Parse(rawCursor!).Should().Be(cursor);

        resp.Entries.Should().HaveCount(1);
        resp.Entries[0].Sid.Should().Be("s1");
    }
}
