using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// W6-0: E2E test of the backchannel revoked-sids list. Exercises the full pipeline:
/// HTTP \u2192 RevokedSidsController \u2192 direct-vm://identity-revoked-sids \u2192
/// RevokedSidsManagementProcessor \u2192 redb PROPS. Uses real PostgreSQL + Kestrel via
/// <see cref="HttpIdentityFixture"/>.
/// </summary>
[Collection("HttpIdentity")]
public class RevokedSidsApiTests
{
    private const string Base = "/api/v1/identity/revoked-sids";

    private readonly HttpIdentityFixture _fixture;
    private readonly HttpClient _http;

    public RevokedSidsApiTests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
        _http = fixture.Http;
    }

    private HttpRequestMessage WithAuth(HttpRequestMessage request)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);
        return request;
    }

    private async Task<RevokedSidEntry> AddAsync(string? sid, string? sub, string? clientId = null,
        DateTimeOffset? expiresAt = null)
    {
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Post, Base)
        {
            Content = JsonContent.Create(new RevokedSidsAddRequest
            {
                Sid = sid, Sub = sub, ClientId = clientId, ExpiresAt = expiresAt
            })
        });
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "add should succeed; body: {0}", await resp.Content.ReadAsStringAsync());
        return (await resp.Content.ReadFromJsonAsync<RevokedSidEntry>())!;
    }

    private async Task<RevokedSidsSinceResponse> SinceAsync(DateTimeOffset? cursor = null)
    {
        var url = cursor.HasValue
            ? $"{Base}/since?cursor={Uri.EscapeDataString(cursor.Value.ToString("O"))}"
            : $"{Base}/since";
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Get, url));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "since should succeed; body: {0}", await resp.Content.ReadAsStringAsync());
        return (await resp.Content.ReadFromJsonAsync<RevokedSidsSinceResponse>())!;
    }

    [Fact]
    public async Task Add_then_Since_returns_entry()
    {
        var sid = $"sid-{Guid.NewGuid():N}";

        // Take cursor BEFORE adding so we know our entry is included.
        var before = await SinceAsync();
        var cursor = before.ServerTime;

        var added = await AddAsync(sid: sid, sub: "user-1");
        added.Sid.Should().Be(sid);
        added.Sub.Should().Be("user-1");
        added.RevokedAt.Should().BeAfter(DateTimeOffset.UtcNow.AddMinutes(-1));
        added.ExpiresAt.Should().BeAfter(added.RevokedAt);

        var after = await SinceAsync(cursor);
        after.Entries.Should().Contain(e => e.Sid == sid);
        after.NextCursor.Should().BeOnOrAfter(cursor);
    }

    [Fact]
    public async Task Since_with_recent_cursor_returns_only_newer()
    {
        var sidOld = $"sid-old-{Guid.NewGuid():N}";
        await AddAsync(sid: sidOld, sub: "user-1");

        // Cursor between the two adds.
        var mid = (await SinceAsync()).ServerTime;
        await Task.Delay(50); // ensure DateCreate strictly > mid

        var sidNew = $"sid-new-{Guid.NewGuid():N}";
        await AddAsync(sid: sidNew, sub: "user-1");

        var after = await SinceAsync(mid);
        after.Entries.Should().Contain(e => e.Sid == sidNew);
        after.Entries.Should().NotContain(e => e.Sid == sidOld);
    }

    [Fact]
    public async Task Add_with_sub_only_publishes_sub_entry()
    {
        var sub = $"sub-{Guid.NewGuid():N}";
        var cursor = (await SinceAsync()).ServerTime;

        var added = await AddAsync(sid: null, sub: sub);
        added.Sid.Should().BeNull();
        added.Sub.Should().Be(sub);

        var after = await SinceAsync(cursor);
        after.Entries.Should().Contain(e => e.Sub == sub && e.Sid == null);
    }

    [Fact]
    public async Task Add_without_sid_or_sub_returns_400_invalid_request()
    {
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Post, Base)
        {
            Content = JsonContent.Create(new RevokedSidsAddRequest
            {
                Sid = null, Sub = null, ClientId = "client-x"
            })
        });
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Add_clamps_excessive_expires_at_to_max_retention()
    {
        // Default RevokedSidsMaxRetention = 24h; request 30 days \u2192 server clamps.
        var huge = DateTimeOffset.UtcNow.AddDays(30);
        var sid = $"sid-clamp-{Guid.NewGuid():N}";
        var added = await AddAsync(sid: sid, sub: null, expiresAt: huge);
        added.ExpiresAt.Should().BeBefore(DateTimeOffset.UtcNow.AddDays(2));
        added.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow.AddHours(23));
    }

    [Fact]
    public async Task Add_requires_management_auth()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, Base)
        {
            Content = JsonContent.Create(new RevokedSidsAddRequest
            {
                Sid = "sid-noauth", Sub = "user-1"
            })
        };
        // No Authorization header.
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Since_first_call_without_cursor_returns_baseline_window()
    {
        // Sanity: bootstrap call returns a populated response with ServerTime and a cursor.
        var resp = await SinceAsync();
        resp.ServerTime.Should().BeAfter(DateTimeOffset.UtcNow.AddMinutes(-1));
        resp.NextCursor.Should().BeOnOrBefore(resp.ServerTime);
    }
}
