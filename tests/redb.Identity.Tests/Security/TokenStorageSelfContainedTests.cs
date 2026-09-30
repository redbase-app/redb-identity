using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// What a token row holds. OpenIddict keeps an entry per issued access and refresh token (for revocation,
/// one-time redemption and reuse detection), and the question a database reader raises is whether that
/// entry contains the token itself. It does not: access and refresh tokens are self-contained (a JWS and a
/// JWE respectively), the store never sees the string handed to the client, and the row carries metadata
/// only — no <c>ReferenceId</c>, no payload in <c>note</c>. That is OpenIddict's default: reference tokens
/// are an opt-in (<c>UseReferenceAccessTokens</c> / <c>UseReferenceRefreshTokens</c>) this server does not
/// take, and the test pins that it stays untaken — a reference refresh token would be stored as the very
/// string the client presents, since the store writes what OpenIddict passes and OpenIddict passes it raw.
/// <para>
/// Authorization codes, device codes, user codes and pushed-authorization request tokens are reference
/// tokens by OpenIddict's design (the client can only ever present an opaque handle for them); those rows do
/// hold the handle and an encrypted payload, and live for minutes as one-shot values.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class TokenStorageSelfContainedTests
{
    private readonly ProductionHttpFixture _fx;

    public TokenStorageSelfContainedTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Access_and_refresh_tokens_leave_no_readable_trace_in_their_rows()
    {
        var resp = await _fx.Http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid offline_access",
        }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "password grant failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var access = json.GetProperty("access_token").GetString()!;
        var refresh = json.GetProperty("refresh_token").GetString()!;

        // Shape first: a compact JWE has five segments, so the refresh token is self-contained and readable
        // only with the server's encryption key. The access token is a plain JWS here because the fixture
        // disables access-token encryption; in production it is a JWE too.
        refresh.Split('.').Should().HaveCount(5, "refresh tokens are encrypted, self-contained JWTs, not reference handles");
        access.Split('.').Should().HaveCount(3);

        var subject = Guid.Parse(Sub(access));

        await _fx.UseRedbAsync(async redb =>
        {
            (await redb.GetByUniqueAsync<TokenProps>(p => p.ReferenceId, refresh)).Should().BeNull(
                "the string handed to the client is not a lookup key in the store");
            (await redb.GetByUniqueAsync<TokenProps>(p => p.ReferenceId, access)).Should().BeNull();

            var refreshRows = await redb.Query<TokenProps>()
                .WhereRedb(o => o.ValueGuid == subject)
                .Where(p => p.Type == "refresh_token")
                .ToListAsync();
            var accessRows = await redb.Query<TokenProps>()
                .WhereRedb(o => o.ValueGuid == subject)
                .Where(p => p.Type == "access_token")
                .ToListAsync();
            refreshRows.Should().NotBeEmpty("OpenIddict keeps an entry per refresh token for redemption and reuse detection");
            accessRows.Should().NotBeEmpty("OpenIddict keeps an entry per access token for revocation");

            foreach (var row in refreshRows.Concat(accessRows))
            {
                row.note.Should().BeNull("no payload is persisted for a self-contained token (payload lives in note)");
                row.Props.ReferenceId.Should().BeNull("a self-contained token has no reference handle");
                row.value_string.Should().BeNull("nor a legacy mirror of one");
            }
        });
    }

    private static string Sub(string jws)
    {
        var payload = jws.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        return doc.RootElement.GetProperty("sub").GetString()!;
    }
}
