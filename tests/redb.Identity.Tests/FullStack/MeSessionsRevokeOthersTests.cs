using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// W6 — full-stack coverage for <c>DELETE /api/v1/identity/me/sessions/others</c>.
/// <para>
/// Closes the gap called out by <see cref="redb.Identity.Tests.Routes.MeSessionsProcessorTests"/>:
/// the processor-level unit tests can only assert the precondition gates, while the
/// happy path (list → revoke-each → audit event) requires the wired SessionService and
/// a token carrying the correct <c>sub</c> / <c>sid</c> claims. That can only be exercised
/// through the actual HTTP pipeline.
/// </para>
/// <para>
/// Two paths are pinned:
/// <list type="number">
///   <item>
///     A token with a <c>sid</c> claim (issued via the interactive auth code + PKCE flow)
///     revokes every session of the caller <b>except</b> the one bound to <c>sid</c>.
///   </item>
///   <item>
///     A token without a <c>sid</c> claim revokes <b>all</b> sessions of the caller —
///     the documented contract for non-OIDC-session grants (e.g. password / client_credentials
///     style flows). The endpoint must <b>NOT</b> short-circuit with
///     <c>400 sid_unavailable</c> here.
///   </item>
/// </list>
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class MeSessionsRevokeOthersTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public MeSessionsRevokeOthersTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    [Fact]
    public async Task RevokeOthers_TokenWithSid_KeepsCurrentSessionOnly()
    {
        // 1. Obtain a user-bound access token through the interactive auth code + PKCE
        //    flow. AttachSessionPrincipalHandler stamps the resulting principal with a
        //    sid claim → the access token carries sid = current session id.
        var (accessToken, sessionId) = await IssueAccessTokenWithSidAsync();
        sessionId.Should().BeGreaterThan(0, "auth code flow must produce a sid-bound session");

        // 2. Seed two extra sessions for the same user so revoke-others has actual work
        //    to do. Direct SessionService.CreateAsync is the standard side-channel used
        //    in FullStackSessionTests and bypasses the OIDC machinery.
        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new InvalidOperationException("Test user missing");

        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestPublicClientId)
            .FirstOrDefaultAsync()
            ?? throw new InvalidOperationException("Public PKCE client not seeded");

        var extra1 = await sessionService.CreateAsync(coreUser.Id, app.id);
        var extra2 = await sessionService.CreateAsync(coreUser.Id, app.id);

        try
        {
            // 3. Verify list endpoint sees all three sessions (current + 2 extras).
            var beforeIds = await ListSessionIdsAsync(accessToken);
            beforeIds.Should().Contain(new[] { sessionId, extra1.id, extra2.id },
                "all three sessions must be visible before revoke-others is called");

            // 4. Fire DELETE /me/sessions/others. Endpoint MUST revoke extra1 + extra2
            //    while keeping the sid-bound current session alive.
            using var req = WithAuth(
                new HttpRequestMessage(HttpMethod.Delete, "/api/v1/identity/me/sessions/others"),
                accessToken);

            var resp = await _http.SendAsync(req);
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                "revoke-others must succeed (got {0}: {1})",
                resp.StatusCode, await resp.Content.ReadAsStringAsync());

            var body = await ParseJsonAsync(resp);
            body.GetProperty("success").GetBoolean().Should().BeTrue();
            body.GetProperty("revoked").GetInt32().Should().BeGreaterOrEqualTo(2,
                "extra1 and extra2 must be counted as revoked; current session must not");

            // 5. Verify the post-state: current is still listed, extras are gone.
            var afterIds = await ListSessionIdsAsync(accessToken);
            afterIds.Should().Contain(sessionId,
                "the sid-bound current session must survive revoke-others");
            afterIds.Should().NotContain(extra1.id,
                "extra1 must be revoked by revoke-others");
            afterIds.Should().NotContain(extra2.id,
                "extra2 must be revoked by revoke-others");
        }
        finally
        {
            // Best-effort cleanup so subsequent tests start clean even on failure.
            try { await sessionService.RevokeAsync(extra1.id); } catch { /* already revoked */ }
            try { await sessionService.RevokeAsync(extra2.id); } catch { /* already revoked */ }
            try { await sessionService.RevokeAsync(sessionId); } catch { /* may have been collected */ }
        }
    }

    [Fact]
    public async Task RevokeOthers_TokenWithoutSid_RevokesAllUserSessions()
    {
        // Tokens issued via grants that do NOT go through AttachSessionPrincipalHandler
        // (password grant on the confidential client) carry no sid. Contract: revoke-
        // others on such a token revokes EVERY session of the caller — never returns
        // 400 sid_unavailable for the others variant.
        var accessToken = await IssueAccessTokenViaPasswordGrantAsync();
        if (accessToken is null)
            return; // password grant disabled in this env — soft skip.

        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new InvalidOperationException("Test user missing");

        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestPublicClientId)
            .FirstOrDefaultAsync()
            ?? throw new InvalidOperationException("Public PKCE client not seeded");

        var s1 = await sessionService.CreateAsync(coreUser.Id, app.id);
        var s2 = await sessionService.CreateAsync(coreUser.Id, app.id);

        try
        {
            using var req = WithAuth(
                new HttpRequestMessage(HttpMethod.Delete, "/api/v1/identity/me/sessions/others"),
                accessToken);

            var resp = await _http.SendAsync(req);
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                "revoke-others MUST succeed even without sid (got {0}: {1})",
                resp.StatusCode, await resp.Content.ReadAsStringAsync());

            var body = await ParseJsonAsync(resp);
            body.GetProperty("success").GetBoolean().Should().BeTrue();
            body.GetProperty("revoked").GetInt32().Should().BeGreaterOrEqualTo(2,
                "both seeded sessions must be counted as revoked");

            var remaining = await ListSessionIdsAsync(accessToken);
            remaining.Should().NotContain(s1.id, "no-sid revoke-others must revoke s1");
            remaining.Should().NotContain(s2.id, "no-sid revoke-others must revoke s2");
        }
        finally
        {
            try { await sessionService.RevokeAsync(s1.id); } catch { /* already revoked */ }
            try { await sessionService.RevokeAsync(s2.id); } catch { /* already revoked */ }
        }
    }

    // ────────────────── helpers ──────────────────

    private static HttpRequestMessage WithAuth(HttpRequestMessage request, string token)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private async Task<long[]> ListSessionIdsAsync(string accessToken)
    {
        using var req = WithAuth(
            new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/me/sessions"),
            accessToken);

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "GET /me/sessions must succeed (got {0}: {1})",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());

        var json = await ParseJsonAsync(resp);
        json.ValueKind.Should().Be(JsonValueKind.Array);

        var ids = new List<long>();
        foreach (var item in json.EnumerateArray())
        {
            if (item.TryGetProperty("sessionId", out var sidProp))
                ids.Add(sidProp.GetInt64());
        }
        return ids.ToArray();
    }

    /// <summary>
    /// Drives /login → /connect/authorize → /connect/token with PKCE and the
    /// identity:account scope so the resulting access token carries both sub
    /// (caller id) and sid (current session id).
    /// </summary>
    private async Task<(string accessToken, long sessionId)> IssueAccessTokenWithSidAsync()
    {
        var (verifier, challenge) = GeneratePkce();
        var code = await AuthorizeAsync(
            ProductionHttpFixture.TestPublicClientId,
            challenge,
            scope: "openid identity:account");

        code.Should().NotBeNullOrEmpty("authorize must produce a code");

        var resp = await _http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
                ["client_id"] = ProductionHttpFixture.TestPublicClientId,
                ["code_verifier"] = verifier,
            }));

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange failed: {0}", await resp.Content.ReadAsStringAsync());

        var json = await ParseJsonAsync(resp);
        var accessToken = json.GetProperty("access_token").GetString()!;

        // Decode the unencrypted access token to read the sid claim. The fixture starts
        // OpenIddict with DisableAccessTokenEncryption() so the JWT payload is readable.
        var sid = ExtractSidClaim(accessToken);
        sid.Should().HaveValue("identity:account access token issued via the auth-code flow MUST carry a sid claim");

        return (accessToken, sid!.Value);
    }

    private async Task<string?> IssueAccessTokenViaPasswordGrantAsync()
    {
        var resp = await _http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = ProductionHttpFixture.TestUsername,
                ["password"] = ProductionHttpFixture.TestPassword,
                ["scope"] = "openid identity:account",
                ["client_id"] = ProductionHttpFixture.TestClientId,
                ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            }));

        if (!resp.IsSuccessStatusCode)
            return null; // password grant not granted to identity:account in this env

        var json = await ParseJsonAsync(resp);
        return json.GetProperty("access_token").GetString();
    }

    private async Task<string?> AuthorizeAsync(string clientId, string challenge, string scope)
    {
        var cookieJar = new System.Net.CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookieJar,
            UseCookies = true,
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        var loginResp = await client.PostAsync("/login", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["username"] = ProductionHttpFixture.TestUsername,
                ["password"] = ProductionHttpFixture.TestPassword,
            }));
        cookieJar.Count.Should().BeGreaterThan(0,
            "login must set a session cookie (got {0}: {1})",
            loginResp.StatusCode, await loginResp.Content.ReadAsStringAsync());

        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = scope,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };
        var resp = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));

        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNull();
            return ExtractQueryParam(location!, "code");
        }

        var json = await ParseJsonAsync(resp);
        if (json.TryGetProperty("code", out var c))
            return c.GetString();

        if (json.TryGetProperty("error", out var err))
            throw new InvalidOperationException(
                $"Authorize error: {err.GetString()} — " +
                (json.TryGetProperty("error_description", out var d) ? d.GetString() : "(no description)"));

        throw new InvalidOperationException($"Unexpected authorize response: {json.GetRawText()}");
    }

    private static (string verifier, string challenge) GeneratePkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }

    private static string? ExtractQueryParam(string url, string param)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        foreach (var pair in url[(idx + 1)..].Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv[0] == param) return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    /// <summary>
    /// Reads the <c>sid</c> claim out of an unencrypted JWT access token by base64url-
    /// decoding the payload segment. The fixture configures
    /// <c>DisableAccessTokenEncryption()</c>, so this is sufficient — no key material
    /// is needed (signature is not verified here, we trust the issuer that just minted it).
    /// </summary>
    private static long? ExtractSidClaim(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }

        var json = JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement;
        if (!json.TryGetProperty("sid", out var sidProp))
            return null;

        return sidProp.ValueKind switch
        {
            JsonValueKind.String => long.TryParse(sidProp.GetString(), out var s) ? s : null,
            JsonValueKind.Number => sidProp.TryGetInt64(out var n) ? n : null,
            _ => null,
        };
    }
}
