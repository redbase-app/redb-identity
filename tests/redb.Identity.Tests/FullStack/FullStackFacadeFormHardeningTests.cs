using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using System.Text;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Http.Processors;
using redb.Identity.Http.Security;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Hardening of the HTTP facade's own HTML forms (login, consent, MFA), end to end.
/// <para>
/// Three findings of 2026-09-09, all previously absent from the facade while present in
/// the web console: (1) no browser-protection headers, so every facade page could be framed
/// (clickjacking on the consent "Allow" button); (2) the consent POST trusted a hidden
/// <c>user_id</c> field over the session and <c>ReadSessionCookie</c> let cookie-less
/// requests through, so an anonymous cross-site POST recorded any user's consent for any
/// client; (3) no cross-site request check on any form POST (login CSRF). The web console's
/// BFF and the demo scripts post these forms without a browser — hence the Origin/Referer
/// model rather than a form token: a request that announces no origin is let through, one
/// that announces a foreign origin is refused.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class FullStackFacadeFormHardeningTests
{
    private readonly ProductionHttpFixture _fx;

    public FullStackFacadeFormHardeningTests(ProductionHttpFixture fx) => _fx = fx;

    // ─────────────────────────────────────────────────────────────────────────
    //  (1) browser-protection headers
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("/login")]
    [InlineData("/consent?client_id=e2e-explicit-consent&scopes=openid")]
    [InlineData("/.well-known/openid-configuration")]
    public async Task FacadeResponses_CarryFrameAndSniffProtection(string path)
    {
        var resp = await Anonymous().GetAsync(path);

        HeaderValue(resp, "X-Frame-Options").Should().Be("DENY",
            "the facade renders login/consent/MFA pages itself and none may be framed");
        HeaderValue(resp, "Content-Security-Policy").Should().Contain("frame-ancestors 'none'");
        HeaderValue(resp, "X-Content-Type-Options").Should().Be("nosniff");
        HeaderValue(resp, "Referrer-Policy").Should().NotBeNullOrEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  (2) consent is bound to the session, never to a form field
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConsentPost_WithoutSession_Is401_AndRecordsNothing()
    {
        var victim = Random.Shared.NextInt64(1_000_000_000, long.MaxValue);
        var appId = await AppObjectIdAsync(ProductionHttpFixture.TestConsentClientId);

        var resp = await Anonymous().PostAsync("/consent", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ProductionHttpFixture.TestConsentClientId,
            ["user_id"] = victim.ToString(),
            ["scopes"] = "openid profile",
            ["decision"] = "allow",
            ["returnUrl"] = "/connect/authorize?client_id=x",
        }));

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "a consent decision without a session cookie is not a decision anyone made; body: {0}",
            await resp.Content.ReadAsStringAsync());
        HeaderValue(resp, "X-Frame-Options").Should().Be("DENY", "rejections carry the same headers");
        (await ConsentsOfAsync(victim, appId)).Should().BeEmpty(
            "before the fix this anonymous POST recorded a permanent authorization for the victim");
    }

    [Fact]
    public async Task ConsentPost_IgnoresFormUserId_AndGrantsForTheSessionUser()
    {
        var forged = Random.Shared.NextInt64(1_000_000_000, long.MaxValue);
        var clientId = await SeedExplicitConsentClientAsync();
        var appId = await AppObjectIdAsync(clientId);

        var cookies = new CookieContainer();
        using var browser = CreateBrowserClient(cookies);
        await LoginAsync(browser);

        var resp = await browser.PostAsync("/consent", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["user_id"] = forged.ToString(),
            ["scopes"] = "openid profile",
            ["decision"] = "allow",
            ["returnUrl"] = "/connect/authorize?client_id=" + clientId,
        }));

        resp.StatusCode.Should().BeOneOf(new[] { HttpStatusCode.Found, HttpStatusCode.SeeOther },
            "a logged-in user's decision is accepted and redirected back to the authorize URL");
        (await ConsentsOfAsync(forged, appId)).Should().BeEmpty("the form's user_id is not who consented");

        var recorded = await _fx.UseRedbAsync(async redb => await redb.Query<AuthorizationProps>()
            .Where(a => a.ApplicationObjectId == appId)
            .ToListAsync());
        recorded.Should().ContainSingle("exactly one grant — the session user's — exists for a fresh client")
            .Which.key.Should().NotBe(forged);
    }

    [Fact]
    public async Task ConsentPage_NoLongerEmbedsAUserId()
    {
        var resp = await Anonymous().GetAsync("/consent?client_id=e2e-explicit-consent&scopes=openid&user_id=42");
        var html = await resp.Content.ReadAsStringAsync();

        html.Should().NotContain("name=\"user_id\"",
            "the consenting user is the session's, so the form has nothing to say about it");
    }

    [Fact]
    public async Task ConsentPage_WithoutTicket_IsRefused_NotRenderedFromQuery()
    {
        // The phishing link: a crafted /consent URL naming the attacker's client under a
        // familiar app name. Before the fix the page rendered app_name straight from the query.
        var resp = await Anonymous().GetAsync(
            "/consent?client_id=e2e-attacker&app_name=Your%20Bank&scopes=openid%20profile");
        var html = await resp.Content.ReadAsStringAsync();

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "the consent page renders only from a server-signed ticket, never from query parameters");
        html.Should().NotContain("Your Bank",
            "the attacker-supplied display name must never reach the operator's trusted UI");
    }

    [Fact]
    public async Task ConsentPost_WithTicketForAnotherUser_Is403()
    {
        // Same DataProtection provider (and purpose) as the facade's own instance, so the server
        // accepts the signature — the fixture constructs its ticket service inline, not via DI.
        var ticketService = new SessionTicketService(
            _fx.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>());
        var otherUser = Random.Shared.NextInt64(1_000_000_000, long.MaxValue);
        var ticket = ticketService.ProtectConsent(new ConsentTicket(
            UserId: otherUser, ClientId: ProductionHttpFixture.TestConsentClientId,
            AppName: "App", Scopes: "openid", ReturnUrl: "/connect/authorize?client_id=x"));

        var cookies = new CookieContainer();
        using var browser = CreateBrowserClient(cookies);
        await LoginAsync(browser);

        var req = new HttpRequestMessage(HttpMethod.Post, "/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["ct"] = ticket,
                ["decision"] = "allow",
            })
        };
        req.Headers.TryAddWithoutValidation("Origin", _fx.BaseUrl);

        var resp = await browser.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a ticket minted for another user cannot be replayed under this session");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  (4) session identity is never trusted from an HTTP header
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_WithForgedSessionHeader_DoesNotAuthenticate()
    {
        var victim = Random.Shared.NextInt64(1_000_000_000, long.MaxValue);
        var (verifier, challenge) = Pkce();
        var url = "/connect/authorize?response_type=code"
                + $"&client_id={ProductionHttpFixture.TestPublicClientId}"
                + $"&redirect_uri={Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri)}"
                + "&scope=openid"
                + $"&code_challenge={challenge}&code_challenge_method=S256";

        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.TryAddWithoutValidation("session_user_id", victim.ToString());
        req.Headers.TryAddWithoutValidation("session_username", "victim");

        var resp = await Anonymous().SendAsync(req);

        // The property under test: the forged header does NOT authenticate. Before the fix this
        // request was answered with a 302 to the client's redirect_uri carrying a code for the
        // victim. Unauthenticated, the facade sends the browser to /login (or answers with an
        // OAuth error) — never to the redirect_uri, never with a code.
        var location = resp.Headers.Location?.ToString() ?? "";
        location.Should().NotStartWith(ProductionHttpFixture.TestRedirectUri,
            "a session_user_id sent as an HTTP header must NOT mint an authorization code — "
            + "before the fix the header was copied into the exchange and trusted as the principal");
        location.Should().NotContain("code=");
        resp.Headers.Contains("Set-Cookie").Should().BeFalse("no session is established by a header");
        if (resp.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther)
            location.Should().StartWith("/login", "an unauthenticated authorize request goes to the login page");
        else
            ((int)resp.StatusCode).Should().BeGreaterThanOrEqualTo(400, "or is refused as login_required");
    }

    [Fact]
    public async Task AuditLog_IgnoresForgedAttributionHeaders_AndRecordsTheRealClient()
    {
        // EventDispatchProcessor reads user_id / ip_address / user_agent from the WireTap copy
        // of the business exchange — the same In.Headers the HTTP consumer fills from the
        // request. Before the fix a client could sign the security log with someone else's
        // user id, a fabricated address and a fabricated agent.
        // Revocation is one of the WireTap-audited routes reachable over HTTP (TokenRevoked).
        var realAgent = $"hardening-probe/{Guid.NewGuid():N}";
        const string forgedIp = "203.0.113.77";
        const string forgedAgent = "forged-agent/1.0";
        const long forgedUser = 987_654_321L;

        var token = await IssueClientCredentialsTokenAsync();
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/revocation")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = ProductionHttpFixture.TestClientId,
                ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            })
        };
        req.Headers.TryAddWithoutValidation("User-Agent", realAgent);
        req.Headers.TryAddWithoutValidation("ip_address", forgedIp);
        req.Headers.TryAddWithoutValidation("user_agent", forgedAgent);
        req.Headers.TryAddWithoutValidation("user_id", forgedUser.ToString());
        var resp = await Anonymous().SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "RFC 7009: revocation answers 200: {0}",
            await resp.Content.ReadAsStringAsync());

        var row = await FindAuditRowAsync("TokenRevoked",
            i => AgentOf(i) == realAgent || AgentOf(i) == forgedAgent);

        row.Should().NotBeNull("the revocation must be audited; newest TokenRevoked rows seen: {0}",
            await DescribeAuditRowsAsync("TokenRevoked"));
        AgentOf(row!.Value).Should().Be(realAgent, "the audited agent is the real User-Agent, not the forged internal header");
        var ip = Field(row.Value, "ipAddress", "ip_address");
        ip.Should().NotBe(forgedIp, "the audited address is the transport's, not a header the client typed");
        ip.Should().NotBeNullOrEmpty("HTTP-originated events fall back to the proxy-sanitized remote address");
        var userId = NumberField(row.Value, "userId", "user_id");
        userId.Should().NotBe(forgedUser,
            "a client-credentials token has no end-user; the audited user id must not be the header the client typed");

        // Attribution the row must carry: the form-authenticated client (client_id used to be a header
        // only for Basic auth, so form-auth clients were audited as NULL) and a real timestamp (the
        // SQLite audit table declared TEXT while the provider writes Julian REAL, so it read back as
        // 0001-01-01 and date filters compared text to a number).
        Field(row.Value, "clientId", "client_id").Should().Be(ProductionHttpFixture.TestClientId,
            "the revoking client authenticated with form credentials and must be attributed");
        var ts = Field(row.Value, "timestamp", "timestamp");
        ts.Should().NotBeNullOrEmpty();
        DateTimeOffset.Parse(ts!, System.Globalization.CultureInfo.InvariantCulture).Should()
            .BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(10),
                "the audit timestamp must round-trip through the provider's datetime encoding");
    }

    private async Task<string> IssueClientCredentialsTokenAsync()
    {
        var resp = await Anonymous().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
        }));
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "token issuance must succeed: {0}", body);
        return System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString()!;
    }

    [Fact]
    public void StripReservedInboundHeaders_RemovesInternalIdentityHeaders()
    {
        var ex = new redb.Route.Core.Exchange(new redb.Route.Core.Message());
        ex.In.Headers["session_user_id"] = "42";
        ex.In.Headers["session_id"] = "100";
        ex.In.Headers["access_token"] = "forged";
        ex.In.Headers["operation"] = "delete";
        ex.In.Headers["X-Correlation-Id"] = "keep-me";

        redb.Identity.Http.Processors.HttpIdentityProcessors.StripReservedInboundHeaders(ex);

        ex.In.Headers.ContainsKey("session_user_id").Should().BeFalse();
        ex.In.Headers.ContainsKey("session_id").Should().BeFalse();
        ex.In.Headers.ContainsKey("access_token").Should().BeFalse();
        ex.In.Headers.ContainsKey("operation").Should().BeFalse("over HTTP the operation is derived from method and path");
        ex.In.Headers.ContainsKey("X-Correlation-Id").Should().BeTrue("only reserved internal names are stripped");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  (3) cross-site form posts are refused, origin-less callers are not
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Origin", "https://evil.example")]
    [InlineData("Referer", "https://evil.example/phish.html")]
    [InlineData("Origin", "null")]
    public async Task LoginPost_FromForeignOrigin_Is403_AndSetsNoSession(string header, string value)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/login") { Content = CredentialsForm() };
        req.Headers.TryAddWithoutValidation(header, value);

        var resp = await Anonymous().SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a browser form submitted from another site announces it and is refused before credentials are read");
        resp.Headers.Contains("Set-Cookie").Should().BeFalse("no session may be planted by a cross-site login");
    }

    [Fact]
    public async Task LoginPost_FromOwnOrigin_IsProcessed()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/login") { Content = CredentialsForm() };
        req.Headers.TryAddWithoutValidation("Origin", _fx.BaseUrl);

        var resp = await Anonymous().SendAsync(req);

        resp.StatusCode.Should().NotBe(HttpStatusCode.Forbidden, "the facade's own page posting to itself is the normal case");
        resp.Headers.Contains("Set-Cookie").Should().BeTrue("a same-origin login still produces the session");
    }

    [Fact]
    public async Task LoginPost_WithoutOriginOrReferer_IsProcessed()
    {
        var resp = await Anonymous().PostAsync("/login", CredentialsForm());

        resp.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            "the web console's BFF, the demo scripts and API clients post without a browser origin");
        resp.Headers.Contains("Set-Cookie").Should().BeTrue();
    }

    [Fact]
    public async Task ConsentPost_FromForeignOrigin_Is403_EvenWithASession()
    {
        var cookies = new CookieContainer();
        using var browser = CreateBrowserClient(cookies);
        await LoginAsync(browser);

        var req = new HttpRequestMessage(HttpMethod.Post, "/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ProductionHttpFixture.TestConsentClientId,
                ["scopes"] = "openid",
                ["decision"] = "allow",
            })
        };
        req.Headers.TryAddWithoutValidation("Origin", "https://evil.example");

        var resp = await browser.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a cross-site form carrying the victim's cookie is exactly the CSRF the guard exists for");
    }

    [Theory]
    [InlineData("https://op.example", "https://op.example/", null, true)]
    [InlineData("https://op.example:443", "https://op.example/", null, true)]
    [InlineData("https://OP.example", "https://op.example/", null, true)]
    [InlineData("https://evil.example", "https://op.example/", null, false)]
    [InlineData("https://op.example.evil.net", "https://op.example/", null, false)]
    [InlineData("null", "https://op.example/", null, false)]
    [InlineData("garbage", "https://op.example/", null, false)]
    [InlineData("https://internal-name:8443", "https://op.example/", "internal-name:8443", true)]
    [InlineData("https://internal-name", "https://op.example/", "internal-name:443", true)]
    [InlineData("https://evil.example", "https://op.example/", "internal-name:8443", false)]
    public void IsOwnOrigin_MatchesIssuerOrAddressedHost(string announced, string issuer, string? host, bool expected)
    {
        AntiForgeryProcessors.IsOwnOrigin(announced, new Uri(issuer), host).Should().Be(expected);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static string? HeaderValue(HttpResponseMessage resp, string name)
        => resp.Headers.TryGetValues(name, out var v) ? string.Join(",", v)
         : resp.Content.Headers.TryGetValues(name, out var cv) ? string.Join(",", cv)
         : null;

    /// <summary>
    /// A fresh client per call: no cookie jar (so a login in one test can never lend its
    /// session to an "anonymous" request in another) and no redirect following (so a 302 to
    /// the client's redirect_uri is observed, not chased to a dead port).
    /// </summary>
    private HttpClient Anonymous()
        => new(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            { BaseAddress = new Uri(_fx.BaseUrl) };

    // The management API serialises audit items in camelCase (the DTO attributes say snake_case,
    // the facade serialiser wins) — read the field by either name.
    private static string? Field(System.Text.Json.JsonElement item, string camel, string snake)
        => item.TryGetProperty(camel, out var c) && c.ValueKind == System.Text.Json.JsonValueKind.String ? c.GetString()
         : item.TryGetProperty(snake, out var s) && s.ValueKind == System.Text.Json.JsonValueKind.String ? s.GetString()
         : null;

    private static string? AgentOf(System.Text.Json.JsonElement item) => Field(item, "userAgent", "user_agent");

    private static long NumberField(System.Text.Json.JsonElement item, string camel, string snake)
        => item.TryGetProperty(camel, out var c) && c.ValueKind == System.Text.Json.JsonValueKind.Number ? c.GetInt64()
         : item.TryGetProperty(snake, out var s) && s.ValueKind == System.Text.Json.JsonValueKind.Number ? s.GetInt64()
         : 0;

    /// <summary>
    /// The audit sink is fed by a WireTap and flushes asynchronously; poll the management
    /// audit query until the row appears (or give up after a few seconds).
    /// </summary>
    private async Task<System.Text.Json.JsonElement?> FindAuditRowAsync(
        string eventType, Func<System.Text.Json.JsonElement, bool> match)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/identity/audit?eventType={eventType}&count=100");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
            var resp = await Anonymous().SendAsync(req);
            if (resp.IsSuccessStatusCode)
            {
                var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
                foreach (var item in doc.RootElement.GetProperty("items").EnumerateArray())
                    if (match(item)) return item.Clone();
            }
            await Task.Delay(250);
        }
        return null;
    }

    private async Task<string> DescribeAuditRowsAsync(string eventType)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/identity/audit?eventType={eventType}&count=5");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        var resp = await Anonymous().SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) return $"{(int)resp.StatusCode}: {body}";
        return body.Length > 1500 ? body[..1500] : body;
    }

    private static (string verifier, string challenge) Pkce()
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    private static FormUrlEncodedContent CredentialsForm() => new(new Dictionary<string, string>
    {
        ["username"] = ProductionHttpFixture.TestUsername,
        ["password"] = ProductionHttpFixture.TestPassword,
    });

    private HttpClient CreateBrowserClient(CookieContainer cookies)
    {
        var handler = new HttpClientHandler { CookieContainer = cookies, AllowAutoRedirect = false, UseCookies = true };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
    }

    private static async Task LoginAsync(HttpClient browser)
    {
        var resp = await browser.PostAsync("/login", CredentialsForm());
        resp.Headers.Contains("Set-Cookie").Should().BeTrue("login must establish the session: {0}",
            await resp.Content.ReadAsStringAsync());
    }

    private async Task<string> SeedExplicitConsentClientAsync()
    {
        var clientId = $"e2e-form-consent-{Guid.NewGuid():N}"[..40];
        var manager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = clientId,
            RedirectUris = { new Uri(ProductionHttpFixture.TestRedirectUri) },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Scopes.Profile,
            }
        });
        return clientId;
    }

    private Task<long> AppObjectIdAsync(string clientId)
        => _fx.UseRedbAsync(async redb =>
            (await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, clientId))!.Id);

    private Task<List<RedbObject<AuthorizationProps>>> ConsentsOfAsync(long userId, long appId)
        => _fx.UseRedbAsync(async redb => await redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.ApplicationObjectId == appId)
            .ToListAsync());
}
