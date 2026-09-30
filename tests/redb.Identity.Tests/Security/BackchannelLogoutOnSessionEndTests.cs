using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// OIDC Back-Channel Logout 1.0 end to end, the way it happens in a browser: the End-User signs in at the
/// OP, a relying party obtains tokens through that session at the authorization endpoint, the relying party
/// later sends the browser to <c>end_session_endpoint</c> with its <c>id_token_hint</c>, and the OP POSTs a
/// <c>logout_token</c> to that relying party's <c>backchannel_logout_uri</c> naming the same <c>sub</c> the
/// id_token carried and the <c>sid</c> of the session that ended.
/// <para>
/// Browser sessions are created before any relying party is involved, so the session has to learn which
/// relying parties used it (<see cref="SessionProps.ClientApplicationIds"/>, bound at the authorization
/// endpoint). Without that binding a per-session logout had nobody to notify, and the only path that ever
/// reached a relying party was the unauthenticated logout-by-userId that has since been closed.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class BackchannelLogoutOnSessionEndTests
{
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private readonly ProductionHttpFixture _fx;

    public BackchannelLogoutOnSessionEndTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Ending_a_session_notifies_the_relying_parties_that_used_it_with_their_sub_and_sid()
    {
        var port = FreePort();
        var captured = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        var rp = new RouteContext(_fx.ServiceProvider, $"bclogout-rp-{port}");
        rp.AddComponent(new HttpComponent { ServerManager = new SharedHttpServerManager(new HttpHostingOptions()) });
        rp.AddRoutes(new Receiver(port, captured));
        await rp.Start();
        try
        {
            var client = await RegisterRelyingPartyAsync($"http://127.0.0.1:{port}/bclogout");

            using var browser = await LoginAsync();
            var session = await NewestActiveSessionAsync();

            var idToken = await IssueIdTokenAsync(browser, client);
            var idTokenClaims = Payload(idToken);
            idTokenClaims.GetProperty("sid").GetString().Should().Be(session.id.ToString(),
                "the id_token names the OP session it was issued through");
            var sub = idTokenClaims.GetProperty("sub").GetString()!;

            var logout = await browser.PostAsync("/connect/logout", Form(new() { ["id_token_hint"] = idToken }));
            ((int)logout.StatusCode).Should().BeOneOf(200, 302);

            var body = await captured.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var logoutToken = System.Web.HttpUtility.ParseQueryString(body)["logout_token"];
            logoutToken.Should().NotBeNullOrEmpty("the relying party must receive a logout_token form post");

            var jwt = new JwtSecurityTokenHandler { MapInboundClaims = false }.ReadJwtToken(logoutToken);
            jwt.Audiences.Should().ContainSingle().Which.Should().Be(client);
            jwt.Payload["sub"].Should().Be(sub, "the RP matches the logout token against the sub of its id_token");
            jwt.Payload["sid"].Should().Be(session.id.ToString(), "the RP ends exactly the session that ended at the OP");
            jwt.Payload.ContainsKey("events").Should().BeTrue();
            jwt.Payload["events"]!.ToString().Should().Contain(LogoutEvent);

            var ended = await _fx.UseRedbAsync(redb => redb.LoadAsync<SessionProps>(session.id));
            ended!.Props.Status.Should().Be("revoked");
            ended.Props.ClientApplicationIds.Should().NotBeNullOrEmpty("the session recorded the relying party that used it");
        }
        finally
        {
            await rp.Stop();
            await rp.DisposeAsync();
        }
    }

    // ── the relying party's back-channel endpoint, on the same HTTP stack the OP runs on ──

    private sealed class Receiver(int port, TaskCompletionSource<string> captured) : RouteBuilder
    {
        protected override void Configure()
        {
            From($"http:POST:127.0.0.1:{port}/bclogout?inOut=true")
                .RouteId("bclogout-rp")
                .Process(e =>
                {
                    var body = e.In.Body switch
                    {
                        byte[] bytes => Encoding.UTF8.GetString(bytes),
                        string text => text,
                        _ => string.Empty,
                    };
                    captured.TrySetResult(body);
                    e.Out = new Message(string.Empty);
                });
        }
    }

    // ── helpers ──

    private async Task<string> RegisterRelyingPartyAsync(string backchannelLogoutUri)
    {
        var req = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(new
            {
                client_name = "bclogout-rp",
                redirect_uris = new[] { ProductionHttpFixture.TestRedirectUri },
                grant_types = new[] { "authorization_code" },
                response_types = new[] { "code" },
                token_endpoint_auth_method = "none",
                scope = "openid",
                backchannel_logout_uri = backchannelLogoutUri,
                backchannel_logout_session_required = true,
            })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ProductionHttpFixture.DynamicRegAccessToken);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Created, "registration failed: {0}", await resp.Content.ReadAsStringAsync());
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("client_id").GetString()!;
    }

    private async Task<HttpClient> LoginAsync()
    {
        var jar = new CookieContainer();
        var client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = jar,
            UseCookies = true,
        })
        { BaseAddress = new Uri(_fx.BaseUrl) };

        var login = await client.PostAsync("/login", Form(new()
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
        }));
        ((int)login.StatusCode).Should().BeOneOf(200, 302);
        jar.Count.Should().BeGreaterThan(0, "login must issue the session cookie");
        return client;
    }

    /// <summary>Tests in this collection run one at a time, so the newest active session is the one just created.</summary>
    private async Task<RedbObject<SessionProps>> NewestActiveSessionAsync()
    {
        var active = await _fx.UseRedbAsync(redb => redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .ToListAsync());
        return active.OrderByDescending(s => s.id).First();
    }

    private async Task<string> IssueIdTokenAsync(HttpClient browser, string clientId)
    {
        var (verifier, challenge) = Pkce();
        var authorize = await browser.PostAsync("/connect/authorize", Form(new()
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }));

        string? code = null;
        if (authorize.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
            code = QueryParam(authorize.Headers.Location!.ToString(), "code");
        else if (JsonDocument.Parse(await authorize.Content.ReadAsStringAsync()).RootElement.TryGetProperty("code", out var c))
            code = c.GetString();
        code.Should().NotBeNullOrEmpty("authorize must yield a code for the logged-in browser");

        var token = await _fx.Http.PostAsync("/connect/token", Form(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = clientId,
            ["code_verifier"] = verifier,
        }));
        token.StatusCode.Should().Be(HttpStatusCode.OK, "token exchange failed: {0}", await token.Content.ReadAsStringAsync());
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("id_token").GetString()!;
    }

    private static JsonElement Payload(string jws)
    {
        var payload = jws.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement.Clone();
    }

    private static FormUrlEncodedContent Form(Dictionary<string, string> kv) => new(kv);

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static (string verifier, string challenge) Pkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Base64Url(bytes);
        var challenge = Base64Url(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string? QueryParam(string url, string name)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        foreach (var pair in url[(idx + 1)..].Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv[0] == name) return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }
}
