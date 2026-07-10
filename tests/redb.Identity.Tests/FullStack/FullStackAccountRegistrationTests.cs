using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Configuration;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// N-3 (sub-step N3-7): full-stack E2E tests for the anonymous self-service
/// account-registration flow. Path: HTTP \u2192 Kestrel \u2192 AccountRegistrationController
/// (no auth) \u2192 direct-vm \u2192 AccountRegisterProcessor \u2192 IUserProvider + redb
/// stores. Asserts the happy-path user creation + ROPC sign-in, the duplicate-login
/// 409 contract, the weak-password 400 rejection, and the feature-gate 403 when
/// <see cref="RegistrationOptions.Enabled"/> is flipped off.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackAccountRegistrationTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    private const string ClientId = ProductionHttpFixture.TestClientId;
    private const string ClientSecret = ProductionHttpFixture.TestClientSecret;

    public FullStackAccountRegistrationTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    private static string UniqueLogin(string tag) => $"reg-{tag}-{Guid.NewGuid():N}".Substring(0, 24);
    private static string UniqueEmail(string tag) => $"reg-{tag}-{Guid.NewGuid():N}@example.invalid";

    private async Task<HttpResponseMessage> PostRegisterAsync(object body)
        => await _http.PostAsJsonAsync("/api/v1/identity/account/register", body);

    private async Task<HttpResponseMessage> TryPasswordGrantAsync(string username, string password)
    {
        var content = new FormUrlEncodedContent(new System.Collections.Generic.Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
            ["scope"] = "openid"
        });
        return await _http.PostAsync("/connect/token", content);
    }

    // \u2550\u2550 Happy path \u2550\u2550

    [Fact]
    public async Task Register_HappyPath_CreatesUser_AndPasswordGrantSucceeds()
    {
        var login = UniqueLogin("ok");
        var email = UniqueEmail("ok");
        var password = $"E2E@Reg-{Guid.NewGuid():N}!";

        var resp = await PostRegisterAsync(new
        {
            login,
            email,
            password,
            displayName = "E2E Self Sign-Up",
        });

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "happy-path register must succeed: {0}", await resp.Content.ReadAsStringAsync());

        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("success").GetBoolean().Should().BeTrue();
        body.GetProperty("login").GetString().Should().Be(login);
        body.GetProperty("userId").GetInt64().Should().BeGreaterThan(0);

        // The new credentials must be immediately usable via the ROPC token endpoint.
        using var grant = await TryPasswordGrantAsync(login, password);
        grant.StatusCode.Should().Be(HttpStatusCode.OK,
            "newly registered user must be able to sign in via password grant: {0}",
            await grant.Content.ReadAsStringAsync());
    }

    // \u2550\u2550 Duplicate login / e-mail \u2550\u2550

    [Fact]
    public async Task Register_DuplicateLogin_Returns409()
    {
        var login = UniqueLogin("dup");
        var password = $"E2E@Reg-{Guid.NewGuid():N}!";

        using (var first = await PostRegisterAsync(new
        {
            login,
            email = UniqueEmail("dup1"),
            password,
        }))
        {
            first.StatusCode.Should().Be(HttpStatusCode.OK,
                "seed-create must succeed: {0}", await first.Content.ReadAsStringAsync());
        }

        using var second = await PostRegisterAsync(new
        {
            login,
            email = UniqueEmail("dup2"),
            password = $"E2E@Reg-{Guid.NewGuid():N}!",
        });
        second.StatusCode.Should().Be(HttpStatusCode.Conflict,
            "duplicate login must surface 409 (NOT anti-enumeration): {0}",
            await second.Content.ReadAsStringAsync());
        var body = await second.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("success").GetBoolean().Should().BeFalse();
        body.GetProperty("error").GetString().Should().Be("duplicate");
    }

    // \u2550\u2550 Weak password \u2550\u2550

    [Fact]
    public async Task Register_WeakPassword_Returns400()
    {
        using var resp = await PostRegisterAsync(new
        {
            login = UniqueLogin("weak"),
            email = UniqueEmail("weak"),
            // "12345678" is the canonical complexity-policy failure case (length-ok but no diversity).
            password = "12345678",
        });
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "weak password must be rejected: {0}", await resp.Content.ReadAsStringAsync());
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("success").GetBoolean().Should().BeFalse();
        body.GetProperty("error").GetString().Should().Be("weak_password");
    }

    // \u2550\u2550 Feature-gate off \u2550\u2550

    [Fact]
    public async Task Register_WhenDisabled_Returns403()
    {
        var opts = _fx.ServiceProvider.GetRequiredService<IOptions<RedbIdentityOptions>>().Value;
        var original = opts.Registration.Enabled;
        opts.Registration.Enabled = false;
        try
        {
            using var resp = await PostRegisterAsync(new
            {
                login = UniqueLogin("off"),
                email = UniqueEmail("off"),
                password = $"E2E@Reg-{Guid.NewGuid():N}!",
            });
            resp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
                "register must be denied when feature gate is off: {0}",
                await resp.Content.ReadAsStringAsync());
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
            body.GetProperty("success").GetBoolean().Should().BeFalse();
            body.GetProperty("error").GetString().Should().Be("registration_disabled");
        }
        finally
        {
            opts.Registration.Enabled = original;
        }
    }
}
