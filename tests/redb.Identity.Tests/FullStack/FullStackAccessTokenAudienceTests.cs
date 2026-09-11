using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) audience conformance, end to end.
/// <para>
/// §2.2 makes <c>aud</c> REQUIRED in every access token; §3 obliges the authorization
/// server to fall back to a default resource indicator when the request names none; §4
/// obliges the resource server to reject a token whose <c>aud</c> does not include it.
/// Before this suite the scope store served <c>ScopeProps.Resources</c> but no sign-in
/// handler ever attached them to the principal, so issued access tokens carried no
/// <c>aud</c> at all and the local validation stack never checked one.
/// </para>
/// <para>
/// Audience composition under test: Resources of the granted scopes ∪ the application's
/// <c>AccessTokenAudiences</c>; the OP's own audience (<c>{issuer}/resources</c>) joins
/// whenever an <c>identity:*</c> scope is granted, and stands alone when nothing else is
/// configured. The management API accepts only tokens carrying the OP's own audience.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class FullStackAccessTokenAudienceTests
{
    private readonly ProductionHttpFixture _fx;

    public FullStackAccessTokenAudienceTests(ProductionHttpFixture fx) => _fx = fx;

    private string OwnAudience => RedbIdentityOptions.ResolveDefaultAccessTokenAudience(
        new Uri($"{_fx.BaseUrl}/"), configured: null);

    [Fact]
    public void DefaultAudience_IsIssuerSlashResources_UnlessConfigured()
    {
        var issuer = new Uri("https://op.example.com/tenant/");

        RedbIdentityOptions.ResolveDefaultAccessTokenAudience(issuer, configured: null)
            .Should().Be("https://op.example.com/tenant/resources",
                "the {issuer}/resources pattern (Duende/Okta style) is the built-in default");
        RedbIdentityOptions.ResolveDefaultAccessTokenAudience(new Uri("https://op.example.com"), configured: null)
            .Should().Be("https://op.example.com/resources", "no double slash for a root issuer");
        RedbIdentityOptions.ResolveDefaultAccessTokenAudience(issuer, configured: " api://my-default ")
            .Should().Be("api://my-default", "an operator-configured value wins, trimmed");
    }

    [Fact]
    public async Task AccessToken_WithoutAnyResource_CarriesTheDefaultAudience()
    {
        var token = await IssuePasswordToken(
            ProductionHttpFixture.TestClientId, ProductionHttpFixture.TestClientSecret, "openid profile");

        ReadAudiences(token).Should().BeEquivalentTo(new[] { OwnAudience, ProductionHttpFixture.TestClientId },
            "RFC 9068 §3: a request naming no resource gets the AS default resource indicator; "
            + "the issuing client is an audience too so it can introspect its own token");
    }

    [Fact]
    public async Task AccessToken_ForExternalApiScope_CarriesOnlyThatResource()
    {
        var n = Guid.NewGuid().ToString("N")[..8];
        var resource = $"https://api-{n}.example";
        await SeedScopeAsync($"e2e-aud-{n}", resource);
        var (clientId, secret) = await SeedClientAsync($"e2e-aud-ext-{n}", $"e2e-aud-{n}");

        var token = await IssueClientCredentialsToken(clientId, secret, $"e2e-aud-{n}");

        ReadAudiences(token).Should().BeEquivalentTo(new[] { resource, clientId },
            "a token minted for an external API is for that API (and its own client) — the OP's own audience must not leak in");
        ReadAudiences(token).Should().NotContain(OwnAudience);
    }

    [Fact]
    public async Task AccessToken_ForExternalApiPlusIdentityScope_CarriesBoth()
    {
        var n = Guid.NewGuid().ToString("N")[..8];
        var resource = $"https://api-{n}.example";
        await SeedScopeAsync($"e2e-aud-{n}", resource);
        var (clientId, secret) = await SeedClientAsync($"e2e-aud-mix-{n}", $"e2e-aud-{n}", "identity:manage");

        var token = await IssueClientCredentialsToken(clientId, secret, $"e2e-aud-{n} identity:manage");

        ReadAudiences(token).Should().BeEquivalentTo(new[] { resource, OwnAudience, clientId },
            "identity:* scopes are the OP's own API, so its audience rides along with the external one");
    }

    [Fact]
    public async Task AccessToken_UsesApplicationAccessTokenAudiences()
    {
        var n = Guid.NewGuid().ToString("N")[..8];
        var extra = $"https://extra-{n}.example";
        await SeedScopeAsync($"e2e-aud-plain-{n}", resource: null);
        var (clientId, secret) = await SeedClientAsync($"e2e-aud-app-{n}", $"e2e-aud-plain-{n}");
        await _fx.UseRedbAsync(async redb =>
        {
            var app = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, clientId);
            app!.Props.AccessTokenAudiences = [extra];
            await redb.SaveAsync(app);
        });

        var token = await IssueClientCredentialsToken(clientId, secret, $"e2e-aud-plain-{n}");

        ReadAudiences(token).Should().BeEquivalentTo(new[] { extra, clientId },
            "per-application audiences are a configured resource indicator, so the default steps aside");
    }

    [Fact]
    public void LocalValidation_RequiresTheOwnAudience()
    {
        var options = _fx.ServiceProvider
            .GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue;

        options.Audiences.Should().Contain(OwnAudience,
            "RFC 9068 §4: the OP's own resource side must verify aud, not just signature/issuer/expiry");
    }

    [Fact]
    public async Task ManagementApi_RejectsTokenMintedForAnotherResource_With401()
    {
        var n = Guid.NewGuid().ToString("N")[..8];
        await SeedScopeAsync($"e2e-aud-{n}", $"https://api-{n}.example");
        var (clientId, secret) = await SeedClientAsync($"e2e-aud-rs-{n}", $"e2e-aud-{n}");
        var foreignToken = await IssueClientCredentialsToken(clientId, secret, $"e2e-aud-{n}");

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", foreignToken);
        var resp = await _fx.Http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "a token whose aud names only another API is invalid here (401), not merely under-scoped (403)");
    }

    [Fact]
    public async Task ManagementApi_StillAcceptsItsOwnManagementToken()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        var resp = await _fx.Http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "the identity:manage token carries the OP's own audience and must keep working");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static string[] ReadAudiences(string accessToken)
    {
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(accessToken);
        return jwt.Audiences.ToArray();
    }

    private async Task SeedScopeAsync(string scopeName, string? resource)
    {
        var manager = _fx.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var descriptor = new OpenIddictScopeDescriptor { Name = scopeName, DisplayName = scopeName };
        if (resource is not null)
            descriptor.Resources.Add(resource);
        await manager.CreateAsync(descriptor);
    }

    private async Task<(string ClientId, string Secret)> SeedClientAsync(string clientId, params string[] scopes)
    {
        var secret = $"secret-{Guid.NewGuid():N}";
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = clientId,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            }
        };
        foreach (var scope in scopes)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);

        var manager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(descriptor);
        return (clientId, secret);
    }

    private Task<string> IssuePasswordToken(string clientId, string secret, string scope)
        => IssueToken(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = scope,
        });

    private Task<string> IssueClientCredentialsToken(string clientId, string secret, string scope)
        => IssueToken(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = scope,
        });

    private async Task<string> IssueToken(Dictionary<string, string> form)
    {
        var resp = await _fx.Http.PostAsync("/connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "token issuance must succeed: {0}", body);
        return JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString()!;
    }
}
