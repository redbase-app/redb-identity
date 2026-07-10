using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// N-3: federation buttons on the universal /login page + the antiforgery-protected
/// /auth/federation/{providerId}/start kickoff endpoint.
///
/// These tests intentionally avoid exercising the real OIDC challenge pipeline
/// (the host's OpenID metadata is unreachable in this fixture). They cover only
/// the BFF-local concerns: input validation, antiforgery enforcement, and the
/// public-providers projection rendering on the login page.
/// </summary>
public sealed class FederationLoginTests : IClassFixture<FederationWebHostFixture>
{
    private readonly FederationWebHostFixture _factory;

    public FederationLoginTests(FederationWebHostFixture factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Get_login_renders_federation_button_when_provider_is_published()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/login");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var html = await resp.Content.ReadAsStringAsync();
        html.Should().Contain("/auth/federation/test-google/start",
            "the public providers stub returns 'test-google' and the login page must render a kickoff form for it");
        html.Should().Contain("Continue with Test Google");
    }

    [Fact]
    public async Task Post_federation_start_with_invalid_provider_id_redirects_to_login_with_error()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Need a valid antiforgery token first so we exercise the regex check (not the antiforgery check).
        var (cookieJar, token) = await PrimeAntiforgeryAsync(client);

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("__RequestVerificationToken", token),
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, "/auth/federation/UPPERCASE_BAD/start")
        {
            Content = content,
        };
        req.Headers.Add("Cookie", cookieJar);

        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().BeOneOf(HttpStatusCode.Redirect, HttpStatusCode.Found, HttpStatusCode.SeeOther);
        var location = resp.Headers.Location?.ToString() ?? "";
        location.Should().StartWith("/login");
        location.Should().Contain("error=invalid_provider");
    }

    [Fact]
    public async Task Post_federation_start_without_antiforgery_returns_400()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var content = new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>());

        var resp = await client.PostAsync("/auth/federation/test-google/start", content);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    /// <summary>
    /// GETs /login, harvests Set-Cookie (antiforgery cookie) plus the embedded
    /// __RequestVerificationToken value from the rendered HTML so subsequent POSTs
    /// can satisfy the antiforgery filter.
    /// </summary>
    private static async Task<(string CookieHeader, string Token)> PrimeAntiforgeryAsync(HttpClient client)
    {
        var resp = await client.GetAsync("/login");
        resp.EnsureSuccessStatusCode();

        // Collect every Set-Cookie (the antiforgery cookie name varies; just forward them all).
        var cookies = resp.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(v => v.Split(';', 2)[0]).ToArray()
            : Array.Empty<string>();
        var cookieHeader = string.Join("; ", cookies);

        var html = await resp.Content.ReadAsStringAsync();
        // <input ... name="__RequestVerificationToken" ... value="XYZ" />
        var marker = "name=\"__RequestVerificationToken\"";
        var idx = html.IndexOf(marker, StringComparison.Ordinal);
        idx.Should().BeGreaterThan(-1, "the login page must render an antiforgery hidden input");
        var valueMarker = "value=\"";
        var valueIdx = html.IndexOf(valueMarker, idx, StringComparison.Ordinal);
        valueIdx.Should().BeGreaterThan(-1);
        var start = valueIdx + valueMarker.Length;
        var end = html.IndexOf('"', start);
        var token = html.Substring(start, end - start);

        return (cookieHeader, token);
    }
}
