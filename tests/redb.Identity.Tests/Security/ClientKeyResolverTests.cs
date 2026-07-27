using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Z7 phase 1 — <see cref="ClientKeyResolver"/>: where a client's verification keys come from.
/// <para>
/// Every case here stays offline. A <c>jwks_uri</c> pointing at an internal address must be
/// refused <b>before</b> a socket is opened, so "no HTTP happened" is itself the assertion:
/// the injected <see cref="IHttpClientFactory"/> throws if anyone tries to use it.
/// </para>
/// </summary>
public sealed class ClientKeyResolverTests
{
    /// <summary>A valid, minimal RSA public JWKS (one key, kid=test-1).</summary>
    private const string ValidJwks = """
        {"keys":[{"kty":"RSA","use":"sig","kid":"test-1","alg":"RS256",
        "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        "e":"AQAB"}]}
        """;

    private static RedbObject<ApplicationProps> App(string? inlineJwks = null, string? jwksUri = null)
        => new(new ApplicationProps
        {
            ClientId = "test-client",
            JsonWebKeySet = inlineJwks,
            JwksUri = jwksUri,
        });

    /// <summary>Factory that fails the test if a fetch is attempted.</summary>
    private static IHttpClientFactory NoNetwork()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ =>
            throw new InvalidOperationException("network access attempted — the guard should have refused first"));
        return factory;
    }

    private static ClientKeyResolver Build(
        IHttpClientFactory? factory = null,
        Action<ClientKeysOptions>? configure = null)
    {
        var options = new RedbIdentityOptions();
        configure?.Invoke(options.ClientKeys);
        return new ClientKeyResolver(
            factory ?? NoNetwork(),
            Options.Create(options),
            NullLogger<ClientKeyResolver>.Instance);
    }

    [Fact]
    public async Task Returns_keys_from_inline_jwks_without_touching_the_network()
    {
        var keys = await Build().GetSigningKeysAsync(App(inlineJwks: ValidJwks));
        keys.Should().HaveCount(1);
    }

    [Fact]
    public async Task Returns_empty_when_client_published_no_keys()
    {
        var keys = await Build().GetSigningKeysAsync(App());
        keys.Should().BeEmpty();
    }

    /// <summary>
    /// A typo in the pasted JWKS must not silently fall through to <c>jwks_uri</c>: using a
    /// different key source than the configured one would hide the mistake behind a working login.
    /// </summary>
    [Fact]
    public async Task Malformed_inline_jwks_yields_no_keys_and_does_not_fall_back_to_uri()
    {
        var app = App(inlineJwks: "{ not json", jwksUri: "https://example.com/jwks");
        var keys = await Build().GetSigningKeysAsync(app);
        keys.Should().BeEmpty();
    }

    /// <summary>Inline is operator-controlled and needs no network — it must win.</summary>
    [Fact]
    public async Task Inline_jwks_takes_precedence_over_jwks_uri()
    {
        var app = App(inlineJwks: ValidJwks, jwksUri: "https://example.com/jwks");
        var keys = await Build().GetSigningKeysAsync(app);
        keys.Should().HaveCount(1);
    }

    [Theory]
    [InlineData("https://169.254.169.254/jwks")]
    [InlineData("https://127.0.0.1/jwks")]
    [InlineData("https://10.1.2.3/jwks")]
    [InlineData("http://example.com/jwks")]   // plain HTTP is refused by default
    [InlineData("file:///etc/passwd")]
    public async Task Refuses_to_fetch_dangerous_jwks_uri(string uri)
    {
        // NoNetwork() throws on any fetch attempt, so reaching the assertion proves
        // the guard rejected the URL before opening a connection.
        var keys = await Build().GetSigningKeysAsync(App(jwksUri: uri));
        keys.Should().BeEmpty();
    }

    /// <summary>
    /// An unreachable or hostile endpoint must fail closed — no keys, so the caller cannot
    /// verify, so it rejects. "Could not check" must never read as "valid".
    /// </summary>
    [Fact]
    public async Task Fails_closed_when_the_endpoint_cannot_be_reached()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler));

        var resolver = Build(factory, o => o.AllowPrivateNetworkTargets = true);
        var keys = await resolver.GetSigningKeysAsync(App(jwksUri: "https://127.0.0.1/jwks"));

        keys.Should().BeEmpty();
    }

    /// <summary>A JWKS served over the wire is parsed and returned.</summary>
    [Fact]
    public async Task Fetches_and_parses_a_reachable_jwks()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(ValidJwks),
        });
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler));

        var resolver = Build(factory, o => o.AllowPrivateNetworkTargets = true);
        var keys = await resolver.GetSigningKeysAsync(App(jwksUri: "https://127.0.0.1/jwks"));

        keys.Should().HaveCount(1);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(respond(request));
    }
}
