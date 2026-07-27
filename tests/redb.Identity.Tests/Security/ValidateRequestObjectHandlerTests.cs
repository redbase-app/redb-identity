using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.OpenIddict.Handlers;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Z7 phase 2 — <see cref="ValidateRequestObjectHandler"/>: accepting, verifying and rejecting a
/// JAR (RFC 9101) request object on <c>/connect/authorize</c>.
/// <para>
/// The invariant that matters most is the first test: with <c>EnableJar = false</c> the answer is
/// exactly what every pre-JAR release gave — <c>request_not_supported</c>. The flag adds a path; it
/// does not change the default. The rest assert the security properties: no <c>alg:none</c>, no
/// cross-client key use, no unsigned or unverifiable object slips through.
/// </para>
/// </summary>
public sealed class ValidateRequestObjectHandlerTests
{
    private const string ClientId = "jar-client";
    private const string Issuer = "https://id.example.com/";

    private static readonly RSA _clientRsa = RSA.Create(2048);

    // ── harness ──────────────────────────────────────────────────────────────

    private static string SignRequestObject(
        RSA rsa,
        string clientId = ClientId,
        string alg = "RS256",
        Action<Dictionary<string, object>>? mutate = null,
        bool withExp = true)
    {
        var claims = new Dictionary<string, object>
        {
            ["iss"] = clientId,
            ["aud"] = Issuer.TrimEnd('/'),
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["redirect_uri"] = "https://client.example.com/cb",
        };
        mutate?.Invoke(claims);

        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            NotBefore = now,
            IssuedAt = now,
            Expires = withExp ? now.AddMinutes(5) : null,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), alg),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static RedbObject<ApplicationProps> Client(string? declaredAlg = null) =>
        new(new ApplicationProps { ClientId = ClientId, RequestObjectSigningAlg = declaredAlg });

    private static ValidateAuthorizationRequestContext Context(string? requestObject, string? clientId = ClientId, string? requestUri = null)
    {
        var tx = new OpenIddictServerTransaction { Request = new OpenIddictRequest() };
        tx.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = new TestExchange();
        var ctx = new ValidateAuthorizationRequestContext(tx);
        if (requestObject is not null) ctx.Request.Request = requestObject;
        if (requestUri is not null) ctx.Request.RequestUri = requestUri;
        if (clientId is not null) ctx.Request.ClientId = clientId;
        return ctx;
    }

    private static ValidateRequestObjectHandler Handler(
        bool enableJar = true,
        RedbObject<ApplicationProps>? application = null,
        IReadOnlyCollection<SecurityKey>? keys = null,
        JarEnforcementMode mode = JarEnforcementMode.LogOnly)
    {
        var apps = Substitute.For<IOpenIddictApplicationManager>();
        apps.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<object?>(application));

        var resolver = Substitute.For<IClientKeyResolver>();
        resolver.GetSigningKeysAsync(Arg.Any<RedbObject<ApplicationProps>>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<IReadOnlyCollection<SecurityKey>>(keys ?? []));

        var options = new RedbIdentityOptions { Issuer = new Uri(Issuer) };
        options.Features.EnableJar = enableJar;
        options.Jar.EnforcementMode = mode;

        // These tests exercise inline request objects only; a request_uri fetch would fail the test
        // (the factory throws), which is what we want — no network in unit tests.
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(Arg.Any<string>()).Returns(_ =>
            throw new InvalidOperationException("no network in unit tests"));

        return new ValidateRequestObjectHandler(
            apps, resolver, httpFactory, Options.Create(options), NullLogger<ValidateRequestObjectHandler>.Instance);
    }

    private static IReadOnlyCollection<SecurityKey> PublicKeyOf(RSA rsa) =>
        [new RsaSecurityKey(rsa.ExportParameters(false))];

    // ── flag-off invariant ───────────────────────────────────────────────────

    [Fact]
    public async Task Flag_off_rejects_request_parameter_exactly_as_before()
    {
        var ctx = Context(SignRequestObject(_clientRsa));
        await Handler(enableJar: false).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be(OpenIddictConstants.Errors.RequestNotSupported);
    }

    [Fact]
    public async Task No_request_object_present_is_a_no_op()
    {
        var ctx = Context(requestObject: null);
        await Handler(enableJar: true).HandleAsync(ctx);
        ctx.IsRejected.Should().BeFalse();
    }

    /// <summary>PAR issues <c>urn:ietf:params:oauth:request_uri:*</c>; OpenIddict resolves it, we must not touch it.</summary>
    [Fact]
    public async Task Par_request_uri_is_left_for_openiddict()
    {
        var ctx = Context(requestObject: null, requestUri: "urn:ietf:params:oauth:request_uri:abc123");
        await Handler(enableJar: true).HandleAsync(ctx);
        ctx.IsRejected.Should().BeFalse();
    }

    // ── happy path ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Valid_signed_request_object_is_accepted_and_parameters_merged()
    {
        var ctx = Context(SignRequestObject(_clientRsa, mutate: c => c["scope"] = "openid email"));
        await Handler(application: Client(), keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);

        ctx.IsRejected.Should().BeFalse();
        // §6.1: the value from inside the signed object wins.
        ctx.Request.Scope.Should().Be("openid email");
    }

    // ── security rejections ──────────────────────────────────────────────────

    [Fact]
    public async Task Unsigned_alg_none_is_rejected()
    {
        // A JOSE header with alg=none and no signature.
        var header = Base64Url("""{"alg":"none","typ":"JWT"}""");
        var body = Base64Url($$"""{"iss":"{{ClientId}}","client_id":"{{ClientId}}","response_type":"code"}""");
        var ctx = Context($"{header}.{body}.");

        await Handler(application: Client(), keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    [Fact]
    public async Task Request_object_signed_by_a_different_key_is_rejected()
    {
        var attacker = RSA.Create(2048);
        var ctx = Context(SignRequestObject(attacker));   // signed by attacker's key...
        await Handler(application: Client(), keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);   // ...verified against the client's

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    [Fact]
    public async Task Client_has_no_keys_is_rejected()
    {
        var ctx = Context(SignRequestObject(_clientRsa));
        await Handler(application: Client(), keys: []).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    [Fact]
    public async Task Missing_client_id_is_rejected()
    {
        var ctx = Context(SignRequestObject(_clientRsa), clientId: null);
        await Handler(application: Client(), keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    [Fact]
    public async Task Inner_client_id_mismatch_is_rejected()
    {
        // Outer client_id says jar-client; the signed object claims someone else.
        var ctx = Context(SignRequestObject(_clientRsa, mutate: c => c["client_id"] = "another-client"));
        await Handler(application: Client(), keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    [Fact]
    public async Task Unknown_client_is_rejected()
    {
        var ctx = Context(SignRequestObject(_clientRsa));
        await Handler(application: null, keys: PublicKeyOf(_clientRsa)).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    // ── declared-algorithm enforcement ───────────────────────────────────────

    /// <summary>LogOnly: a declared/actual mismatch is allowed through (and logged).</summary>
    [Fact]
    public async Task LogOnly_allows_algorithm_mismatch()
    {
        var ctx = Context(SignRequestObject(_clientRsa, alg: "RS256"));
        await Handler(application: Client(declaredAlg: "PS256"), keys: PublicKeyOf(_clientRsa),
            mode: JarEnforcementMode.LogOnly).HandleAsync(ctx);

        ctx.IsRejected.Should().BeFalse();
    }

    /// <summary>Enforce: the same mismatch is rejected — here the stored field finally does something.</summary>
    [Fact]
    public async Task Enforce_rejects_algorithm_mismatch()
    {
        var ctx = Context(SignRequestObject(_clientRsa, alg: "RS256"));
        await Handler(application: Client(declaredAlg: "PS256"), keys: PublicKeyOf(_clientRsa),
            mode: JarEnforcementMode.Enforce).HandleAsync(ctx);

        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    // ── request_uri (by reference) ───────────────────────────────────────────

    /// <summary>A PAR-issued request_uri must be left for OpenIddict, never fetched.</summary>
    [Fact]
    public async Task Par_request_uri_is_not_fetched()
    {
        var ctx = Context(requestObject: null, requestUri: "urn:ietf:params:oauth:request_uri:xyz");
        // NoNetwork factory throws on any fetch; reaching a non-rejected state proves we didn't fetch.
        await Handler().HandleAsync(ctx);
        ctx.IsRejected.Should().BeFalse();
    }

    /// <summary>A request_uri pointing at an internal address is refused before any socket opens.</summary>
    [Fact]
    public async Task Request_uri_to_internal_target_is_refused()
    {
        // Default JarOptions: RequestUriAllowPrivateNetworkTargets = false.
        var ctx = Context(requestObject: null, requestUri: "https://169.254.169.254/ro");
        await Handler().HandleAsync(ctx);   // NoNetwork factory would throw if a fetch were attempted
        ctx.IsRejected.Should().BeTrue();
        ctx.Error.Should().Be("invalid_request_object");
    }

    /// <summary>A fetched request object is validated exactly like an inline one.</summary>
    [Fact]
    public async Task Fetched_request_uri_is_validated_like_inline()
    {
        var jwt = SignRequestObject(_clientRsa);
        var handler = new StubHandler(_ => new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
        { Content = new System.Net.Http.StringContent(jwt) });
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new System.Net.Http.HttpClient(handler));

        var apps = Substitute.For<IOpenIddictApplicationManager>();
        apps.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<object?>(Client()));
        var resolver = Substitute.For<IClientKeyResolver>();
        resolver.GetSigningKeysAsync(Arg.Any<RedbObject<ApplicationProps>>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<IReadOnlyCollection<SecurityKey>>(PublicKeyOf(_clientRsa)));
        var options = new RedbIdentityOptions { Issuer = new Uri(Issuer) };
        options.Features.EnableJar = true;
        options.Jar.RequestUriAllowPrivateNetworkTargets = true;   // test host is loopback
        options.Jar.RequestUriRequireHttps = false;

        var h = new ValidateRequestObjectHandler(apps, resolver, factory,
            Options.Create(options), NullLogger<ValidateRequestObjectHandler>.Instance);

        var ctx = Context(requestObject: null, requestUri: "http://127.0.0.1:9/ro");
        await h.HandleAsync(ctx);

        ctx.IsRejected.Should().BeFalse();
        ctx.Request.Scope.Should().Be("openid profile");
    }

    private static string Base64Url(string s) =>
        Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(s));

    private sealed class StubHandler(Func<System.Net.Http.HttpRequestMessage, System.Net.Http.HttpResponseMessage> respond)
        : System.Net.Http.HttpMessageHandler
    {
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(respond(request));
    }
}
