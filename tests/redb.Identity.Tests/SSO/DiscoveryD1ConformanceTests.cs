using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.SSO;

/// <summary>
/// D1 — OIDC Discovery 1.0 §3 + RFC 8414 §2 conformance for the production
/// /.well-known/openid-configuration document.
///
/// Runs in the production-bootstrap fixture so AddRedbIdentityServer's
/// RegisterClaims + ApplyDiscoveryResponseHandler are wired in.
/// </summary>
[Collection("ProductionBootstrap")]
public class DiscoveryD1ConformanceTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _out;

    public DiscoveryD1ConformanceTests(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    [Fact]
    public async Task Discovery_AdvertisesStandardClaims()
    {
        var result = await _fx.Request(IdentityEndpoints.Discovery,
            new Dictionary<string, string>());
        var response = result.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;

        // RegisterClaims(...) added in D1 — without it OpenIddict emits an empty list.
        response.Should().ContainKey("claims_supported");
        var claims = response["claims_supported"];
        claims.Should().NotBeNull();
        claims.Should().BeAssignableTo<System.Collections.IEnumerable>();
        var claimList = ((System.Collections.IEnumerable)claims!)
            .Cast<object>()
            .Select(c => c.ToString())
            .ToList();

        // OIDC §5.1 — minimum standard claims the deployment supports.
        claimList.Should().Contain("sub");
        claimList.Should().Contain("iss");
        claimList.Should().Contain("aud");
        claimList.Should().Contain("exp");
        claimList.Should().Contain("iat");
        claimList.Should().Contain("nonce");
        claimList.Should().Contain("auth_time");
        claimList.Should().Contain("name");
        claimList.Should().Contain("preferred_username");
        claimList.Should().Contain("email");
        claimList.Should().Contain("email_verified");

        _out.WriteLine($"claims_supported has {claimList.Count} entries ✓");
    }

    [Fact]
    public async Task Discovery_AdvertisesAuthMethodsForRevocationAndIntrospection()
    {
        var result = await _fx.Request(IdentityEndpoints.Discovery,
            new Dictionary<string, string>());
        var response = result.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;

        // D1: ApplyDiscoveryResponseHandler mirrors token_endpoint_auth_methods_supported
        // onto revocation/introspection (RFC 8414 §2 recommended fields).
        response.Should().ContainKey("token_endpoint_auth_methods_supported");
        response.Should().ContainKey("revocation_endpoint_auth_methods_supported");
        response.Should().ContainKey("introspection_endpoint_auth_methods_supported");
    }

    [Fact]
    public async Task Discovery_AdvertisesCodeChallengeS256Only()
    {
        var result = await _fx.Request(IdentityEndpoints.Discovery,
            new Dictionary<string, string>());
        var response = result.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;

        // C4 + D1: PKCE locked to S256 (no `plain`).
        response.Should().ContainKey("code_challenge_methods_supported");
        var methods = ((System.Collections.IEnumerable)response["code_challenge_methods_supported"]!)
            .Cast<object>()
            .Select(m => m.ToString())
            .ToList();
        methods.Should().ContainSingle().Which.Should().Be("S256");
    }
}
