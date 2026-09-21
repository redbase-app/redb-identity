using System.Security.Claims;
using FluentAssertions;
using redb.Identity.Web.Auth;
using Xunit;

namespace redb.Identity.Web.Tests.Auth;

/// <summary>
/// Which claim the UI shows as the signed-in user.
/// <para>
/// The OP keeps <c>preferred_username</c> and <c>name</c> out of the id_token — their destination is
/// the access token, so PII does not travel in a token the relying party forwards. The login therefore
/// arrives only with userinfo, one step later than the id_token, and the top bar used to be stuck with
/// whatever was chosen at id_token time: the opaque <c>sub</c>. These tests pin the order and, above
/// all, that a later-arriving login wins over a subject that was there first.
/// </para>
/// </summary>
public sealed class PrincipalNamingTests
{
    private static ClaimsIdentity Identity(params (string Type, string Value)[] claims)
        => new(claims.Select(c => new Claim(c.Type, c.Value)), "BackchannelOidc", "sub", "roles");

    [Fact]
    public void Login_wins_over_subject()
    {
        var identity = Identity(("sub", "0b3f…-guid"), ("preferred_username", "alice"), ("name", "Alice A"));

        PrincipalNaming.PickNameClaimType(identity).Should().Be("preferred_username");
    }

    [Fact]
    public void Falls_through_name_then_email_then_subject()
    {
        PrincipalNaming.PickNameClaimType(Identity(("sub", "guid"), ("name", "Alice A")))
            .Should().Be("name");
        PrincipalNaming.PickNameClaimType(Identity(("sub", "guid"), ("email", "alice@example.org")))
            .Should().Be("email");
        PrincipalNaming.PickNameClaimType(Identity(("sub", "guid")))
            .Should().Be("sub", "an opaque subject is a poor label, but it is never null");
    }

    [Fact]
    public void Empty_claim_value_does_not_win()
    {
        var identity = Identity(("sub", "guid"), ("preferred_username", ""), ("name", "Alice A"));

        PrincipalNaming.PickNameClaimType(identity).Should().Be("name",
            "a claim that is present but blank would render as an empty label");
    }

    [Fact]
    public void Rebuilt_identity_resolves_Name_to_the_login_and_keeps_every_claim()
    {
        // Exactly the shape the backchannel login produces: named after "sub" at id_token time, then
        // the userinfo claims merged in.
        var identity = Identity(("sub", "0b3f…-guid"), ("email", "alice@example.org"));
        identity.AddClaim(new Claim("preferred_username", "alice"));

        var rebuilt = PrincipalNaming.WithPickedNameClaimType(identity);

        rebuilt.Name.Should().Be("alice");
        rebuilt.AuthenticationType.Should().Be("BackchannelOidc", "the cookie scheme needs it to consider the identity authenticated");
        rebuilt.RoleClaimType.Should().Be("roles");
        rebuilt.Claims.Should().HaveCount(3);
    }
}
