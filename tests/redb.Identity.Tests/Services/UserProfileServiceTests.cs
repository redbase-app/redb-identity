using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Tests.Services;

public class UserProfileServiceTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly UserProfileService _svc;

    public UserProfileServiceTests()
    {
        _svc = new UserProfileService(_redb, NullLogger<UserProfileService>.Instance);
    }

    private static IRedbUser MockUser(long id, string login, bool enabled = true,
        string? email = null, string? phone = null, string? name = null)
    {
        var user = Substitute.For<IRedbUser>();
        user.Id.Returns(id);
        user.Login.Returns(login);
        user.Name.Returns(name ?? login);
        user.Enabled.Returns(enabled);
        user.Email.Returns(email);
        user.Phone.Returns(phone);
        user.DateRegister.Returns(DateTimeOffset.UtcNow);
        return user;
    }

    [Fact]
    public async Task BuildPrincipal_UserNotFound_ReturnsNull()
    {
        _redb.UserProvider.GetUserByIdAsync(999).Returns((IRedbUser?)null);

        var result = await _svc.BuildPrincipalAsync(999, new[] { "openid" });

        result.Should().BeNull();
    }

    [Fact]
    public async Task BuildPrincipal_DisabledUser_ReturnsNull()
    {
        var user = MockUser(1, "disabled-user", enabled: false);
        _redb.UserProvider.GetUserByIdAsync(1).Returns(user);

        var result = await _svc.BuildPrincipalAsync(1, new[] { "openid" });

        result.Should().BeNull();
    }

    [Fact]
    public async Task BuildPrincipal_ActiveUser_ReturnsPrincipalWithSubAndName()
    {
        var user = MockUser(10, "alice", email: "alice@test.com");
        _redb.UserProvider.GetUserByIdAsync(10).Returns(user);
        // Pre-existing UserProps with a stable value_guid — the public sub is now a GUID.
        var aliceGuid = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        var oidcObj = new RedbObject<UserProps>(new UserProps())
        {
            key = 10,
            value_guid = aliceGuid
        };
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>> { oidcObj });
        // GroupService will query groups — mock empty group list
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupMemberProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupProps>>());

        var result = await _svc.BuildPrincipalAsync(10, new[] { "openid", "profile", "email" });

        result.Should().NotBeNull();
        result!.FindFirst(Claims.Subject)!.Value.Should().Be(aliceGuid.ToString("D"),
            because: "the public sub claim is the per-user GUID stored on UserProps.value_guid");
        result.FindFirst("redb:user_id")!.Value.Should().Be("10",
            because: "the bigint _users._id is mirrored into the internal claim for redb queries");
        result.FindFirst(Claims.Name)!.Value.Should().Be("alice");
        result.FindFirst(Claims.Email)!.Value.Should().Be("alice@test.com");
    }

    [Fact]
    public async Task BuildPrincipal_WithOidcProfile_IncludesProfileClaims()
    {
        var user = MockUser(20, "bob", email: "bob@test.com", phone: "+1234567890");
        _redb.UserProvider.GetUserByIdAsync(20).Returns(user);

        var oidcObj = new RedbObject<UserProps>(new UserProps
        {
            GivenName = "Bob",
            FamilyName = "Smith",
            Picture = "https://example.com/bob.jpg",
            EmailVerified = true,
            PhoneNumberVerified = true,
            CustomClaims = new Dictionary<string, string>
            {
                ["department"] = "Engineering"
            }
        });
        oidcObj.key = 20;
        oidcObj.value_guid = Guid.NewGuid();
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>> { oidcObj });
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupMemberProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupProps>>());

        var result = await _svc.BuildPrincipalAsync(20,
            new[] { "openid", "profile", "email", "phone" });

        result.Should().NotBeNull();
        result!.FindFirst(Claims.GivenName)!.Value.Should().Be("Bob");
        result.FindFirst(Claims.FamilyName)!.Value.Should().Be("Smith");
        result.FindFirst(Claims.Picture)!.Value.Should().Be("https://example.com/bob.jpg");
        result.FindFirst(Claims.EmailVerified)!.Value.Should().Be("true");
        result.FindFirst(Claims.PhoneNumberVerified)!.Value.Should().Be("true");
        result.FindFirst("department")!.Value.Should().Be("Engineering");
    }

    [Fact]
    public async Task BuildPrincipal_WithoutProfileScope_OmitsProfileClaims()
    {
        var user = MockUser(30, "charlie", email: "charlie@test.com");
        _redb.UserProvider.GetUserByIdAsync(30).Returns(user);

        var charlieGuid = Guid.NewGuid();
        var oidcObj = new RedbObject<UserProps>(new UserProps
        {
            GivenName = "Charlie",
            FamilyName = "Brown"
        });
        oidcObj.key = 30;
        oidcObj.value_guid = charlieGuid;
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>> { oidcObj });
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupMemberProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<GroupProps>>());

        var result = await _svc.BuildPrincipalAsync(30, new[] { "openid" });

        result.Should().NotBeNull();
        result!.FindFirst(Claims.Subject)!.Value.Should().Be(charlieGuid.ToString("D"));
        result.FindFirst(Claims.GivenName).Should().BeNull("profile scope not requested");
        result.FindFirst(Claims.FamilyName).Should().BeNull("profile scope not requested");
        result.FindFirst(Claims.Email).Should().BeNull("email scope not requested");
    }
}
