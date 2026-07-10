using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class MfaAdminClientTests
{
    private const string Base = "/api/v1/identity/mfa";

    [Fact]
    public async Task GetUserMfaStatus_GET_status_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"totp\":true}");
        await fx.Client.GetUserMfaStatusAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/status/42");
    }

    // ── TOTP ──

    [Fact]
    public async Task SetupUserTotp_POST_with_userId_username()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"qr\":\"...\"}");
        await fx.Client.SetupUserTotpAsync(42, "alice");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/totp/setup");
        fx.Handler.RequestBodies[0].Should().Contain("\"userId\":42").And.Contain("\"username\":\"alice\"");
    }

    [Fact]
    public async Task ConfirmUserTotp_POST_with_userId_code()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ConfirmUserTotpAsync(42, "123456");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/totp/confirm");
        fx.Handler.RequestBodies[0].Should().Contain("\"code\":\"123456\"");
    }

    [Fact]
    public async Task DisableUserTotp_DELETE_by_userId()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DisableUserTotpAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/totp/42");
    }

    // ── Recovery codes ──

    [Fact]
    public async Task RegenerateUserRecoveryCodes_POST_with_userId_body()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"codes\":[\"a\",\"b\"]}");
        await fx.Client.RegenerateUserRecoveryCodesAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/recovery-codes/regenerate");
        fx.Handler.RequestBodies[0].Should().Contain("\"userId\":42");
    }

    // ── SMS ──

    [Fact]
    public async Task SetupUserSms_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"challenge\":\"sent\"}");
        await fx.Client.SetupUserSmsAsync(42, "alice", "+15551234567");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sms/setup");
        fx.Handler.RequestBodies[0].Should().Contain("\"destination\":\"+15551234567\"");
    }

    [Fact]
    public async Task ConfirmUserSms_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ConfirmUserSmsAsync(42, "123456", mfaState: "state-x");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sms/confirm");
        fx.Handler.RequestBodies[0].Should().Contain("\"mfaState\":\"state-x\"");
    }

    [Fact]
    public async Task DisableUserSms_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DisableUserSmsAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sms/42");
    }

    // ── Email ──

    [Fact]
    public async Task SetupUserEmail_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"challenge\":\"sent\"}");
        await fx.Client.SetupUserEmailAsync(42, "alice", "alice@example.com");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/email/setup");
        fx.Handler.RequestBodies[0].Should().Contain("\"destination\":\"alice@example.com\"");
    }

    [Fact]
    public async Task ConfirmUserEmail_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ConfirmUserEmailAsync(42, "123456");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/email/confirm");
    }

    [Fact]
    public async Task DisableUserEmail_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DisableUserEmailAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/email/42");
    }
}
