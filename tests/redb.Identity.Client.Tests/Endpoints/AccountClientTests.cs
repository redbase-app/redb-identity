using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Users;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class AccountClientTests
{
    private const string Base = "/api/v1/identity/me";

    // ── Profile ──

    [Fact]
    public async Task GetMyProfile_GET_me()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"id\":1,\"login\":\"alice\"}");
        await fx.Client.GetMyProfileAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be(Base);
    }

    [Fact]
    public async Task UpdateMyProfile_PUT_me_with_body()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"id\":1,\"displayName\":\"Alice\"}");
        await fx.Client.UpdateMyProfileAsync(new MeUpdateProfileRequest { DisplayName = "Alice" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be(Base);
        fx.Handler.RequestBodies[0].Should().Contain("\"displayName\":\"Alice\"");
    }

    // ── Password ──

    [Fact]
    public async Task ChangeMyPassword_PUT_me_password()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true,\"sessionsRevoked\":3}");
        await fx.Client.ChangeMyPasswordAsync(new MeChangePasswordRequest { OldPassword = "old", NewPassword = "new" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/password");
        fx.Handler.RequestBodies[0].Should().Contain("\"oldPassword\":\"old\"").And.Contain("\"newPassword\":\"new\"");
    }

    // ── Sessions ──

    [Fact]
    public async Task ListMySessions_GET_me_sessions()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[]");
        await fx.Client.ListMySessionsAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sessions");
    }

    [Fact]
    public async Task RevokeMyCurrentSession_DELETE_to_current_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeMyCurrentSessionAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sessions/current");
    }

    [Fact]
    public async Task RevokeMySession_DELETE_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeMySessionAsync(7);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sessions/7");
    }

    [Fact]
    public async Task RevokeMyOtherSessions_DELETE_to_others_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true,\"revoked\":3}");
        await fx.Client.RevokeMyOtherSessionsAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/sessions/others");
    }

    // ── MFA (self) ──

    [Fact]
    public async Task GetMyMfaStatus_GET_me_mfa()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"totp\":false}");
        await fx.Client.GetMyMfaStatusAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa");
    }

    [Fact]
    public async Task SetupMyMfa_POST_setup_subroute_with_body()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"qr\":\"...\"}");
        await fx.Client.SetupMyMfaAsync(new Dictionary<string, object?> { ["method"] = "totp" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa/setup");
        fx.Handler.RequestBodies[0].Should().Contain("\"method\":\"totp\"");
    }

    [Fact]
    public async Task ConfirmMyMfa_POST_confirm_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ConfirmMyMfaAsync(new Dictionary<string, object?> { ["code"] = "123456" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa/confirm");
    }

    [Fact]
    public async Task DisableMyMfaMethod_DELETE_by_method()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DisableMyMfaMethodAsync("totp");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa/totp");
    }

    [Fact]
    public async Task RegenerateMyRecoveryCodes_POST_to_recovery_codes()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"codes\":[\"a\"]}");
        await fx.Client.RegenerateMyRecoveryCodesAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa/recovery-codes");
    }

    [Fact]
    public async Task DownloadMyRecoveryCodes_GET_returns_HttpResponseMessage()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "code-1\ncode-2\n", mediaType: "text/plain");
        var resp = await fx.Client.DownloadMyRecoveryCodesAsync();
        try
        {
            resp.IsSuccessStatusCode.Should().BeTrue();
            (await resp.Content.ReadAsStringAsync()).Should().Contain("code-1");
            fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/mfa/recovery-codes/download");
        }
        finally { resp.Dispose(); }
    }

    // ── WebAuthn (self) ──

    [Fact]
    public async Task GetMyWebAuthnStatus_GET_webauthn()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"enrolled\":false}");
        await fx.Client.GetMyWebAuthnStatusAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn");
    }

    [Fact]
    public async Task BeginMyWebAuthnRegistration_POST_register_begin()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"options\":{}}");
        await fx.Client.BeginMyWebAuthnRegistrationAsync(new Dictionary<string, object?> { ["display_name"] = "Yubikey" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn/register/begin");
    }

    [Fact]
    public async Task CompleteMyWebAuthnRegistration_POST_register_complete()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"key\":\"k1\"}");
        await fx.Client.CompleteMyWebAuthnRegistrationAsync(new Dictionary<string, object?> { ["attestation"] = "x" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn/register/complete");
    }

    [Fact]
    public async Task ListMyWebAuthnCredentials_GET_credentials()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[]");
        await fx.Client.ListMyWebAuthnCredentialsAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn/credentials");
    }

    [Fact]
    public async Task RenameMyWebAuthnCredential_PATCH_by_key()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RenameMyWebAuthnCredentialAsync("k1", new Dictionary<string, object?> { ["name"] = "Yubikey 5" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Patch);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn/credentials/k1");
        fx.Handler.RequestBodies[0].Should().Contain("\"name\":\"Yubikey 5\"");
    }

    [Fact]
    public async Task DeleteMyWebAuthnCredential_DELETE_by_key()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DeleteMyWebAuthnCredentialAsync("k1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/webauthn/credentials/k1");
    }

    // ── Consents (self) ──

    [Fact]
    public async Task ListMyConsents_GET_consents()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[]");
        await fx.Client.ListMyConsentsAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/consents");
    }

    [Fact]
    public async Task RevokeMyConsent_DELETE_by_clientId()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeMyConsentAsync("client-x");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/consents/client-x");
    }
}
