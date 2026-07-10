using FluentAssertions;
using Fido2NetLib;
using Fido2NetLib.Objects;
using AssertionOptions = Fido2NetLib.AssertionOptions;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Exceptions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// MFA-3 unit tests for <see cref="WebAuthnMfaMethod"/>. Focuses on the
/// redb-specific glue layer above Fido2NetLib (UV ratchet pre-checks, AAGUID
/// blocklist, IMfaMethod-OTP-shape rejection, credential lookup). Full attestation
/// /assertion verification round-trips are covered in the integration suite where
/// real Fido2NetLib + WebAuthn-virtual-authenticator can be used.
/// </summary>
public sealed class WebAuthnMfaMethodTests
{
    private static WebAuthnMfaMethod NewSut(IFido2? fido = null, IdentityWebAuthnOptions? options = null)
    {
        fido ??= Substitute.For<IFido2>();
        options ??= new IdentityWebAuthnOptions
        {
            Enabled = true,
            RpId = "auth.test.local",
            Origins = { "https://auth.test.local" },
        };
        return new WebAuthnMfaMethod(fido, Options.Create(options));
    }

    [Fact]
    public void MethodId_IsWebAuthn()
    {
        NewSut().MethodId.Should().Be("webauthn");
    }

    [Fact]
    public async Task IMfaMethod_Initiate_Throws_NotSupported()
    {
        IMfaMethod sut = NewSut();
        await sut.Awaiting(s => s.InitiateSetupAsync("user@test.local"))
            .Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*WebAuthn does not use the IMfaMethod*");
    }

    [Fact]
    public async Task IMfaMethod_ConfirmAndApply_Throws_NotSupported()
    {
        IMfaMethod sut = NewSut();
        await sut.Awaiting(s => s.ConfirmAndApplyAsync(new MfaProps(), null!, "123456"))
            .Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task IMfaMethod_Verify_Throws_NotSupported()
    {
        IMfaMethod sut = NewSut();
        await sut.Awaiting(s => s.VerifyAsync(new MfaProps(), "123456"))
            .Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task CompleteAssertion_CredentialNotInDictionary_ThrowsCredentialNotFound()
    {
        var sut = NewSut();
        var assertion = new AuthenticatorAssertionRawResponse
        {
            // RawId not in `credentials` below.
            RawId = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                ClientDataJson = new byte[1],
                Signature = new byte[1],
                UserHandle = new byte[1],
            },
        };

        var options = new AssertionOptions { Challenge = new byte[32] };
        var creds = new Dictionary<string, WebAuthnCredential>
        {
            ["c1"] = new WebAuthnCredential
            {
                CredentialId = new byte[] { 0xCA, 0xFE },
                PublicKey = new byte[1],
                SignCount = 0,
                RegisteredAt = DateTimeOffset.UtcNow,
            },
        };

        Func<Task> act = () => sut.CompleteAssertionAsync(assertion, options, creds, userId: 42);

        var ex = await act.Should().ThrowAsync<WebAuthnException>();
        ex.Which.ErrorCode.Should().Be("credential_not_found");
    }

    [Fact]
    public async Task CompleteAssertion_UvDowngrade_RejectedBeforeFidoCall()
    {
        var fido = Substitute.For<IFido2>();
        var sut = NewSut(fido);

        var rawId = new byte[] { 0x01, 0x02, 0x03 };
        // Build an authenticatorData byte[37+] where the flags byte (index 32) has UV bit OFF (0x01 only = UP).
        var authData = new byte[37];
        authData[32] = 0x01; // UP=1, UV=0

        var assertion = new AuthenticatorAssertionRawResponse
        {
            RawId = rawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authData,
                ClientDataJson = new byte[1],
                Signature = new byte[1],
                UserHandle = new byte[1],
            },
        };

        var options = new AssertionOptions { Challenge = new byte[32] };
        var creds = new Dictionary<string, WebAuthnCredential>
        {
            ["c1"] = new WebAuthnCredential
            {
                CredentialId = rawId,
                PublicKey = new byte[1],
                SignCount = 5,
                RegisteredAt = DateTimeOffset.UtcNow,
                UserVerified = true, // registered WITH uv → must assert WITH uv
            },
        };

        Func<Task> act = () => sut.CompleteAssertionAsync(assertion, options, creds, userId: 42);

        var ex = await act.Should().ThrowAsync<WebAuthnException>();
        ex.Which.ErrorCode.Should().Be("uv_downgrade");

        // Crucial: never reached MakeAssertionAsync (rejection happens above the verify call).
        await fido.DidNotReceive().MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
    }
}
