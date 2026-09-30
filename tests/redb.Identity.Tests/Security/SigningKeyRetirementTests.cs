using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Retiring a signing key ends the trust in it; rotating one does not.
/// <para>
/// The two are different operations and the store says so itself. <c>RotateAsync</c> demotes the active
/// key and leaves its <c>NotAfter</c> alone, so tokens it signed keep validating until that date — the
/// handover window relying parties need. <c>RetireAsync</c> sets <c>NotAfter</c> to now: the key is
/// compromised or no longer wanted, and from this moment nothing it signed may pass. The post-configure
/// that feeds OpenIddict honoured the upper bound only for the minting pool; the validation pool it built
/// took every persisted key past <c>NotBefore</c>, retired ones included, and kept them there for as long
/// as the row existed. Retirement therefore removed a key from the JWKS and from minting, and from nothing
/// else — the one reaction an operator has to a leaked key did not reach validation.
/// </para>
/// <para>
/// Asked of the real pipeline twice: the server's own introspection endpoint and the validation stack
/// the management API authenticates with (<see cref="OpenIddictValidationService"/>). The options are
/// inspected as well, because "the retired key is not in the credential lists" is the exact contract the
/// post-configure owns, whatever OpenIddict chooses to read from them.
/// </para>
/// </summary>
[Collection("PostgresCollection")]
public sealed class SigningKeyRetirementTests : IClassFixture<PropsSigningKeyStoreFixture>
{
    private readonly PropsSigningKeyStoreFixture _fx;

    public SigningKeyRetirementTests(PropsSigningKeyStoreFixture fx) => _fx = fx;

    [Fact]
    public async Task A_rotated_key_keeps_validating_and_a_retired_key_stops_immediately()
    {
        var firstKid = await ActiveSigningKidAsync();
        var token = await MintAsync();
        KidOf(token).Should().Be(firstKid, "the active key is the one OpenIddict signs with");
        (await IntrospectedActiveAsync(token)).Should().BeTrue("a freshly issued token is active");

        // Rotation: a new active key, the old one demoted but still inside its NotAfter window.
        var rotated = await _fx.Store.RotateAsync("signing");
        rotated.Kid.Should().NotBe(firstKid);
        (await ActiveSigningKidAsync()).Should().Be(rotated.Kid);
        KidOf(await MintAsync()).Should().Be(rotated.Kid, "new tokens are signed by the new key");

        (await IntrospectedActiveAsync(token)).Should().BeTrue(
            "a token signed under the demoted key validates until that key's own NotAfter — the handover "
            + "window is the whole point of rotation");
        await ValidationStackAcceptsAsync(token, expected: true);

        // Retirement: NotAfter is now. Trust ends here, for every consumer of the key.
        (await _fx.Store.RetireAsync(firstKid)).Should().BeTrue();

        // Compared by key material, not by KeyId: the objects in these lists get their KeyId set only when
        // they are wrapped into credentials, so a stale entry may carry none and a KeyId check would pass
        // right through it.
        var retiredMaterial = Fingerprint((await _fx.Store.ListAllIncludingRetiredAsync()).Single(k => k.Kid == firstKid).SecurityKey);
        var options = _fx.ServiceProvider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        options.SigningCredentials.Select(c => Fingerprint(c.Key)).Should().NotContain(retiredMaterial,
            "a retired key must not be offered for minting");
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint).Should().NotContain(retiredMaterial,
            "a retired key must not be offered for validation either - this is the list that kept it");
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint).Should().Contain(Fingerprint(rotated.SecurityKey),
            "the key that is still in its window stays trusted");

        (await IntrospectedActiveAsync(token)).Should().BeFalse(
            "the key that signed this token was retired; a leaked key that keeps validating tokens is the "
            + "one failure a signing-key store exists to prevent");
        await ValidationStackAcceptsAsync(token, expected: false);
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────

    private async Task<string> ActiveSigningKidAsync()
    {
        var keys = await _fx.Store.GetAllAsync();
        return keys.Single(k => k.IsActive && k.KeyKind == "signing").Kid;
    }

    private async Task<string> MintAsync()
    {
        var result = await _fx.Request(IdentityEndpoints.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = PropsSigningKeyStoreFixture.ClientId,
            ["client_secret"] = PropsSigningKeyStoreFixture.ClientSecret,
            ["scope"] = PropsSigningKeyStoreFixture.Scope,
        });

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error", "the token request must succeed before anything about keys can be tested");
        return response["access_token"]!.ToString()!;
    }

    /// <summary>What the server itself says about the token (RFC 7662) - <c>active</c>, never an error.</summary>
    private async Task<bool> IntrospectedActiveAsync(string accessToken)
    {
        var result = await _fx.Request(IdentityEndpoints.Introspect, new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["client_id"] = PropsSigningKeyStoreFixture.ClientId,
            ["client_secret"] = PropsSigningKeyStoreFixture.ClientSecret,
        });

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        // RFC 7662 §2.2 wants an invalid token answered with active=false; OpenIddict answers a token
        // whose signing key it cannot find with an invalid_token error instead (ID2090). Both are the
        // server saying "no", and "no" is what this helper reports. Any other error is a broken request.
        if (response.TryGetValue("error", out var error))
        {
            error.Should().Be("invalid_token", "only a refusal of the token itself counts as inactive");
            return false;
        }

        return response["active"] is true or "true" or "True";
    }

    /// <summary>
    /// The validation stack the management API authenticates bearer tokens with. It answers with a
    /// principal or throws; which of the two is the whole question.
    /// </summary>
    private async Task ValidationStackAcceptsAsync(string accessToken, bool expected)
    {
        var validation = _fx.ServiceProvider.GetRequiredService<OpenIddictValidationService>();
        var attempt = async () => await validation.ValidateAccessTokenAsync(accessToken);

        if (expected)
            await attempt.Should().NotThrowAsync("the validation stack must accept a token whose key is still in its window");
        else
            await attempt.Should().ThrowAsync<Exception>("the validation stack must refuse a token signed by a retired key");
    }

    /// <summary>
    /// The public material of a key, so two <see cref="SecurityKey"/> objects can be compared as keys
    /// rather than as references or by a <c>KeyId</c> that may not have been set on one of them.
    /// </summary>
    private static string Fingerprint(SecurityKey key) => key switch
    {
        RsaSecurityKey rsa => "rsa:" + Convert.ToHexString(
            (rsa.Rsa is not null ? rsa.Rsa.ExportParameters(false) : rsa.Parameters).Modulus!),
        _ => throw new InvalidOperationException($"the store only produces RSA keys; got {key.GetType().Name}"),
    };

    /// <summary>The <c>kid</c> from the JOSE header of a plain JWS.</summary>
    private static string KidOf(string jws)
    {
        var header = jws.Split('.')[0].Replace('-', '+').Replace('_', '/');
        header = header.PadRight(header.Length + (4 - header.Length % 4) % 4, '=');
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(header)));
        return doc.RootElement.GetProperty("kid").GetString()
               ?? throw new InvalidOperationException("the access token header carries no kid");
    }
}
