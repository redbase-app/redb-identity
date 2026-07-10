using System.Net;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// G5 DoD — HTTP-level checks pinning the B3/B5/B7 transport & single-use contracts:
/// <list type="number">
/// <item>POST /mfa without the <c>__Host-redb.identity.mfa</c> cookie never issues a session.</item>
/// <item>Same <c>jti</c>+<c>code</c> replayed → second submission does not create a second session
///      (idempotent-consumer dedupe at route level, keyed by <c>mfa-verify:{jti}:{code}</c>).</item>
/// <item>The encrypted <c>mfa_state</c> blob carries only an OTP <c>jti</c> reference —
///      never the plaintext OTP code (B3 contract; regression guard for state-leak scenarios).</item>
/// </list>
/// </summary>
[Collection("ProductionHttp")]
public sealed class MfaStateCookieG5Tests
{
    private readonly ProductionHttpFixture _fx;

    public MfaStateCookieG5Tests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task MfaVerify_WithoutStateCookie_DoesNotIssueSession()
    {
        var (login, password, secretBase32) = await SeedMfaUserAsync();

        // Step 1 — login with one cookie jar to obtain a valid mfa-state cookie (sanity).
        var jar1 = new CookieContainer();
        using (var c1 = CreateClient(jar1))
        {
            var loginResp = await c1.PostAsync("/login", Form(new()
            {
                ["username"] = login,
                ["password"] = password
            }));
            loginResp.StatusCode.Should().Be(HttpStatusCode.Redirect);
            HasMfaStateCookie(jar1).Should().BeTrue("sanity — login must set the mfa-state cookie");
        }

        // Step 2 — attacker-style request: POST /mfa from an EMPTY cookie jar with a
        // forged-looking TOTP code but NO __Host-redb.identity.mfa cookie at all.
        var jar2 = new CookieContainer();
        using var c2 = CreateClient(jar2);
        var code = GenerateValidTotp(secretBase32);
        var verifyResp = await c2.PostAsync("/mfa", Form(new()
        {
            ["code"] = code
        }));

        HasSessionCookie(jar2).Should().BeFalse(
            "no session cookie may be issued for a verify request that carries no mfa-state cookie");
    }

    [Fact]
    public async Task MfaVerify_SameJtiReplayed_SecondCallDoesNotIssueAnotherSession()
    {
        var (login, password, secretBase32) = await SeedMfaUserAsync();
        var jar = new CookieContainer();
        using var client = CreateClient(jar);

        await client.PostAsync("/login", Form(new()
        {
            ["username"] = login,
            ["password"] = password
        }));
        HasMfaStateCookie(jar).Should().BeTrue();

        // Capture the mfa-state cookie value BEFORE we submit it — a successful verify
        // clears the cookie (Max-Age=0), so we need to replay it by hand on a fresh client.
        var mfaStateCookieValue = MfaStateCookieValue(jar)!;

        // Make both client jars so that the first verify's session-cookie-set does not
        // contaminate the replay client (we want to observe cookies independently).
        var code = GenerateValidTotp(secretBase32);

        var jar1 = new CookieContainer();
        using (var c1 = CreateClient(jar1))
        {
            // Inject the captured mfa-state cookie manually.
            jar1.Add(new Uri(_fx.BaseUrl), new System.Net.Cookie(
                MfaStateCookieName(), mfaStateCookieValue) { HttpOnly = true });
            var resp1 = await c1.PostAsync("/mfa", Form(new() { ["code"] = code }));
            HasSessionCookie(jar1).Should().BeTrue("first verify must succeed");
        }

        // Now replay the SAME jti (same cookie value) + SAME code on a fresh jar.
        // IdempotentConsumer keyed by mfa-verify:{jti}:{code} with skipDuplicate=true —
        // the processor must NOT issue a brand-new session for the replay.
        var jar2 = new CookieContainer();
        using (var c2 = CreateClient(jar2))
        {
            jar2.Add(new Uri(_fx.BaseUrl), new System.Net.Cookie(
                MfaStateCookieName(), mfaStateCookieValue) { HttpOnly = true });
            var resp2 = await c2.PostAsync("/mfa", Form(new() { ["code"] = code }));

            // The route-level IdempotentConsumer is registered with skipDuplicate=true, so
            // the second call skips MfaVerifyProcessor entirely and no Set-Cookie for the
            // session cookie is emitted. Anything else would let an attacker who captured
            // the mfa-state cookie mint additional sessions at will.
            HasSessionCookie(jar2).Should().BeFalse(
                "replayed jti+code must not mint a second session");
        }
    }

    [Fact]
    public void MfaStateBlob_DoesNotCarryPlaintextOtpCode()
    {
        // B3 / G5 §7 regression guard: the encrypted mfa_state blob is the only artefact that
        // travels in the cookie, and it MUST only reference the OTP by jti — never include the
        // plaintext code. This is what keeps `OTP not in URL/logs` true even if a correlation
        // logger inadvertently logs the state cookie.
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            OtpJti = Guid.NewGuid(),
            OtpMethod = "sms",
            OtpExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            ReturnUrl = "/",
            IssuedAt = DateTimeOffset.UtcNow,
            Jti = Guid.NewGuid()
        };

        var json = System.Text.Json.JsonSerializer.Serialize(state);
        json.Should().NotContain("OtpCode", "MfaState must not carry OTP plaintext (B3)");
        json.Should().NotContain("otpCode");

        // Also pin the reflection-level contract so future refactors that add a plaintext
        // OTP property back onto MfaState trip this test.
        var propNames = typeof(MfaState)
            .GetProperties()
            .Select(p => p.Name)
            .ToArray();
        propNames.Should().NotContain("OtpCode");
        propNames.Should().NotContain("Code");
        propNames.Should().Contain("OtpJti");
    }

    // ── helpers ──

    private HttpClient CreateClient(CookieContainer jar) =>
        new(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = jar,
            UseCookies = true
        })
        { BaseAddress = new Uri(_fx.BaseUrl) };

    private static FormUrlEncodedContent Form(Dictionary<string, string> kv) => new(kv);

    private bool HasSessionCookie(CookieContainer jar)
    {
        foreach (System.Net.Cookie c in jar.GetCookies(new Uri(_fx.BaseUrl)))
        {
            if (c.Name.EndsWith("redb.identity.session", StringComparison.Ordinal) && !string.IsNullOrEmpty(c.Value))
                return true;
        }
        return false;
    }

    private bool HasMfaStateCookie(CookieContainer jar)
    {
        foreach (System.Net.Cookie c in jar.GetCookies(new Uri(_fx.BaseUrl)))
        {
            if (c.Name.EndsWith("redb.identity.mfa", StringComparison.Ordinal) && !string.IsNullOrEmpty(c.Value))
                return true;
        }
        return false;
    }

    private string MfaStateCookieName() => "redb.identity.mfa";

    private string? MfaStateCookieValue(CookieContainer jar)
    {
        foreach (System.Net.Cookie c in jar.GetCookies(new Uri(_fx.BaseUrl)))
        {
            if (c.Name.EndsWith("redb.identity.mfa", StringComparison.Ordinal))
                return c.Value;
        }
        return null;
    }

    private static string GenerateValidTotp(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    private async Task<(string Login, string Password, string SecretBase32)> SeedMfaUserAsync()
    {
        var login = $"mfa-g5-{Guid.NewGuid():N}".Substring(0, 24);
        var password = "Mfa@G5#Test123!";
        var secretBase32 = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));

        var coreUser = await _fx.Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = password,
            Name = login,
            Email = $"{login}@example.com",
            Phone = "+1999000111",
            Enabled = true
        });

        var protector = _fx.ServiceProvider.GetRequiredService<MfaSecretProtector>();
        var mfaObj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            DefaultMethod = "totp",
            TotpSecret = protector.Protect(secretBase32),
            TotpConfirmed = true
        });
        mfaObj.name = login;
        mfaObj.key = coreUser.Id;
        await _fx.Redb.SaveAsync(mfaObj);

        return (login, password, secretBase32);
    }
}
