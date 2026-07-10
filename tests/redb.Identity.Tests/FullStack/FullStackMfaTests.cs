using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for the interactive MFA browser flow:
/// login (with MFA-enabled user) → 302 to /mfa → POST verify code → session cookie set.
/// Covers TOTP success, invalid code re-render, and recovery code usage.
/// Each test uses a freshly seeded MFA-enabled user so the shared <see cref="ProductionHttpFixture.TestUsername"/>
/// stays MFA-free for the other browser flow tests.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackMfaTests
{
    private readonly ProductionHttpFixture _fx;

    public FullStackMfaTests(ProductionHttpFixture fx)
    {
        _fx = fx;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Login → MFA challenge redirect
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Login_WithMfaEnabledUser_RedirectsToMfaPage()
    {
        var (login, password, _) = await SeedMfaUserAsync();
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        var resp = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = login,
            ["password"] = password
        }));

        resp.StatusCode.Should().Be(HttpStatusCode.Redirect, "MFA-enabled login must redirect to /mfa");
        var location = resp.Headers.Location?.ToString() ?? "";
        location.Should().StartWith("/mfa");
        // B3 §4: mfa_state is NO LONGER echoed into the URL — transported via HttpOnly cookie.
        location.Should().NotContain("mfa_state=");
        // B9 / BUG-9: mfa_methods is NO LONGER echoed into the URL — the MFA page derives
        // the methods server-side from the encrypted state.
        location.Should().NotContain("mfa_methods=");

        // MFA challenge MUST NOT set the session cookie yet — full auth requires the second factor.
        // (An MFA-state cookie IS set, but it is not a session.)
        HasSessionCookie(cookies).Should().BeFalse(
            "no session cookie may be issued before MFA verification succeeds");
        HasMfaStateCookie(cookies).Should().BeTrue(
            "MFA challenge must issue the HttpOnly mfa-state cookie (B3 §4)");
    }

    // ══════════════════════════════════════════════════════════════════
    //  POST /mfa with valid TOTP → session cookie
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Mfa_Verify_WithValidTotpCode_SetsSessionCookie()
    {
        var (login, password, secretBase32) = await SeedMfaUserAsync();
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        // Step 1 — login → 302 /mfa, mfa-state cookie set
        var loginResp = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = login,
            ["password"] = password
        }));
        HasMfaStateCookie(cookies).Should().BeTrue();

        // Step 2 — POST /mfa with valid TOTP code (mfa-state cookie sent automatically)
        var code = GenerateValidTotp(secretBase32);
        var verifyResp = await client.PostAsync("/mfa", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = code
        }));

        // Session cookie MUST be set on successful verification
        HasSessionCookie(cookies).Should().BeTrue(
            "successful MFA verification must issue the session cookie");
    }

    // ══════════════════════════════════════════════════════════════════
    //  POST /mfa with invalid code → form re-render, no cookie
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Mfa_Verify_WithInvalidTotpCode_DoesNotSetCookie()
    {
        var (login, password, _) = await SeedMfaUserAsync();
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        var loginResp = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = login,
            ["password"] = password
        }));
        HasMfaStateCookie(cookies).Should().BeTrue();

        var verifyResp = await client.PostAsync("/mfa", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = "000000"
        }));

        HasSessionCookie(cookies).Should().BeFalse(
            "invalid MFA code must NOT issue a session cookie");
    }

    // ══════════════════════════════════════════════════════════════════
    //  POST /mfa/recovery with valid recovery code → session cookie
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task MfaRecovery_WithValidCode_SetsSessionCookie()
    {
        var (login, password, _, plainRecoveryCode) = await SeedMfaUserWithRecoveryAsync();
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        var loginResp = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = login,
            ["password"] = password
        }));
        HasMfaStateCookie(cookies).Should().BeTrue();

        var resp = await client.PostAsync("/mfa/recovery", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["recovery_code"] = plainRecoveryCode
        }));

        HasSessionCookie(cookies).Should().BeTrue(
            "valid recovery code must issue the session cookie");
    }

    // ══════════════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════════════

    private HttpClient CreateBrowserClient(CookieContainer? cookies = null, bool allowRedirect = true)
    {
        cookies ??= new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = allowRedirect,
            CookieContainer = cookies,
            UseCookies = true
        };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
    }

    private bool HasSessionCookie(CookieContainer cookies)
    {
        foreach (System.Net.Cookie c in cookies.GetCookies(new Uri(_fx.BaseUrl)))
        {
            // Bare or __Host- prefixed session cookie
            if (c.Name.EndsWith("redb.identity.session", StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private bool HasMfaStateCookie(CookieContainer cookies)
    {
        foreach (System.Net.Cookie c in cookies.GetCookies(new Uri(_fx.BaseUrl)))
        {
            if (c.Name.EndsWith("redb.identity.mfa", StringComparison.Ordinal) && !string.IsNullOrEmpty(c.Value))
                return true;
        }
        return false;
    }

    private static string? ExtractQueryParam(string url, string param)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        var query = url[(idx + 1)..];
        foreach (var pair in query.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == param)
                return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    private static string GenerateValidTotp(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    /// <summary>
    /// Seeds (or reuses) a dedicated MFA-enabled test user with a confirmed TOTP secret.
    /// Each test gets its own login (so failure counters / lockouts don't leak across tests).
    /// Returns (login, password, base32 secret).
    /// </summary>
    private async Task<(string Login, string Password, string SecretBase32)> SeedMfaUserAsync()
    {
        var login = $"mfa-e2e-{Guid.NewGuid():N}".Substring(0, 24);
        var password = "Mfa@E2E#Test123!";
        var secretBase32 = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));

        await CreateUserAndMfaPropsAsync(login, password, secretBase32, recoveryHashes: null);
        return (login, password, secretBase32);
    }

    /// <summary>Seeds an MFA-enabled user plus a single recovery code; returns the plaintext code too.</summary>
    private async Task<(string Login, string Password, string SecretBase32, string RecoveryCode)>
        SeedMfaUserWithRecoveryAsync()
    {
        var login = $"mfa-rec-{Guid.NewGuid():N}".Substring(0, 24);
        var password = "Mfa@E2E#Test123!";
        var secretBase32 = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        var plainRecovery = $"REC-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        var hash = HashRecoveryCode(plainRecovery);

        await CreateUserAndMfaPropsAsync(login, password, secretBase32, new List<string> { hash });
        return (login, password, secretBase32, plainRecovery);
    }

    private async Task CreateUserAndMfaPropsAsync(
        string login, string password, string secretBase32, List<string>? recoveryHashes)
    {
        // 1. Core user via UserProvider
        var coreUser = await _fx.Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = password,
            Name = login,
            Email = $"{login}@example.com",
            Phone = "+1999000111",
            Enabled = true
        });

        // 2. MfaProps with confirmed TOTP — uses the SAME DataProtection key ring as the running server
        // so the encrypted secret can be decrypted by the server's MfaSecretProtector.
        var protector = _fx.ServiceProvider.GetRequiredService<MfaSecretProtector>();

        var mfaObj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            DefaultMethod = "totp",
            TotpSecret = protector.Protect(secretBase32),
            TotpConfirmed = true,
            RecoveryCodes = recoveryHashes
        });
        mfaObj.name = login;
        mfaObj.key = coreUser.Id;
        await _fx.Redb.SaveAsync(mfaObj);
    }

    /// <summary>
    /// Hashes a recovery code using the same algorithm as <c>MfaService.HashCode</c>:
    /// strip dashes, uppercase, SHA-256, hex (lowercase).
    /// </summary>
    private static string HashRecoveryCode(string code)
    {
        var normalized = code.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
