using System.Net;
using FluentAssertions;
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
/// G10 DoD — HTTP-level pins on session lifecycle & logout semantics (C7 + C8):
/// <list type="number">
/// <item>Successful MFA verify creates a brand-new <see cref="SessionProps"/> row with
///       <see cref="SessionProps.MfaVerified"/>=<c>true</c> — there is no prior session to
///       rotate (no session cookie is issued before MFA passes), so "session-id rotation"
///       collapses to "session creation gated on the second factor".</item>
/// <item><c>POST /connect/logout</c> with a valid session cookie:
///       emits a <c>Max-Age=0</c> Set-Cookie for the session cookie <b>and</b> flips the
///       underlying <see cref="SessionProps.Status"/> to <c>"revoked"</c> in the PROPS store.</item>
/// </list>
/// Authorization/refresh-token cascade is pinned by
/// <see cref="Session.SessionServiceTests.Logout_RevokesSessionsAndAuthorizations"/>.
/// </summary>
[Collection("ProductionHttp")]
public sealed class LogoutG10Tests
{
    private readonly ProductionHttpFixture _fx;

    public LogoutG10Tests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task MfaVerify_CreatesNewSessionRow_WithMfaVerifiedTrue()
    {
        var (login, password, secretBase32, userId) = await SeedMfaUserAsync();

        var sessionsBefore = await _fx.Redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync();
        sessionsBefore.Should().BeEmpty(
            "C7: no server-side session row exists for a user who has only entered a password");

        var jar = new CookieContainer();
        using var client = CreateClient(jar);

        await client.PostAsync("/login", Form(new()
        {
            ["username"] = login,
            ["password"] = password
        }));

        // Password-only submit must NOT create a session row — the backend only gates a
        // SessionProps insert on successful MFA verify (see MfaVerifyProcessor).
        var midFlow = await _fx.Redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync();
        midFlow.Should().BeEmpty("post-password pre-MFA must not create a server-side session");

        var code = GenerateValidTotp(secretBase32);
        await client.PostAsync("/mfa", Form(new() { ["code"] = code }));

        var afterMfa = await _fx.Redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync();
        afterMfa.Should().HaveCount(1, "MFA verify creates exactly one session row");
        afterMfa[0].Props.MfaVerified.Should().BeTrue(
            "session row must record that the second factor was satisfied");
        afterMfa[0].Props.Status.Should().Be("active");
    }

    [Fact]
    public async Task Logout_ClearsSessionCookie_AndMarksSessionRowRevoked()
    {
        var jar = new CookieContainer();
        using var client = CreateClient(jar);

        // Login with the shared MFA-free user — we want a session cookie without the MFA detour.
        var loginResp = await client.PostAsync("/login", Form(new()
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        }));
        ((int)loginResp.StatusCode).Should().BeOneOf(200, 302);
        HasSessionCookie(jar).Should().BeTrue("sanity — login must issue the session cookie");

        // Capture the active session row id BEFORE logout so we can verify it was flipped to 'revoked'.
        // We can resolve userId via TestUserId helper, but the fixture does not expose it — just
        // query active sessions we newly created (there may be residue from other tests; take the
        // max id which is guaranteed newer than any previous snapshot).
        var activeBefore = await _fx.Redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .ToListAsync();
        var ourSession = activeBefore.OrderByDescending(s => s.id).FirstOrDefault();
        ourSession.Should().NotBeNull("login must have inserted at least one active session row");

        // Perform logout via POST /connect/logout (cookie jar auto-forwards the session cookie).
        var logoutResp = await client.PostAsync("/connect/logout", Form(new()));
        // The endpoint may either render the Signed-Out page (200) or redirect to the post-logout URI.
        ((int)logoutResp.StatusCode).Should().BeOneOf(200, 302);

        // The server must emit a Max-Age=0 Set-Cookie for the session cookie. With the cookie
        // jar tracking lifetime automatically, the cookie is removed from the jar after expiry.
        HasSessionCookie(jar).Should().BeFalse(
            "logout must emit a Max-Age=0 Set-Cookie that evicts the session cookie from the UA");

        // And the underlying SessionProps row must be marked revoked (LogoutProcessor →
        // SessionService.LogoutAsync cascades to all of the user's active sessions).
        var reloaded = await _fx.Redb.LoadAsync<SessionProps>(ourSession!.id);
        reloaded.Should().NotBeNull();
        reloaded!.Props.Status.Should().Be("revoked",
            "logout must flip SessionProps.Status to 'revoked' for server-side enforcement");
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

    private static string GenerateValidTotp(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    private async Task<(string Login, string Password, string SecretBase32, long UserId)> SeedMfaUserAsync()
    {
        var login = $"mfa-g10-{Guid.NewGuid():N}".Substring(0, 24);
        var password = "Mfa@G10#Test123!";
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

        return (login, password, secretBase32, coreUser.Id);
    }
}
