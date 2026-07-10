using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Models;
using redb.Identity.Core.PasswordReset;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// N-4 (Session C): full-stack E2E tests for the anonymous password-recovery flow.
/// Path: HTTP → Kestrel → PasswordRecoveryController (no auth) → direct-vm → processor →
/// IPasswordResetTokenStore + InMemoryEmailNotificationChannel + redb stores.
/// <para>
/// Asserts the anti-enumeration contract (always 200, no e-mail sent on misses), the
/// single-use token guarantee, the per-client URL whitelist, and the post-reset session
/// revocation effect (old password rejected, new password accepted).
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class FullStackPasswordRecoveryTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    private const string ResetEmail = "e2e@example.com";
    private const string ResetUrl = "http://localhost/reset-password";
    private const string ResetUrlNotWhitelisted = "http://attacker.example/reset";
    private const string ClientId = ProductionHttpFixture.TestClientId;

    public FullStackPasswordRecoveryTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Test setup helpers
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Ensures the test client carries <paramref name="resetUrl"/> on its
    /// <c>ApplicationProps.PasswordResetUris</c> whitelist. Idempotent — adds the URL
    /// only if it is not already present.
    /// </summary>
    private async Task EnsureWhitelistedAsync(string resetUrl)
    {
        await _fx.UseRedbAsync(async redb =>
        {
            var app = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == ClientId)
                .FirstOrDefaultAsync();
            app.Should().NotBeNull("seed for {0} must exist", ClientId);
            var existing = app!.Props.PasswordResetUris ?? Array.Empty<string>();
            if (existing.Contains(resetUrl, StringComparer.Ordinal)) return;
            app.Props.PasswordResetUris = existing.Concat(new[] { resetUrl }).ToArray();
            await redb.SaveAsync(app);
        });
    }

    private static (string jti, string token) ExtractResetParams(string html)
    {
        // BuildResetLink writes …?token=<urlEncoded>&jti=<guid:N>
        var jtiMatch = Regex.Match(html, @"jti=([0-9a-fA-F]{32})");
        var tokenMatch = Regex.Match(html, @"token=([A-Za-z0-9\-_%]+)");
        jtiMatch.Success.Should().BeTrue("reset e-mail must carry jti=… ; body was: {0}", html);
        tokenMatch.Success.Should().BeTrue("reset e-mail must carry token=… ; body was: {0}", html);
        return (jtiMatch.Groups[1].Value, Uri.UnescapeDataString(tokenMatch.Groups[1].Value));
    }

    private async Task<HttpResponseMessage> PostForgotAsync(string email, string callerResetUrl, string clientId = ClientId)
        => await _http.PostAsJsonAsync("/api/v1/identity/password/forgot",
            new { email, clientId, callerResetUrl });

    private async Task<HttpResponseMessage> PostResetAsync(string jti, string token, string newPassword)
        => await _http.PostAsJsonAsync("/api/v1/identity/password/reset",
            new { jti, token, newPassword });

    private async Task<HttpResponseMessage> TryPasswordGrantAsync(string username, string password)
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });
        return await _http.PostAsync("/connect/token", content);
    }

    /// <summary>
    /// Restore the seeded password so other tests in the ProductionHttp collection keep
    /// working regardless of execution order. Direct store call via the IUserProvider —
    /// bypasses the password-history check the public flow enforces.
    /// </summary>
    private async Task RestoreSeedPasswordAsync()
    {
        await _fx.UseRedbAsync(async redb =>
        {
            var user = await redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername);
            if (user is null) return;
            await redb.UserProvider.SetPasswordAsync(user, ProductionHttpFixture.TestPassword);
        });
    }

    // ══════════════════════════════════════════════════════════════════
    //  Happy path — token issued, e-mail captured, reset succeeds
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ForgotReset_HappyPath_IssuesEmail_AcceptsReset_RevokesOldPassword()
    {
        await EnsureWhitelistedAsync(ResetUrl);
        _fx.Emails.Clear();

        // 1. Initiate recovery
        var forgotResp = await PostForgotAsync(ResetEmail, ResetUrl);
        forgotResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var forgotJson = await forgotResp.Content.ReadFromJsonAsync<JsonElement>();
        forgotJson.GetProperty("success").GetBoolean().Should().BeTrue();

        // 2. Captured e-mail must contain a reset link
        var captured = _fx.Emails.ForRecipient(ResetEmail);
        captured.Should().HaveCount(1, "the happy-path forgot call must dispatch exactly one reset e-mail");
        var msg = captured[0];
        msg.TemplateId.Should().Be(IdentityEmailTemplates.PasswordReset);
        msg.HtmlBody.Should().Contain(ResetUrl);

        var (jti, token) = ExtractResetParams(msg.HtmlBody);

        // 3. Consume the token to set a new password. Suffix with a fresh GUID so reruns
        // against the same DB are not blocked by the password-history ("last N passwords") rule.
        var newPassword = $"E2E@NewPwd-{Guid.NewGuid():N}!";
        try
        {
            var resetResp = await PostResetAsync(jti, token, newPassword);
            resetResp.StatusCode.Should().Be(HttpStatusCode.OK,
                "happy-path reset must succeed: {0}", await resetResp.Content.ReadAsStringAsync());
            var resetJson = await resetResp.Content.ReadFromJsonAsync<JsonElement>();
            resetJson.GetProperty("success").GetBoolean().Should().BeTrue();

            // 4. Old password must no longer work…
            using (var oldAttempt = await TryPasswordGrantAsync(ProductionHttpFixture.TestUsername, ProductionHttpFixture.TestPassword))
            {
                oldAttempt.StatusCode.Should().NotBe(HttpStatusCode.OK,
                    "old password must be rejected after a successful reset");
            }

            // 5. …and the new password must.
            using var newAttempt = await TryPasswordGrantAsync(ProductionHttpFixture.TestUsername, newPassword);
            newAttempt.StatusCode.Should().Be(HttpStatusCode.OK,
                "new password must be accepted by the ROPC flow: {0}",
                await newAttempt.Content.ReadAsStringAsync());
        }
        finally
        {
            await RestoreSeedPasswordAsync();
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Anti-enumeration — unknown e-mail returns success, no e-mail sent
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Forgot_UnknownEmail_ReturnsSuccess_NoEmailSent()
    {
        await EnsureWhitelistedAsync(ResetUrl);
        _fx.Emails.Clear();

        var resp = await PostForgotAsync("nobody-here-please-ignore@example.invalid", ResetUrl);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("success").GetBoolean().Should().BeTrue();

        _fx.Emails.Messages.Should().BeEmpty(
            "anti-enumeration: unknown e-mail must not trigger any dispatch");
    }

    // ══════════════════════════════════════════════════════════════════
    //  Anti-enumeration — non-whitelisted callerResetUrl is silently dropped
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Forgot_CallerResetUrlNotWhitelisted_ReturnsSuccess_NoEmailSent()
    {
        await EnsureWhitelistedAsync(ResetUrl);
        _fx.Emails.Clear();

        var resp = await PostForgotAsync(ResetEmail, ResetUrlNotWhitelisted);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        _fx.Emails.ForRecipient(ResetEmail).Should().BeEmpty(
            "open-redirect protection: a non-whitelisted CallerResetUrl must drop the request silently");
    }

    // ══════════════════════════════════════════════════════════════════
    //  Anti-enumeration — unknown client_id returns success, no e-mail sent
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Forgot_UnknownClient_ReturnsSuccess_NoEmailSent()
    {
        _fx.Emails.Clear();

        var resp = await PostForgotAsync(ResetEmail, ResetUrl, clientId: "no-such-client-id");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        _fx.Emails.Messages.Should().BeEmpty(
            "anti-enumeration: unknown client_id must drop the request silently");
    }

    // ══════════════════════════════════════════════════════════════════
    //  Single-use guarantee — second reset attempt with the same token fails
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Reset_SecondAttemptWithSameToken_Fails()
    {
        await EnsureWhitelistedAsync(ResetUrl);
        _fx.Emails.Clear();

        await PostForgotAsync(ResetEmail, ResetUrl);
        var captured = _fx.Emails.ForRecipient(ResetEmail);
        captured.Should().HaveCount(1);
        var (jti, token) = ExtractResetParams(captured[0].HtmlBody);

        // Fresh GUID-suffixed password keeps reruns clear of the password-history rule.
        var newPassword = $"E2E@OnceOnly-{Guid.NewGuid():N}!";
        try
        {
            using var first = await PostResetAsync(jti, token, newPassword);
            first.StatusCode.Should().Be(HttpStatusCode.OK, "first consume must succeed");

            // Second attempt with the SAME token: row is already marked Consumed.
            using var second = await PostResetAsync(jti, token, "E2E@WillNotApply-" + Guid.NewGuid().ToString("N") + "!");
            second.StatusCode.Should().NotBe(HttpStatusCode.OK,
                "single-use guarantee: a second reset with the same token must be rejected");
        }
        finally
        {
            await RestoreSeedPasswordAsync();
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Expired token — direct store call with a near-zero TTL, then consume
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Reset_ExpiredToken_Fails()
    {
        // Issue directly through the store with a TTL that has already elapsed.
        // Wait 150 ms past expiry to defeat any clock granularity, then attempt consume.
        var sp = (IServiceProvider)typeof(ProductionHttpFixture)
            .GetField("_sp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(_fx)!;

        var resetStore = sp.GetRequiredService<IPasswordResetTokenStore>();

        long userId = await _fx.UseRedbAsync(async redb =>
        {
            var u = await redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername);
            return u!.Id;
        });

        var issued = await resetStore.IssueAsync(userId, ResetUrl, TimeSpan.FromMilliseconds(1));
        await Task.Delay(150);

        using var resp = await PostResetAsync(issued.Jti.ToString("N"), issued.PlaintextToken, "E2E@WontApply123!");
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK,
            "expired tokens must be rejected by VerifyAndConsumeAsync");
    }
}
