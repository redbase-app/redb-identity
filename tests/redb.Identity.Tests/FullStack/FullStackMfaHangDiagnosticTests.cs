using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Diagnostic-only: reproduce the sequential-test hang in a single method so we can
/// inspect server logs without fighting the xUnit scheduler. Does NOT assert flow
/// correctness — its purpose is to expose the hang/not-hang boundary.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackMfaHangDiagnosticTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public FullStackMfaHangDiagnosticTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    private HttpClient NewClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = new CookieContainer(),
            UseCookies = true
        };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
    }

    [Fact]
    public async Task TwoSequentialLogins_ShouldNotHang()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        _out.WriteLine("=== first POST /login ===");
        using (var c1 = NewClient())
        {
            var r1 = await c1.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "nonexistent-user-1",
                ["password"] = "wrong"
            }), cts.Token);
            _out.WriteLine($"first status={r1.StatusCode}");
        }

        _out.WriteLine("=== second POST /login ===");
        using (var c2 = NewClient())
        {
            var r2 = await c2.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "nonexistent-user-2",
                ["password"] = "wrong"
            }), cts.Token);
            _out.WriteLine($"second status={r2.StatusCode}");
        }

        _out.WriteLine("=== third POST /login ===");
        using (var c3 = NewClient())
        {
            var r3 = await c3.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "nonexistent-user-3",
                ["password"] = "wrong"
            }), cts.Token);
            _out.WriteLine($"third status={r3.StatusCode}");
        }
    }

    [Fact]
    public async Task TwoSequentialMfaPosts_ShouldNotHang()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        _out.WriteLine("=== first POST /mfa ===");
        using (var c1 = NewClient())
        {
            var r1 = await c1.PostAsync("/mfa", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = "000000"
            }), cts.Token);
            _out.WriteLine($"first status={r1.StatusCode}");
        }

        _out.WriteLine("=== second POST /mfa ===");
        using (var c2 = NewClient())
        {
            var r2 = await c2.PostAsync("/mfa", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = "000000"
            }), cts.Token);
            _out.WriteLine($"second status={r2.StatusCode}");
        }
    }

    /// <summary>
    /// Reproduces the suspected shape of the sequential-test hang: two consecutive
    /// (seed MFA user → POST /login → POST /mfa) flows in ONE test, each with its
    /// own cookie jar.
    /// </summary>
    [Fact]
    public async Task TwoFullMfaFlows_InOneTest_ShouldNotHang()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        async Task RunOne(string label)
        {
            _out.WriteLine($"=== flow {label}: seeding user ===");
            var (login, password, secret) = await SeedMfaUserAsync();

            using var client = NewClient();
            _out.WriteLine($"=== flow {label}: POST /login ===");
            var r1 = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = login,
                ["password"] = password
            }), cts.Token);
            _out.WriteLine($"flow {label}: login={r1.StatusCode}");

            var code = GenerateValidTotp(secret);
            _out.WriteLine($"=== flow {label}: POST /mfa ===");
            var r2 = await client.PostAsync("/mfa", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = code
            }), cts.Token);
            _out.WriteLine($"flow {label}: verify={r2.StatusCode}");
        }

        await RunOne("A");
        await RunOne("B");
    }

    /// <summary>
    /// Variant: only POST /login (skip /mfa). If this passes but the full flow hangs,
    /// the culprit is the verify step itself (tx / LockForUpdate / SessionService.CreateAsync).
    /// </summary>
    [Fact]
    public async Task TwoLoginsWithMfaSeed_NoVerify_ShouldNotHang()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        async Task RunOne(string label)
        {
            var (login, password, _) = await SeedMfaUserAsync();
            using var client = NewClient();
            _out.WriteLine($"=== flow {label}: POST /login ===");
            var r1 = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = login,
                ["password"] = password
            }), cts.Token);
            _out.WriteLine($"flow {label}: login={r1.StatusCode}");
        }

        await RunOne("A");
        await RunOne("B");
    }

    // ── helpers (copied minimal subset from FullStackMfaTests) ──

    private async Task<(string login, string password, string secret)> SeedMfaUserAsync()
    {
        var login = $"diag-{Guid.NewGuid():N}".Substring(0, 20);
        var password = "Diag@Test123!";
        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));

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
            TotpSecret = protector.Protect(secret),
            TotpConfirmed = true
        });
        mfaObj.name = login;
        mfaObj.key = coreUser.Id;
        await _fx.Redb.SaveAsync(mfaObj);

        return (login, password, secret);
    }

    private static string GenerateValidTotp(string secret)
    {
        var totp = new Totp(Base32Encoding.ToBytes(secret), step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }
}
