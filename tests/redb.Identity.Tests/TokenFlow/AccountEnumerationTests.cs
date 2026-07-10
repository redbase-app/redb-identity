using System.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Models.Users;
using redb.Core.Providers;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// C14 / SEC-A20: account-enumeration mitigation.
/// Verifies that:
///  - login responses are byte-identical for "wrong username" vs "wrong password";
///  - the LoginService performs a fake BCrypt verify on the user-not-found path so the
///    wall-clock cost is in the same order of magnitude as the wrong-password path
///    (defeats simple timing-side-channel enumeration).
/// </summary>
public class AccountEnumerationTests
{
    private const string KnownUsername = "real-user";
    private const string KnownPassword = "Correct!Password123";
    private const long KnownUserId = 1001;

    private static ServiceProvider BuildSp(IRedbUser? validatedUser)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        var redb = Substitute.For<IRedbService>();
        var userProvider = Substitute.For<IUserProvider>();

        // Mirror the production contract of ValidateUserAsync: returns null for both
        // (a) user not found and (b) user disabled — the consumer cannot tell them apart.
        userProvider.ValidateUserAsync(KnownUsername, KnownPassword)
            .Returns(Task.FromResult(validatedUser));
        userProvider.ValidateUserAsync(Arg.Is<string>(u => u != KnownUsername), Arg.Any<string>())
            .Returns(Task.FromResult<IRedbUser?>(null));
        userProvider.ValidateUserAsync(KnownUsername, Arg.Is<string>(p => p != KnownPassword))
            .Returns(Task.FromResult<IRedbUser?>(null));

        redb.UserProvider.Returns(userProvider);

        var queryable = Substitute.For<IRedbQueryable<UserProps>>();
        queryable.WhereRedb(Arg.Any<System.Linq.Expressions.Expression<Func<IRedbObject, bool>>>())
            .Returns(queryable);
        queryable.FirstOrDefaultAsync().Returns(Task.FromResult<RedbObject<UserProps>?>(null));
        redb.Query<UserProps>().Returns(queryable);

        services.AddSingleton(redb);
        services.AddTransient<LoginService>();

        return services.BuildServiceProvider();
    }

    private static IRedbUser MockUser(long id, string login, bool enabled = true)
    {
        var u = Substitute.For<IRedbUser>();
        u.Id.Returns(id);
        u.Login.Returns(login);
        u.Enabled.Returns(enabled);
        return u;
    }

    [Fact]
    public async Task WrongUsername_And_WrongPassword_ReturnIdenticalResult()
    {
        var validatedUser = MockUser(KnownUserId, KnownUsername);
        await using var sp = BuildSp(validatedUser);

        var loginService = sp.GetRequiredService<LoginService>();

        var wrongUserResult = await loginService.AuthenticateAsync("nobody", KnownPassword);
        var wrongPwResult = await loginService.AuthenticateAsync(KnownUsername, "WrongPw");

        wrongUserResult.Succeeded.Should().BeFalse();
        wrongPwResult.Succeeded.Should().BeFalse();

        // C14: identical error message — never disclose which factor mismatched.
        wrongUserResult.ErrorMessage.Should().Be(wrongPwResult.ErrorMessage);
        wrongUserResult.ErrorMessage.Should().Be("Invalid credentials.");
    }

    [Fact]
    public async Task DisabledUser_And_WrongPassword_ReturnIdenticalResult()
    {
        // ValidateUserAsync returns null for both disabled and wrong-password,
        // so AuthenticateLocal cannot distinguish them. validatedUser=null
        // simulates the disabled-account path.
        await using var sp = BuildSp(validatedUser: null);

        var loginService = sp.GetRequiredService<LoginService>();

        var disabledResult = await loginService.AuthenticateAsync(KnownUsername, KnownPassword);
        var wrongPwResult = await loginService.AuthenticateAsync(KnownUsername, "WrongPw");

        disabledResult.Succeeded.Should().BeFalse();
        wrongPwResult.Succeeded.Should().BeFalse();

        disabledResult.ErrorMessage.Should().Be(wrongPwResult.ErrorMessage);
        disabledResult.ErrorMessage.Should().Be("Invalid credentials.");
    }

    [Fact]
    public async Task UserNotFound_PerformsFakeHashVerify_ForTimingEquivalence()
    {
        // Sanity check: the wrong-username path should take real time (≥10 ms) because
        // a fake BCrypt verify runs on it. We're not asserting tight timing equivalence —
        // that is too flaky in CI — only that the unknown-username path is no longer
        // returning in <1 ms (which would be a clear timing oracle).
        var validatedUser = MockUser(KnownUserId, KnownUsername);
        await using var sp = BuildSp(validatedUser);

        var loginService = sp.GetRequiredService<LoginService>();

        // Warm up JIT + BCrypt internals.
        await loginService.AuthenticateAsync("warmup", "x");

        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 5; i++)
        {
            await loginService.AuthenticateAsync($"nobody-{i}", KnownPassword);
        }
        sw.Stop();

        var avgMs = sw.Elapsed.TotalMilliseconds / 5.0;
        avgMs.Should().BeGreaterThan(10.0,
            "the user-not-found path must perform a fake BCrypt verify so it does not " +
            "return instantly and reveal account existence via timing");
    }
}
