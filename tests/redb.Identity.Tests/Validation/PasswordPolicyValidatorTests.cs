using System.Threading;
using System.Threading.Tasks;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Security;
using Xunit;

namespace redb.Identity.Tests.Validation;

/// <summary>
/// H10 Phase 4 — pure unit tests on <see cref="DefaultPasswordPolicyValidator"/>.
/// No DI / no IRedbService — every test instantiates a fresh validator over a fresh
/// <see cref="PasswordPolicyOptions"/> snapshot so assertions are independent of the
/// project-wide STRICT defaults shipped in <c>redb.Identity.Core.config.json</c>.
/// </summary>
public class PasswordPolicyValidatorTests
{
    private static DefaultPasswordPolicyValidator MakeValidator(PasswordPolicyOptions? opts = null)
        => new(opts ?? new PasswordPolicyOptions());

    [Fact]
    public async Task EmptyPassword_Fails()
    {
        var v = MakeValidator();
        var r = await v.ValidateAsync("", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("required", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task TooShort_Fails()
    {
        var v = MakeValidator(new PasswordPolicyOptions { MinLength = 12 });
        var r = await v.ValidateAsync("Short1!aA", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("at least 12"));
    }

    [Fact]
    public async Task TooLong_Fails()
    {
        var v = MakeValidator(new PasswordPolicyOptions { MaxLength = 16 });
        var r = await v.ValidateAsync(new string('A', 8) + new string('a', 8) + "1!", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("not exceed 16"));
    }

    [Fact]
    public async Task MissingDigit_Fails()
    {
        var v = MakeValidator();
        var r = await v.ValidateAsync("StrongPasswordNoDigits", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("digit"));
    }

    [Fact]
    public async Task MissingUppercase_Fails()
    {
        var v = MakeValidator();
        var r = await v.ValidateAsync("strongpassword12345", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("uppercase"));
    }

    [Fact]
    public async Task MissingLowercase_Fails()
    {
        var v = MakeValidator();
        var r = await v.ValidateAsync("STRONGPASSWORD12345", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("lowercase"));
    }

    [Fact]
    public async Task MissingSpecial_WhenRequired_Fails()
    {
        var v = MakeValidator(new PasswordPolicyOptions { RequireSpecial = true });
        var r = await v.ValidateAsync("Str0ngPassw0rdNo", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("special"));
    }

    [Fact]
    public async Task MissingSpecial_WhenNotRequired_Passes()
    {
        var v = MakeValidator(new PasswordPolicyOptions { RequireSpecial = false });
        var r = await v.ValidateAsync("Str0ngPassw0rdNo", null, CancellationToken.None);
        Assert.True(r.IsValid);
    }

    [Fact]
    public async Task MeetsAllRules_Passes()
    {
        var v = MakeValidator();
        var r = await v.ValidateAsync("Str0ng!Passw0rd", null, CancellationToken.None);
        Assert.True(r.IsValid);
        Assert.Empty(r.Errors);
    }

    [Fact]
    public async Task MultipleViolations_AllReported()
    {
        var v = MakeValidator();
        // 3 chars, lowercase only — fails MinLength + RequireDigit + RequireUppercase
        var r = await v.ValidateAsync("abc", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.True(r.Errors.Count >= 3);
    }

    [Fact]
    public async Task HistoryCheck_WhenStoreNull_Skipped()
    {
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { HistoryCount = 5 }, history: null);
        var r = await v.ValidateAsync("Str0ng!Passw0rd", userId: 42, CancellationToken.None);
        Assert.True(r.IsValid);
    }

    [Fact]
    public async Task HistoryCheck_WhenReused_Fails()
    {
        var fakeHistory = new FakePasswordHistoryStore { Reused = true };
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { HistoryCount = 5 }, fakeHistory);
        var r = await v.ValidateAsync("Str0ng!Passw0rd", userId: 42, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("last 5 passwords"));
    }

    [Fact]
    public async Task HistoryCheck_WhenNotReused_Passes()
    {
        var fakeHistory = new FakePasswordHistoryStore { Reused = false };
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { HistoryCount = 5 }, fakeHistory);
        var r = await v.ValidateAsync("Str0ng!Passw0rd", userId: 42, CancellationToken.None);
        Assert.True(r.IsValid);
    }

    [Fact]
    public async Task BreachCheck_WhenDisabled_NotInvoked()
    {
        var fakeBreach = new FakeBreachedPasswordChecker { Breached = true };
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { BreachCheckEnabled = false },
            history: null, breachChecker: fakeBreach);
        var r = await v.ValidateAsync("Str0ng!Passw0rd", null, CancellationToken.None);
        Assert.True(r.IsValid);
        Assert.False(fakeBreach.WasCalled);
    }

    [Fact]
    public async Task BreachCheck_WhenEnabledAndBreached_Fails()
    {
        var fakeBreach = new FakeBreachedPasswordChecker { Breached = true };
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { BreachCheckEnabled = true },
            history: null, breachChecker: fakeBreach);
        var r = await v.ValidateAsync("Str0ng!Passw0rd", null, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.Contains(r.Errors, e => e.Contains("data breach"));
    }

    [Fact]
    public async Task ComposureFailure_ShortCircuitsExpensiveChecks()
    {
        // Verify that when basic rules fail, history and breach checkers are NOT called —
        // matters because they may issue I/O / HTTP that we don't want to incur for
        // obviously bad passwords.
        var fakeHistory = new FakePasswordHistoryStore { Reused = true };
        var fakeBreach = new FakeBreachedPasswordChecker { Breached = true };
        var v = new DefaultPasswordPolicyValidator(
            new PasswordPolicyOptions { HistoryCount = 5, BreachCheckEnabled = true },
            fakeHistory, fakeBreach);
        var r = await v.ValidateAsync("short", userId: 42, CancellationToken.None);
        Assert.False(r.IsValid);
        Assert.False(fakeHistory.WasCalled);
        Assert.False(fakeBreach.WasCalled);
    }

    private sealed class FakePasswordHistoryStore : IPasswordHistoryStore
    {
        public bool Reused { get; set; }
        public bool WasCalled { get; private set; }
        public Task<bool> IsRecentlyUsedAsync(long userId, string password, int count, CancellationToken ct)
        {
            WasCalled = true;
            return Task.FromResult(Reused);
        }
        public Task RecordAsync(long userId, string password, int keep, CancellationToken ct)
            => Task.CompletedTask;
    }

    private sealed class FakeBreachedPasswordChecker : IBreachedPasswordChecker
    {
        public bool Breached { get; set; }
        public bool WasCalled { get; private set; }
        public Task<bool> IsBreachedAsync(string password, CancellationToken ct)
        {
            WasCalled = true;
            return Task.FromResult(Breached);
        }
    }
}
