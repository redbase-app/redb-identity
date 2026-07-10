using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// Unit tests for <see cref="MfaRecoveryProcessor"/>:
/// Recovery code verification during login — state decryption, one-time code consumption.
/// </summary>
public sealed class MfaRecoveryProcessorTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaStateProtector _stateProtector;
    private readonly MfaService _mfaService;
    private readonly MfaRecoveryProcessor _sut;

    public MfaRecoveryProcessorTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-recovery-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        _stateProtector = new MfaStateProtector(dpProvider);
        var totpMethod = new TotpMfaMethod(secretProtector);
        _mfaService = new MfaService(
            _redb,
            new IMfaMethod[] { totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            _stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        // B1-recovery: processor now wraps the verify in BeginTransactionAsync + LockForUpdateAsync.
        // Wire no-op tx + no-op lock on the substitute so the processor path executes to completion.
        var tx = Substitute.For<redb.Core.Data.IRedbTransaction>();
        tx.CommitAsync().Returns(Task.CompletedTask);
        var ctx = Substitute.For<redb.Core.Data.IRedbContext>();
        ctx.BeginTransactionAsync().Returns(Task.FromResult(tx));
        _redb.Context.Returns(ctx);
        _redb.LockForUpdateAsync(Arg.Any<long[]>()).Returns(Task.CompletedTask);

        var sp = BuildServiceProvider(_mfaService, _redb);
        _sut = new MfaRecoveryProcessor(sp);
    }

    private static IServiceProvider BuildServiceProvider(MfaService mfaService, IRedbService redb)
    {
        var scopedSp = Substitute.For<IServiceProvider>();
        scopedSp.GetService(typeof(MfaService)).Returns(mfaService);
        scopedSp.GetService(typeof(IRedbService)).Returns(redb);

        var scope = Substitute.For<IServiceScope>();
        scope.ServiceProvider.Returns(scopedSp);

        var scopeFactory = Substitute.For<IServiceScopeFactory>();
        scopeFactory.CreateScope().Returns(scope);

        var sp = Substitute.For<IServiceProvider>();
        sp.GetService(typeof(IServiceScopeFactory)).Returns(scopeFactory);
        return sp;
    }

    private static string HashCode(string code)
    {
        var normalized = code.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexStringLower(bytes);
    }

    [Fact]
    public async Task Process_ValidRecoveryCode_ReturnsSuccessAndConsumesCode()
    {
        var plainCode = "ABCD-EF23";
        var hash = HashCode(plainCode);
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { hash, "other-hash" }
        }) { Id = 100 };
        obj.key = 42;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var state = new MfaState { UserId = 42, Username = "alice", Methods = ["totp"], ReturnUrl = "/cb" };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["recovery_code"] = plainCode
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(true);
        result["userId"].Should().Be(42L);
        result["username"].Should().Be("alice");
        result["returnUrl"].Should().Be("/cb");

        // Code should be consumed
        obj.Props.RecoveryCodes.Should().HaveCount(1);
        obj.Props.RecoveryCodes.Should().NotContain(hash);

        // Event
        exchange.Properties["identity-event-type"].Should().Be("UserLoggedIn");
    }

    [Fact]
    public async Task Process_InvalidRecoveryCode_ReturnsErrorWithState()
    {
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            RecoveryCodes = new List<string> { "some-hash" }
        }) { Id = 100 };
        obj.key = 42;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var state = new MfaState { UserId = 42, Username = "alice", Methods = ["totp"] };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["recovery_code"] = "WRONG-CODE"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_code");
        result["mfa_state"].Should().Be(mfaToken);
    }

    [Fact]
    public async Task Process_MissingMfaState_ReturnsInvalidRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["recovery_code"] = "ABCD-EF23"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Process_MissingRecoveryCode_ReturnsInvalidRequest()
    {
        var state = new MfaState { UserId = 42, Username = "alice" };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Process_ExpiredState_ReturnsInvalidGrant()
    {
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["recovery_code"] = "ABCD-EF23"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Process_TamperedState_ReturnsInvalidGrant()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = "garbage-token",
            ["recovery_code"] = "ABCD-EF23"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Process_NullBody_ReturnsInvalidRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = null;

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }
}
