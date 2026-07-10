using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// Unit tests for <see cref="MfaVerifyProcessor"/>:
/// TOTP verification during login — state decryption, code validation, session creation.
/// </summary>
public sealed class MfaVerifyProcessorTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaSecretProtector _secretProtector;
    private readonly MfaStateProtector _stateProtector;
    private readonly MfaService _mfaService;
    private readonly MfaVerifyProcessor _sut;

    public MfaVerifyProcessorTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-verify-tests");
        _secretProtector = new MfaSecretProtector(dpProvider);
        _stateProtector = new MfaStateProtector(dpProvider);
        var totpMethod = new TotpMfaMethod(_secretProtector);
        _mfaService = new MfaService(
            _redb,
            new IMfaMethod[] { totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            _stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        var sp = BuildServiceProvider(_mfaService, _redb);
        _sut = new MfaVerifyProcessor(sp);
    }

    private static IServiceProvider BuildServiceProvider(MfaService mfaService, IRedbService redb)
    {
        // Stub redb.Context.BeginTransactionAsync — returns a no-op transaction
        var tx = Substitute.For<redb.Core.Data.IRedbTransaction>();
        var ctx = Substitute.For<redb.Core.Data.IRedbContext>();
        ctx.BeginTransactionAsync().Returns(Task.FromResult(tx));
        redb.Context.Returns(ctx);

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

    [Fact]
    public async Task Process_ValidStateAndCode_ReturnsSuccess()
    {
        var base32 = "JBSWY3DPEHPK3PXP";
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32)
        }) { Id = 100 };
        obj.key = 42;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var state = new MfaState { UserId = 42, Username = "alice", Methods = ["totp"], ReturnUrl = "/cb" };
        var mfaToken = _stateProtector.Protect(state);
        var code = GenerateValidCode(base32);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["code"] = code
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(true);
        result["userId"].Should().Be(42L);
        result["username"].Should().Be("alice");
        result["returnUrl"].Should().Be("/cb");

        // Event should be set
        exchange.Properties["identity-event-type"].Should().Be("UserLoggedIn");
    }

    [Fact]
    public async Task Process_MissingMfaState_ReturnsInvalidRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["code"] = "123456"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Process_MissingCode_ReturnsInvalidRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = "some-token"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Process_ExpiredState_ReturnsInvalidGrant()
    {
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            Methods = ["totp"],
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["code"] = "123456"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Process_TamperedState_ReturnsInvalidGrant()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = "tampered-garbage-data",
            ["code"] = "123456"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Process_InvalidCode_ReturnsInvalidCodeWithState()
    {
        var base32 = "JBSWY3DPEHPK3PXP";
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32)
        }) { Id = 100 };
        obj.key = 42;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var state = new MfaState { UserId = 42, Username = "alice", Methods = ["totp"] };
        var mfaToken = _stateProtector.Protect(state);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["mfa_state"] = mfaToken,
            ["code"] = "000000"
        };

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_code");
        result["mfa_state"].Should().Be(mfaToken, "state should be returned for retry");
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

    private static string GenerateValidCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }
}
