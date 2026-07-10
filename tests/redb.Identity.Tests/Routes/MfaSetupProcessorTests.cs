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
/// Unit tests for <see cref="MfaSetupProcessor"/>:
/// All 5 MFA management operations (status, setup, confirm, disable, regenerate-recovery).
/// </summary>
public sealed class MfaSetupProcessorTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaSecretProtector _secretProtector;
    private readonly MfaService _mfaService;
    private readonly MfaSetupProcessor _sut;

    public MfaSetupProcessorTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-processor-tests");
        _secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var totpMethod = new TotpMfaMethod(_secretProtector);
        _mfaService = new MfaService(
            _redb,
            new IMfaMethod[] { totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        // Build a minimal IServiceProvider that returns MfaService from scopes
        var sp = BuildServiceProvider(_mfaService);
        _sut = new MfaSetupProcessor(sp);
    }

    private static IServiceProvider BuildServiceProvider(MfaService mfaService)
    {
        var scopedSp = Substitute.For<IServiceProvider>();
        scopedSp.GetService(typeof(MfaService)).Returns(mfaService);

        var scope = Substitute.For<IServiceScope>();
        scope.ServiceProvider.Returns(scopedSp);

        var scopeFactory = Substitute.For<IServiceScopeFactory>();
        scopeFactory.CreateScope().Returns(scope);

        var sp = Substitute.For<IServiceProvider>();
        sp.GetService(typeof(IServiceScopeFactory)).Returns(scopeFactory);
        return sp;
    }

    private TestExchange CreateExchange(string operation, IDictionary<string, object?>? body = null)
    {
        var exchange = new TestExchange { Pattern = redb.Route.Abstractions.ExchangePattern.InOut };
        exchange.In.Headers["operation"] = operation;
        exchange.In.Body = body;
        return exchange;
    }

    // ── Status ──

    [Fact]
    public async Task Status_MissingUserId_ReturnsError()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var exchange = CreateExchange("status", new Dictionary<string, object?> { });

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Status_ValidUserId_ReturnsStatus()
    {
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { "a", "b" }
        }) { Id = 100 };
        obj.key = 42;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var exchange = CreateExchange("status", new Dictionary<string, object?>
        {
            ["userId"] = 42L
        });

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["enabled"].Should().Be(true);
        ((string[])result["methods"]!).Should().Contain("totp");
        result["recovery_codes_remaining"].Should().Be(2);
    }

    // ── Setup ──

    [Fact]
    public async Task Setup_ValidRequest_ReturnsSecretAndQrUri()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var exchange = CreateExchange("setup", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["username"] = "bob"
        });

        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["method"].Should().Be("totp");
        result["secret_base32"].Should().NotBeNull();
        result["qr_uri"]!.ToString().Should().Contain("bob");
    }

    [Fact]
    public async Task Setup_MissingUserId_ReturnsError()
    {
        var exchange = CreateExchange("setup", new Dictionary<string, object?> { ["username"] = "bob" });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    // ── Confirm ──

    [Fact]
    public async Task Confirm_ValidCode_ReturnsConfirmedWithRecoveryCodes()
    {
        // First setup — issues setup_token, no DB write.
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var setupExchange = CreateExchange("setup", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["username"] = "alice"
        });
        await _sut.Process(setupExchange);

        var setupResult = (IDictionary<string, object?>)setupExchange.Out!.Body!;
        var secret = setupResult["secret_base32"]!.ToString()!;
        var setupToken = setupResult["setup_token"]!.ToString()!;
        setupToken.Should().NotBeNullOrEmpty();

        // Confirm path will create the props row on demand.
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var code = GenerateValidCode(secret);
        var confirmExchange = CreateExchange("confirm", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["code"] = code,
            ["setup_token"] = setupToken
        });
        await _sut.Process(confirmExchange);

        var result = confirmExchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["confirmed"].Should().Be(true);
        ((string[])result["recovery_codes"]!).Should().HaveCount(10);
    }

    [Fact]
    public async Task Confirm_InvalidCode_ReturnsError()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var setupExchange = CreateExchange("setup", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["username"] = "alice"
        });
        await _sut.Process(setupExchange);
        var setupToken = ((IDictionary<string, object?>)setupExchange.Out!.Body!)["setup_token"]!.ToString()!;

        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var exchange = CreateExchange("confirm", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["code"] = "000000",
            ["setup_token"] = setupToken
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_code");
    }

    [Fact]
    public async Task Confirm_MissingSetupToken_ReturnsError()
    {
        var exchange = CreateExchange("confirm", new Dictionary<string, object?>
        {
            ["userId"] = 10L,
            ["code"] = "123456"
            // setup_token deliberately missing
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Confirm_MissingCode_ReturnsError()
    {
        var exchange = CreateExchange("confirm", new Dictionary<string, object?>
        {
            ["userId"] = 10L
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_request");
    }

    // ── Disable ──

    [Fact]
    public async Task Disable_ValidRequest_ReturnsDisabled()
    {
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = "enc"
        }) { Id = 100 };
        obj.key = 10;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var exchange = CreateExchange("disable", new Dictionary<string, object?>
        {
            ["userId"] = 10L
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["disabled"].Should().Be(true);
    }

    // ── Regenerate Recovery ──

    [Fact]
    public async Task RegenerateRecovery_MfaEnabled_ReturnsCodes()
    {
        var obj = new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { "old" }
        }) { Id = 100 };
        obj.key = 10;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var exchange = CreateExchange("regenerate-recovery", new Dictionary<string, object?>
        {
            ["userId"] = 10L
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        ((string[])result["recovery_codes"]!).Should().HaveCount(10);
    }

    [Fact]
    public async Task RegenerateRecovery_MfaNotEnabled_ReturnsError()
    {
        var obj = new RedbObject<MfaProps>(new MfaProps { Enabled = false }) { Id = 100 };
        obj.key = 10;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });

        var exchange = CreateExchange("regenerate-recovery", new Dictionary<string, object?>
        {
            ["userId"] = 10L
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("mfa_not_enabled");
    }

    // ── Invalid operation ──

    [Fact]
    public async Task UnknownOperation_ReturnsError()
    {
        var exchange = CreateExchange("nonexistent");
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result["error"].Should().Be("invalid_operation");
    }

    [Fact]
    public async Task MissingOperationHeader_Throws()
    {
        var exchange = new TestExchange();
        // no operation header
        var act = () => _sut.Process(exchange);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    // ── GetUserId type handling ──

    [Theory]
    [InlineData(42L)]      // long
    [InlineData(42)]       // int
    public async Task GetUserId_HandlesNumericTypes(object userId)
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var exchange = CreateExchange("status", new Dictionary<string, object?>
        {
            ["userId"] = userId
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        // Should not be "invalid_request" — meaning userId was parsed
        result.Should().NotContainKey("error");
    }

    [Fact]
    public async Task GetUserId_HandlesStringType()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var exchange = CreateExchange("status", new Dictionary<string, object?>
        {
            ["userId"] = "42"
        });
        await _sut.Process(exchange);

        var result = exchange.Out!.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        result.Should().NotContainKey("error");
    }

    private static string GenerateValidCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }
}
