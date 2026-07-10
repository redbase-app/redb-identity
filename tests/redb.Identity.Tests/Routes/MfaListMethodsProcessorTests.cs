using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// B9 / BUG-9 — verifies the Auth0-style gated method enumeration:
/// <see cref="MfaListMethodsProcessor"/> returns the methods only when given a
/// valid encrypted state, never to anonymous callers.
/// </summary>
public sealed class MfaListMethodsProcessorTests
{
    private readonly MfaService _mfaService;
    private readonly MfaStateProtector _stateProtector;
    private readonly MfaListMethodsProcessor _sut;

    public MfaListMethodsProcessorTests()
    {
        var redb = Substitute.For<IRedbService>();
        var dpProvider = DataProtectionProvider.Create("redb-mfa-listmethods-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        _stateProtector = new MfaStateProtector(dpProvider);
        _mfaService = new MfaService(
            redb,
            new IMfaMethod[] { new TotpMfaMethod(secretProtector) },
            Array.Empty<IMfaDeliveryChannel>(),
            _stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Options.Create(new RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        _sut = new MfaListMethodsProcessor(BuildServiceProvider(_mfaService));
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

    private TestExchange CreateExchange(IDictionary<string, object?>? body = null)
    {
        return new TestExchange
        {
            Pattern = redb.Route.Abstractions.ExchangePattern.InOut,
            In = { Body = body }
        };
    }

    [Fact]
    public async Task MissingState_ReturnsInvalidRequest()
    {
        var exchange = CreateExchange(new Dictionary<string, object?>());

        await _sut.Process(exchange);

        var result = (IDictionary<string, object?>)exchange.Out!.Body!;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task InvalidState_ReturnsInvalidGrant_NoLeakage()
    {
        var exchange = CreateExchange(new Dictionary<string, object?> { ["mfa_state"] = "garbage-token" });

        await _sut.Process(exchange);

        var result = (IDictionary<string, object?>)exchange.Out!.Body!;
        result["success"].Should().Be(false);
        result["error"].Should().Be("invalid_grant");
        result.Should().NotContainKey("methods");
    }

    [Fact]
    public async Task ValidState_ReturnsMethods()
    {
        var protectedState = _stateProtector.Protect(new MfaState
        {
            Jti = Guid.NewGuid(),
            UserId = 42,
            Username = "alice",
            Methods = new[] { "totp", "sms" }
        });
        var exchange = CreateExchange(new Dictionary<string, object?> { ["mfa_state"] = protectedState });

        await _sut.Process(exchange);

        var result = (IDictionary<string, object?>)exchange.Out!.Body!;
        result["success"].Should().Be(true);
        result["methods"].Should().BeEquivalentTo(new[] { "totp", "sms" });
    }
}
