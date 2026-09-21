using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Management;
using redb.Identity.Management.Controllers;
using redb.Route.Abstractions;
using redb.Route.Components;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

/// <summary>
/// A feature that is switched off answers "no such endpoint", not a failure.
/// <para>
/// Self-service registration, e-mail verification, e-mail change and WebAuthn bind their
/// <c>direct-vm://</c> routes only when enabled, while the facades mount their controllers
/// regardless. A caller reaching a disabled feature therefore arrived at a producer with nothing
/// behind it, and the <c>InvalidOperationException</c> that followed reached the client as a
/// generic failure with an unhandled-exception stack trace in the log — observed on a running
/// worker as <c>POST /account/register</c> answering 400 with
/// <c>No consumer registered for direct-vm endpoint 'identity-account-register'</c>.
/// </para>
/// <para>
/// The contract these tests pin is the one the client SDK already reads: 404, which
/// <c>IdentityClient.RegisterAccountAsync</c> translates into <c>registration_disabled</c>.
/// </para>
/// </summary>
public class DisabledFeatureEndpointTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly SharedVmRegistry _registry = new();
    private readonly AccountRegistrationController _sut;

    public DisabledFeatureEndpointTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.AccountRegister).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);

        // What the real DirectVmProducer does when the route was never bound. Reaching it at all
        // is the defect, so the substitute fails the same way instead of quietly succeeding.
        _producer.Process(Arg.Any<IExchange>(), Arg.Any<CancellationToken>())
            .Returns(_ => throw new InvalidOperationException(
                "No consumer registered for direct-vm endpoint 'direct-vm://identity-account-register'."));

        var sp = new ServiceCollection().AddSingleton(_registry).BuildServiceProvider();
        _ctx.GetServiceProvider().Returns(sp);

        _sut = new AccountRegistrationController { Context = _ctx };
    }

    private static RegisterAccountRequest Request() => new()
    {
        Login = "newcomer",
        Email = "newcomer@example.test",
        Password = "Test@Password123",
    };

    [Fact]
    public async Task An_unbound_route_answers_not_found_instead_of_failing()
    {
        var result = await _sut.Register(Request());

        var error = result.Should().NotBeNull().And.Subject
            .GetType().GetProperty("error")!.GetValue(result) as string;
        error.Should().Be("not_found",
            "the deployment does not expose this operation, which is a 404 and not an error the "
            + "caller can do anything about");
        ManagementErrorCodes.ToStatusCode(error!).Should().Be(404,
            "this is the answer IdentityClient reads back as registration_disabled");
    }

    [Fact]
    public async Task An_unbound_route_is_not_even_sent_to()
    {
        await _sut.Register(Request());

        await _producer.DidNotReceive().Process(Arg.Any<IExchange>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task A_bound_route_is_forwarded_as_before()
    {
        // The guard must cost nothing when the feature is on: with a consumer in the registry the
        // call goes through to the producer exactly as it always did.
        IExchange? captured = null;
        _producer.Process(Arg.Do<IExchange>(e => captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        _registry.TryRegisterProcessor(IdentityEndpoints.AccountRegister, Substitute.For<IProcessor>())
            .Should().BeTrue();

        await _sut.Register(Request());

        captured.Should().NotBeNull();
        captured!.In.Headers["operation"].Should().Be("register");
    }
}
