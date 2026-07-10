using System.Data.Common;
using FluentAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Identity.Contracts;
using redb.Identity.Contracts.Applications;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Tests that builder-level error handling (OnException, DoTry/DoCatch) works end-to-end.
/// These are the bugs that ONLY integration tests catch — unit tests bypass error handling.
/// </summary>
[Collection("IdentityRoute")]
public class ErrorHandlingPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public ErrorHandlingPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task DbException_ReturnsDatabaseUnavailable_NotStackTrace()
    {
        // Simulate DB failure during app creation
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<ApplicationProps>>());
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>())
            .ThrowsAsync(CreateDbException("connection refused"));

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest
            {
                ClientId = "db-fail-app",
                ClientSecret = "secret",
                ClientType = "confidential"
            },
            new Dictionary<string, object?> { ["operation"] = "create" });

        // Reset mock to avoid contaminating other tests
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ApplicationProps>>().Id = 1; return 1L; });

        // Builder-level OnException<DbException> should catch this
        exchange.ExceptionHandled.Should().BeTrue();
        var body = exchange.In.Body;
        body.Should().NotBeNull();

        if (body is Dictionary<string, object> dict)
        {
            dict["error"].Should().Be("server_error");
            dict["error_description"]!.ToString().Should().Contain("Database temporarily unavailable");
            // No stack trace leaked
            dict["error_description"]!.ToString().Should().NotContain("connection refused");
        }
    }

    [Fact]
    public async Task UnexpectedException_ReturnsGenericError_NotInternals()
    {
        // Simulate unexpected exception
        _fixture.Redb.LoadAsync<ApplicationProps>(Arg.Any<long>())
            .ThrowsAsync(new InvalidOperationException("Internal details should not leak"));

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new Dictionary<string, object?> { ["id"] = 999L },
            new Dictionary<string, object?> { ["operation"] = "read" });

        // Reset mock to avoid contaminating other tests
        _fixture.Redb.LoadAsync<ApplicationProps>(Arg.Any<long>()).Returns((RedbObject<ApplicationProps>?)null);

        // Builder-level OnException<Exception> catch-all
        exchange.ExceptionHandled.Should().BeTrue();
        var body = exchange.Out!.Body;
        body.Should().NotBeNull();

        if (body is Dictionary<string, object> dict)
        {
            dict["error"].Should().Be("server_error");
            dict["error_description"]!.ToString().Should().Contain("unexpected error");
            // No internal details leaked
            dict["error_description"]!.ToString().Should().NotContain("Internal details");
        }
    }

    [Fact]
    public async Task MissingOperationHeader_CaughtByErrorHandler()
    {
        // Missing "operation" header → processor throws InvalidOperationException
        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest { ClientId = "test" },
            new Dictionary<string, object?>());

        // Should be handled, not thrown out
        exchange.ExceptionHandled.Should().BeTrue();
        var body = exchange.In.Body;
        body.Should().NotBeNull();
    }

    [Fact]
    public async Task ManageScopes_DbException_ReturnsDatabaseError()
    {
        // DB failure on scope save (avoids ThrowsForAnyArgs on Query which can't be reset)
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<ScopeProps>>());
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ScopeProps>>())
            .ThrowsAsync(CreateDbException("timeout"));

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageScopes,
            new Contracts.Scopes.CreateScopeRequest { Name = "fail-scope", DisplayName = "Fail" },
            new Dictionary<string, object?> { ["operation"] = "create" });

        // Reset mock to avoid contaminating other tests
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ScopeProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ScopeProps>>().Id = 1; return 1L; });

        exchange.ExceptionHandled.Should().BeTrue();
        if (exchange.In.Body is Dictionary<string, object> dict)
        {
            dict["error"].Should().Be("server_error");
        }
    }

    [Fact]
    public async Task ManageUsers_UnexpectedError_HandledGracefully()
    {
        _fixture.Redb.UserProvider.GetUserByIdAsync(Arg.Any<long>())
            .ThrowsAsync(new NullReferenceException("oops"));

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new Dictionary<string, object?> { ["id"] = 1L },
            new Dictionary<string, object?> { ["operation"] = "read" });

        // Reset mock to avoid contaminating other tests
        _fixture.Redb.UserProvider.GetUserByIdAsync(Arg.Any<long>()).Returns((IRedbUser?)null);

        exchange.ExceptionHandled.Should().BeTrue();
        if (exchange.Out!.Body is Dictionary<string, object> dict)
        {
            dict["error"].Should().Be("server_error");
            dict["error_description"]!.ToString().Should().NotContain("oops");
        }
    }

    /// <summary>
    /// Creates a minimal DbException subclass for testing.
    /// DbException is abstract, so we need a concrete implementation.
    /// </summary>
    private static DbException CreateDbException(string message)
    {
        return new TestDbException(message);
    }

    private sealed class TestDbException : DbException
    {
        public TestDbException(string message) : base(message) { }
    }
}
