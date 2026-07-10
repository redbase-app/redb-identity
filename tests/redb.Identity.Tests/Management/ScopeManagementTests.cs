using FluentAssertions;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Management;

public class ScopeManagementTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly ScopeManagementProcessor _processor;

    public ScopeManagementTests()
    {
        var context = MockRouteContext.Create(_redb);
        _processor = new ScopeManagementProcessor(context);
    }

    private static TestExchange CreateExchange(string operation, object? body = null)
    {
        var exchange = new TestExchange();
        exchange.In.Headers["operation"] = operation;
        if (body != null) exchange.In.Body = body;
        return exchange;
    }

    // ── Create ──

    [Fact]
    public async Task Create_ValidInput_ReturnsScopeResponse()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<ScopeProps>>());
        _redb.SaveAsync(Arg.Any<RedbObject<ScopeProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ScopeProps>>().Id = 1; return 1L; });

        var exchange = CreateExchange("create", new CreateScopeRequest
        {
            Name = "api",
            DisplayName = "API Access",
            Description = "Access to API resources",
            Resources = new[] { "resource-server-1" }
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ScopeResponse>().Subject;
        resp.Name.Should().Be("api");
        resp.DisplayName.Should().Be("API Access");
        resp.Description.Should().Be("Access to API resources");
        exchange.Properties["identity-event-type"].Should().Be("ScopeCreated");
    }

    [Fact]
    public async Task Create_MissingName_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateScopeRequest { Name = "" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_DuplicateName_ReturnsDuplicateError()
    {
        var existing = MockRedbQuery.CreateObject<ScopeProps>(1, "api",
            new ScopeProps { ScopeName = "api" });
        MockRedbQuery.Setup(_redb, new List<RedbObject<ScopeProps>> { existing });

        var exchange = CreateExchange("create", new CreateScopeRequest { Name = "api" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("duplicate");
    }

    // ── Read ──

    [Fact]
    public async Task Read_ById_ReturnsScope()
    {
        var scope = MockRedbQuery.CreateObject<ScopeProps>(10, "Profile",
            new ScopeProps { ScopeName = "profile", Description = "Profile data" });
        _redb.LoadAsync<ScopeProps>(10).Returns(scope);

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 10L });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ScopeResponse>().Subject;
        resp.Name.Should().Be("profile");
        resp.Id.Should().Be("10");
    }

    [Fact]
    public async Task Read_ByName_ReturnsScope()
    {
        var scope = MockRedbQuery.CreateObject<ScopeProps>(10, "Profile",
            new ScopeProps { ScopeName = "profile" });
        MockRedbQuery.Setup(_redb, new List<RedbObject<ScopeProps>> { scope });

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["name"] = "profile" });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ScopeResponse>().Subject;
        resp.Name.Should().Be("profile");
    }

    [Fact]
    public async Task Read_NotFound_ReturnsNotFoundError()
    {
        _redb.LoadAsync<ScopeProps>(999).Returns((RedbObject<ScopeProps>?)null);

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 999L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Update ──

    [Fact]
    public async Task Update_ValidInput_ReturnsUpdatedScope()
    {
        var scope = MockRedbQuery.CreateObject<ScopeProps>(5, "Old",
            new ScopeProps { ScopeName = "api", Description = "old" });
        _redb.LoadAsync<ScopeProps>(5).Returns(scope);
        _redb.SaveAsync(Arg.Any<RedbObject<ScopeProps>>()).Returns(5L);

        var exchange = CreateExchange("update", new UpdateScopeRequest
        {
            Id = "5",
            DisplayName = "New Display",
            Description = "new desc",
            Resources = new[] { "rs1" }
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ScopeResponse>().Subject;
        resp.DisplayName.Should().Be("New Display");
        resp.Description.Should().Be("new desc");
        exchange.Properties["identity-event-type"].Should().Be("ScopeUpdated");
    }

    // ── Delete ──

    [Fact]
    public async Task Delete_ValidId_ReturnsSuccess()
    {
        _redb.DeleteAsync(3).Returns(true);

        var exchange = CreateExchange("delete", new Dictionary<string, object?> { ["id"] = 3L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        exchange.Properties["identity-event-type"].Should().Be("ScopeDeleted");
    }

    // ── List ──

    [Fact]
    public async Task List_ReturnsPaginatedResults()
    {
        var items = new List<RedbObject<ScopeProps>>
        {
            MockRedbQuery.CreateObject<ScopeProps>(1, "openid", new ScopeProps { ScopeName = "openid" }),
            MockRedbQuery.CreateObject<ScopeProps>(2, "profile", new ScopeProps { ScopeName = "profile" }),
            MockRedbQuery.CreateObject<ScopeProps>(3, "api", new ScopeProps { ScopeName = "api" })
        };
        MockRedbQuery.Setup(_redb, items);

        var exchange = CreateExchange("list", new ListRequest { Offset = 1, Count = 2 });

        await _processor.Process(exchange);

        var result = exchange.Out!.Body.Should().BeOfType<PagedResult<ScopeResponse>>().Subject;
        result.Total.Should().Be(3);
        result.Items.Should().HaveCount(2);
    }

    // ── Input Validation ──

    [Fact]
    public async Task Create_InvalidNameChars_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateScopeRequest
        {
            Name = "scope with spaces!"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("invalid characters");
    }

    [Fact]
    public async Task Create_DisplayNameTooLong_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateScopeRequest
        {
            Name = "api",
            DisplayName = new string('a', 257)
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("DisplayName");
    }

    [Fact]
    public async Task Create_DescriptionTooLong_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateScopeRequest
        {
            Name = "api",
            Description = new string('a', 1025)
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("Description");
    }
}
