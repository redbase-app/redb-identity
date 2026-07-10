using FluentAssertions;
using NSubstitute;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Management;

public class ApplicationManagementTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly IOpenIddictApplicationManager _appManager = Substitute.For<IOpenIddictApplicationManager>();
    private readonly ApplicationManagementProcessor _processor;

    public ApplicationManagementTests()
    {
        var context = MockRouteContext.CreateWithServices(_redb,
            (typeof(IOpenIddictApplicationManager), _appManager));
        _processor = new ApplicationManagementProcessor(context);
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
    public async Task Create_ValidInput_ReturnsApplicationResponse()
    {
        // 1st FindByClientIdAsync (duplicate check) -> null;
        // 2nd FindByClientIdAsync (read-back after CreateAsync) -> created entity.
        var created = MockRedbQuery.CreateObject<ApplicationProps>(42, "My App",
            new ApplicationProps
            {
                ClientId = "my-app",
                ClientType = "confidential"
            });
        _appManager.FindByClientIdAsync("my-app", Arg.Any<CancellationToken>())
            .Returns(default(object), created);
        _appManager.CreateAsync(Arg.Any<OpenIddictApplicationDescriptor>(), Arg.Any<CancellationToken>())
            .Returns(created);

        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "my-app",
            ClientSecret = "secret",
            DisplayName = "My App",
            ClientType = "confidential"
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.ClientId.Should().Be("my-app");
        resp.DisplayName.Should().Be("My App");
        resp.ClientType.Should().Be("confidential");
        exchange.Properties["identity-event-type"].Should().Be("ClientRegistered");

        // Verify CreateAsync was called with the descriptor that carries the *plain* secret —
        // OpenIddict hashes it internally via its own (BCrypt) mechanism.
        await _appManager.Received(1).CreateAsync(
            Arg.Is<OpenIddictApplicationDescriptor>(d =>
                d.ClientId == "my-app" && d.ClientSecret == "secret"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Create_MissingClientId_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest { ClientId = "" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_InvalidClientType_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            ClientType = "invalid_type"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_InvalidRedirectUri_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            RedirectUris = new[] { "not-a-uri" }
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_DuplicateClientId_ReturnsDuplicateError()
    {
        var existing = MockRedbQuery.CreateObject<ApplicationProps>(1, "existing",
            new ApplicationProps { ClientId = "dup-app" });
        _appManager.FindByClientIdAsync("dup-app", Arg.Any<CancellationToken>())
            .Returns(existing);

        var exchange = CreateExchange("create", new CreateApplicationRequest { ClientId = "dup-app" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("duplicate");

        await _appManager.DidNotReceive().CreateAsync(
            Arg.Any<OpenIddictApplicationDescriptor>(),
            Arg.Any<CancellationToken>());
    }

    // ── Read ──

    [Fact]
    public async Task Read_ById_ReturnsApplication()
    {
        var app = MockRedbQuery.CreateObject<ApplicationProps>(10, "Test App",
            new ApplicationProps { ClientId = "test-read" });
        _redb.LoadAsync<ApplicationProps>(10).Returns(app);

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 10L });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.ClientId.Should().Be("test-read");
        resp.Id.Should().Be("10");
    }

    [Fact]
    public async Task Read_ByClientId_ReturnsApplication()
    {
        var app = MockRedbQuery.CreateObject<ApplicationProps>(10, "Test App",
            new ApplicationProps { ClientId = "by-cid" });
        MockRedbQuery.Setup(_redb, new List<RedbObject<ApplicationProps>> { app });

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["clientId"] = "by-cid" });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.ClientId.Should().Be("by-cid");
    }

    [Fact]
    public async Task Read_NotFound_ReturnsNotFoundError()
    {
        _redb.LoadAsync<ApplicationProps>(999).Returns((RedbObject<ApplicationProps>?)null);

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 999L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Update ──

    [Fact]
    public async Task Update_ValidInput_ReturnsUpdatedApplication()
    {
        var app = MockRedbQuery.CreateObject<ApplicationProps>(5, "Old Name",
            new ApplicationProps { ClientId = "upd-app", ClientType = "confidential" });
        _redb.LoadAsync<ApplicationProps>(5).Returns(app);
        _redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>()).Returns(5L);

        var exchange = CreateExchange("update", new UpdateApplicationRequest
        {
            Id = "5",
            DisplayName = "New Name",
            ClientType = "public"
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.DisplayName.Should().Be("New Name");
        resp.ClientType.Should().Be("public");
        exchange.Properties["identity-event-type"].Should().Be("ClientUpdated");
    }

    [Fact]
    public async Task Update_NotFound_ReturnsNotFoundError()
    {
        _redb.LoadAsync<ApplicationProps>(999).Returns((RedbObject<ApplicationProps>?)null);

        var exchange = CreateExchange("update", new UpdateApplicationRequest { Id = "999" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Delete ──

    [Fact]
    public async Task Delete_ValidId_ReturnsSuccess()
    {
        _redb.DeleteAsync(7).Returns(true);

        var exchange = CreateExchange("delete", new Dictionary<string, object?> { ["id"] = 7L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        exchange.Properties["identity-event-type"].Should().Be("ClientDeleted");
    }

    [Fact]
    public async Task Delete_MissingId_ReturnsValidationError()
    {
        var exchange = CreateExchange("delete", new Dictionary<string, object?> { ["id"] = 0L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    // ── List ──

    [Fact]
    public async Task List_ReturnsPaginatedResults()
    {
        var items = Enumerable.Range(1, 5)
            .Select(i => MockRedbQuery.CreateObject<ApplicationProps>(i, $"App{i}",
                new ApplicationProps { ClientId = $"app-{i}" }))
            .ToList();
        MockRedbQuery.Setup(_redb, items);

        var exchange = CreateExchange("list", new ListRequest { Offset = 0, Count = 3 });

        await _processor.Process(exchange);

        var result = exchange.Out!.Body.Should().BeOfType<PagedResult<ApplicationResponse>>().Subject;
        result.Total.Should().Be(5);
        result.Items.Should().HaveCount(3);
    }

    // ── Unknown operation ──

    [Fact]
    public async Task UnknownOperation_ReturnsInvalidOperation()
    {
        var exchange = CreateExchange("kaboom");

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("invalid_operation");
    }

    // ── Missing operation header ──

    [Fact]
    public async Task MissingOperationHeader_Throws()
    {
        var exchange = new TestExchange();

        await Assert.ThrowsAsync<InvalidOperationException>(() => _processor.Process(exchange));
    }

    // ── Input Validation ──

    [Fact]
    public async Task Create_InvalidConsentType_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            ConsentType = "bogus"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("ConsentType");
    }

    [Fact]
    public async Task Create_InvalidApplicationType_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            ApplicationType = "bogus"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("ApplicationType");
    }

    [Fact]
    public async Task Create_InvalidPostLogoutRedirectUri_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            PostLogoutRedirectUris = new[] { "not-a-uri" }
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("post-logout redirect URI");
    }

    [Fact]
    public async Task Create_DisplayNameTooLong_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app1",
            DisplayName = new string('a', 257)
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("DisplayName");
    }

    [Fact]
    public async Task Create_ClientIdWithInvalidChars_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateApplicationRequest
        {
            ClientId = "app with spaces!"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("invalid characters");
    }
}
