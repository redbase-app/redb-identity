using FluentAssertions;
using NSubstitute;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Application management through the full route pipeline.
/// Validates: route wiring → processor → WireTap → event dispatch.
/// </summary>
[Collection("IdentityRoute")]
public class AppManagementPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public AppManagementPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task CreateApp_ThroughPipeline_ReturnsApplicationResponse()
    {
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<ApplicationProps>>());
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>())
            .Returns(ci => { ci.Arg<RedbObject<ApplicationProps>>().Id = 100; return 100L; });

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest
            {
                ClientId = "pipeline-app",
                ClientSecret = "secret",
                ClientType = "confidential",
                DisplayName = "Pipeline App"
            },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        var resp = exchange.In.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.ClientId.Should().Be("pipeline-app");
        resp.DisplayName.Should().Be("Pipeline App");
    }

    [Fact]
    public async Task CreateApp_MissingClientId_ReturnsError()
    {
        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest { ClientId = "" },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task ReadApp_ById_ReturnsApplication()
    {
        var app = MockRedbQuery.CreateObject<ApplicationProps>(42, "Test",
            new ApplicationProps { ClientId = "read-pipeline" });
        _fixture.Redb.LoadAsync<ApplicationProps>(42).Returns(app);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new Dictionary<string, object?> { ["id"] = 42L },
            new Dictionary<string, object?> { ["operation"] = "read" });

        exchange.Exception.Should().BeNull();
        var resp = exchange.In.Body.Should().BeOfType<ApplicationResponse>().Subject;
        resp.ClientId.Should().Be("read-pipeline");
    }

    [Fact]
    public async Task ListApps_ThroughPipeline_ReturnsPaginated()
    {
        var items = Enumerable.Range(1, 3)
            .Select(i => MockRedbQuery.CreateObject<ApplicationProps>(i, $"App{i}",
                new ApplicationProps { ClientId = $"list-{i}" }))
            .ToList();
        MockRedbQuery.Setup(_fixture.Redb, items);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new ListRequest { Offset = 0, Count = 10 },
            new Dictionary<string, object?> { ["operation"] = "list" });

        exchange.Exception.Should().BeNull();
        var result = exchange.In.Body.Should().BeOfType<PagedResult<ApplicationResponse>>().Subject;
        result.Total.Should().Be(3);
        result.Items.Should().HaveCount(3);
    }

    [Fact]
    public async Task DeleteApp_ThroughPipeline_ReturnsSuccess()
    {
        _fixture.Redb.DeleteAsync(55).Returns(true);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new Dictionary<string, object?> { ["id"] = 55L },
            new Dictionary<string, object?> { ["operation"] = "delete" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((bool)body.success).Should().BeTrue();
    }

    [Fact]
    public async Task UnknownOperation_ThroughPipeline_ReturnsError()
    {
        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            null,
            new Dictionary<string, object?> { ["operation"] = "nuke" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((string)body.error).Should().Be("invalid_operation");
    }
}
