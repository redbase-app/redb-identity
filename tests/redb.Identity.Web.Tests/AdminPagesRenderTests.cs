using Bunit;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using redb.Identity.Client;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;
using redb.Identity.Web.Components.Pages.Admin;
using redb.Identity.Web.Services;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Admin pages must actually render, not merely exist as routes.
/// <para>
/// A user reported Administration → Federation dying with "does not have a property matching the name
/// 'Icon'": the page passed an <c>Icon</c> attribute to <c>UiEmptyState</c>, which has no such
/// parameter — a Blazor runtime error the compiler cannot see. The route tests next door only assert
/// that a route exists and refuses anonymous callers, so the page was "covered" while being broken on
/// every visit where the list came back empty. These tests render the page with a substituted client
/// and look at the markup.
/// </para>
/// </summary>
public sealed class AdminPagesRenderTests : BunitContext
{
    private readonly IIdentityClient _client = Substitute.For<IIdentityClient>();

    public AdminPagesRenderTests()
    {
        Services.AddSingleton(_client);
        Services.AddSingleton(new ToastService());
    }

    [Fact]
    public void FederationList_renders_its_empty_state()
    {
        _client.ListFederationProvidersAsync(Arg.Any<int>(), Arg.Any<int>())
            .Returns(new PagedResult<FederationProviderResponse>
            {
                Items = new List<FederationProviderResponse>(),
                Total = 0,
            });

        var cut = Render<FederationList>();

        cut.Markup.Should().Contain("No federation providers",
            "the empty state is the whole page when nothing is registered yet");
    }

    [Fact]
    public void FederationList_renders_a_provider_row()
    {
        _client.ListFederationProvidersAsync(Arg.Any<int>(), Arg.Any<int>())
            .Returns(new PagedResult<FederationProviderResponse>
            {
                Items = new List<FederationProviderResponse>
                {
                    new()
                    {
                        Id = "p1",
                        ProviderId = "google",
                        Kind = "oidc",
                        DisplayName = "Google",
                        Authority = "https://accounts.google.com",
                        ClientId = "cid",
                        Scopes = ["openid"],
                        Enabled = true,
                        Priority = 100,
                    },
                },
                Total = 1,
            });

        var cut = Render<FederationList>();

        cut.Markup.Should().Contain("google");
        cut.Markup.Should().NotContain("No federation providers");
    }
}
