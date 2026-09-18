using Bunit;
using FluentAssertions;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using redb.Identity.Client;
using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Contracts.Users;
using redb.Identity.Web.Components.Pages.Admin;
using redb.Identity.Web.Services;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Phase 3 component tests (bUnit): the route-level Phase3PagesTests prove the pages
/// exist and are authorized; these render the components in isolation over a substituted
/// <see cref="IIdentityClient"/> and pin the FORM LOGIC — the part no route test sees:
/// wizard step flow and error visibility, request mapping, client-side validation.
/// Every element is re-queried right before each interaction: bUnit's render tree is
/// replaced on every re-render, so cached FindAll results go stale.
/// </summary>
public sealed class Phase3ComponentTests : BunitContext
{
    private readonly IIdentityClient _client = Substitute.For<IIdentityClient>();

    public Phase3ComponentTests()
    {
        Services.AddSingleton(_client);
        Services.AddSingleton(new ToastService());
    }

    // ── P4 UserNew — regression of the review fix: a create error must be VISIBLE
    //    after the wizard bounces the operator back to step 1 ─────────────────────

    [Fact]
    public void UserNew_create_error_is_visible_after_bounce_to_step1()
    {
        _client.CreateUserAsync(Arg.Any<CreateUserRequest>())
            .ThrowsAsync(new InvalidOperationException("login already taken"));

        var cut = Render<UserNew>();

        SetInput(cut, 0, "alice");          // login
        SetInput(cut, 1, "Sup3r-secret!");  // password
        ClickButton(cut, "Next: profile");
        cut.Markup.Should().Contain("Profile", "step 2 must be reachable once step 1 is valid");

        ClickButton(cut, "Create user");

        // The failed create bounces to step 1 — and the error must still be on screen.
        cut.Markup.Should().Contain("login already taken",
            "the review fix moved the error banner outside the step switch");
        cut.Markup.Should().Contain("Account", "the wizard must be back on step 1");
    }

    [Fact]
    public void UserNew_maps_blank_optionals_to_null()
    {
        CreateUserRequest? sent = null;
        _client.CreateUserAsync(Arg.Do<CreateUserRequest>(r => sent = r))
            .Returns(new UserResponse { Id = 7, Login = "alice" });

        var cut = Render<UserNew>();
        SetInput(cut, 0, "alice");
        SetInput(cut, 1, "Sup3r-secret!");
        ClickButton(cut, "Next: profile");
        ClickButton(cut, "Create user");

        sent.Should().NotBeNull();
        sent!.Login.Should().Be("alice");
        sent.Email.Should().BeNull("blank optionals must not be sent as empty strings");
        sent.DisplayName.Should().BeNull();
        sent.PhoneNumber.Should().BeNull();
    }

    // ── P3 ClaimMapperNew — the owner string the modal never let you choose ──────

    [Fact]
    public void ClaimMapperNew_composes_owner_string_for_application()
    {
        CreateClaimMapperRequest? sent = null;
        _client.CreateClaimMapperAsync(Arg.Do<CreateClaimMapperRequest>(r => sent = r))
            .Returns(new ClaimMapperResponse { Id = "m1", Name = "n" });

        var cut = Render<ClaimMapperNew>();

        SetInput(cut, 0, "employee-id");   // Name
        SetInput(cut, 1, "emp_id");        // Claim type
        SetSelect(cut, 0, "application");  // owner kind
        SetNumber(cut, 0, "5");            // owner id
        SetSourceConstant(cut, "ACME");

        ClickButton(cut, "Create mapper");

        sent.Should().NotBeNull("the form was valid");
        sent!.Owner.Should().Be("application:5",
            "the page must compose the exact owner syntax the management API parses");
    }

    [Fact]
    public void ClaimMapperNew_global_owner_sends_null()
    {
        CreateClaimMapperRequest? sent = null;
        _client.CreateClaimMapperAsync(Arg.Do<CreateClaimMapperRequest>(r => sent = r))
            .Returns(new ClaimMapperResponse { Id = "m1", Name = "n" });

        var cut = Render<ClaimMapperNew>();
        SetInput(cut, 0, "employee-id");
        SetInput(cut, 1, "emp_id");
        SetSourceConstant(cut, "ACME");

        ClickButton(cut, "Create mapper");

        sent.Should().NotBeNull();
        sent!.Owner.Should().BeNull("global is the API default and must not be sent as a string");
    }

    // ── P1 FederationDetail — mappings validation and write-only secret ──────────

    [Fact]
    public void FederationDetail_duplicate_mapping_blocks_save()
    {
        _client.GetFederationProviderAsync("p1").Returns(Provider());

        var cut = Render<FederationDetail>(p => p.Add(x => x.Id, "p1"));

        ClickButton(cut, "Claim mappings");
        ClickButton(cut, "Add mapping");
        ClickButton(cut, "Add mapping");

        SetTableInput(cut, 0, "upn");
        SetTableInput(cut, 1, "email");
        SetTableInput(cut, 2, "upn");
        SetTableInput(cut, 3, "name");

        ClickButton(cut, "Save");

        cut.Markup.Should().Contain("Duplicate external claim");
        _client.DidNotReceive().UpdateFederationProviderAsync(
            Arg.Any<string>(), Arg.Any<UpdateFederationProviderRequest>());
    }

    [Fact]
    public void FederationDetail_blank_secret_is_not_sent()
    {
        UpdateFederationProviderRequest? sent = null;
        _client.GetFederationProviderAsync("p1").Returns(Provider());
        _client.UpdateFederationProviderAsync("p1", Arg.Do<UpdateFederationProviderRequest>(r => sent = r))
            .Returns(Provider());

        var cut = Render<FederationDetail>(p => p.Add(x => x.Id, "p1"));
        ClickButton(cut, "Save");

        sent.Should().NotBeNull();
        sent!.ClientSecret.Should().BeNull(
            "an untouched secret field must keep the stored secret, never overwrite it");
    }

    // ── P6 ApiResources — catalogue join with the live scope store ───────────────

    [Fact]
    public void ApiResources_marks_seeded_scopes_and_lists_custom_ones()
    {
        _client.ListScopesAsync(0, 500).Returns(new PagedResult<ScopeResponse>
        {
            Items =
            [
                new ScopeResponse { Id = "s1", Name = "identity:manage" },
                new ScopeResponse { Id = "s2", Name = "users:read" },
                new ScopeResponse { Id = "s3", Name = "photos" }, // operator scope, not in catalogue
            ],
            Total = 3,
        });

        var cut = Render<ApiResources>();

        cut.Markup.Should().Contain("seeded");
        cut.Markup.Should().Contain("photos", "operator scopes outside the model must be listed");
        cut.Markup.Should().Contain("insufficient_scope", "the gate's precedence rules are documented on the page");
    }

    // ── helpers: always re-query — bUnit's DOM snapshot goes stale on re-render ──

    private static FederationProviderResponse Provider() => new()
    {
        Id = "p1",
        ProviderId = "google",
        Kind = "oidc",
        DisplayName = "Google",
        Authority = "https://accounts.google.com",
        ClientId = "cid",
        HasSecret = true,
        Scopes = ["openid"],
        AutoProvision = true,
        Enabled = true,
        Priority = 100,
    };

    private static void SetInput<TComponent>(IRenderedComponent<TComponent> cut, int index, string value)
        where TComponent : IComponent
        => cut.FindAll("input")[index].Change(value);

    private static void SetNumber<TComponent>(IRenderedComponent<TComponent> cut, int index, string value)
        where TComponent : IComponent
        => cut.FindAll("input[type=number]")[index].Input(value); // owner-id field binds @oninput

    private static void SetSelect<TComponent>(IRenderedComponent<TComponent> cut, int index, string value)
        where TComponent : IComponent
        => cut.FindAll("select")[index].Change(value);

    private static void SetTableInput<TComponent>(IRenderedComponent<TComponent> cut, int index, string value)
        where TComponent : IComponent
        => cut.FindAll("table input")[index].Change(value);

    /// <summary>The Constant-value input lives inside the "Source" section (mono style).</summary>
    private static void SetSourceConstant<TComponent>(IRenderedComponent<TComponent> cut, string value)
        where TComponent : IComponent
    {
        var section = cut.FindAll("section")
            .First(s => s.TextContent.Contains("Source kind"));
        var input = section.QuerySelector("input.app-detail__input--mono");
        input.Should().NotBeNull("the Constant source kind renders its value input");
        input!.Change(value);
    }

    private static void ClickButton<TComponent>(IRenderedComponent<TComponent> cut, string textPart)
        where TComponent : IComponent
    {
        var button = cut.FindAll("button")
            .FirstOrDefault(b => b.TextContent.Contains(textPart, StringComparison.OrdinalIgnoreCase));
        button.Should().NotBeNull($"a button containing '{textPart}' must be rendered");
        button!.Click();
    }
}
