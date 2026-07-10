using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Endpoints;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Bootstrap;

/// <summary>
/// B1 — acceptance tests for the emergency-admin bootstrap endpoint
/// (<c>POST /internal/bootstrap-admin</c>). Each test cleans the
/// <c>bootstrap_completed</c> sentinel + the <c>identity-web</c> client and the
/// <c>identity-bootstrap-admins</c> group from the shared production fixture
/// so cases see pristine state regardless of execution order.
/// </summary>
[Collection("ProductionHttp")]
public class BootstrapAdminEndpointTests : IAsyncLifetime
{
    private const string FlagName = "bootstrap_completed";
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;
    private static int _emailSeed;

    public BootstrapAdminEndpointTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    public Task InitializeAsync() => CleanupBootstrapStateAsync();

    public Task DisposeAsync() => CleanupBootstrapStateAsync();

    private async Task CleanupBootstrapStateAsync()
    {
        // 1. Clear the sentinel so IsBootstrapCompletedAsync returns false again.
        await _fx.UseRedbAsync(async redb =>
        {
            var flag = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.Name == FlagName)
                .FirstOrDefaultAsync();
            if (flag is not null)
                await redb.DeleteAsync(flag.Id);

            var grp = await redb.Query<GroupProps>()
                .WhereRedb(o => o.Name == ProductionHttpFixture.BootstrapAdminGroup)
                .FirstOrDefaultAsync();
            if (grp is not null)
                await redb.DeleteAsync(grp.Id);
        });

        // 2. Drop the OIDC client through the OpenIddict manager so its sub-rows
        //    (authorizations / tokens) are cleaned up via the official path.
        using var scope = _fx.ServiceProvider.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await manager.FindByClientIdAsync(ProductionHttpFixture.BootstrapWebClientId);
        if (app is not null)
            await manager.DeleteAsync(app);
    }

    private static string NextEmail() =>
        $"bootstrap-admin-{Interlocked.Increment(ref _emailSeed)}-{Guid.NewGuid():N}@test.local";

    private static BootstrapAdminRequest ValidRequest(string? email = null) => new()
    {
        Email = email ?? NextEmail(),
        Password = "BootstrapPass!2026",
        RedirectUri = "https://admin.example.com/callback",
        PostLogoutRedirectUri = "https://admin.example.com/signed-out",
        BackchannelLogoutUri = "https://admin.example.com/back-logout",
    };

    private HttpRequestMessage NewBootstrapRequest(
        BootstrapAdminRequest body,
        string? secret = ProductionHttpFixture.BootstrapSecret)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/internal/bootstrap-admin")
        {
            Content = JsonContent.Create(body),
        };
        if (secret is not null)
            req.Headers.Add("X-Bootstrap-Secret", secret);
        return req;
    }

    // ── 1. Happy path ──────────────────────────────────────────────────

    [Fact]
    public async Task Bootstrap_Returns_201_OnFirstCall_With_ClientSecret()
    {
        var resp = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));

        resp.StatusCode.Should().Be(HttpStatusCode.Created);

        var payload = await resp.Content.ReadFromJsonAsync<BootstrapAdminResponse>();
        payload.Should().NotBeNull();
        payload!.UserId.Should().BeGreaterThan(0);
        payload.GroupId.Should().BeGreaterThan(0);
        payload.ApplicationId.Should().Be(ProductionHttpFixture.BootstrapWebClientId);
        payload.ClientSecret.Should().NotBeNullOrEmpty();
        payload.ClientSecret!.Length.Should().BeGreaterThanOrEqualTo(40);
        payload.ScopeName.Should().Be(ProductionHttpFixture.BootstrapAdminScope);

        // Sentinel must be present after success.
        await _fx.UseRedbAsync(async redb =>
        {
            var flag = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.Name == FlagName)
                .FirstOrDefaultAsync();
            flag.Should().NotBeNull();
            flag!.ValueBool.Should().BeTrue();
            flag.ValueString.Should().Be(ProductionHttpFixture.BootstrapWebClientId);
        });
    }

    // ── 2. Sentinel: second call short-circuits with 410 Gone. ─────────

    [Fact]
    public async Task Bootstrap_Returns_410_OnSecondCall()
    {
        var first = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        first.StatusCode.Should().Be(HttpStatusCode.Created);

        var second = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        second.StatusCode.Should().Be(HttpStatusCode.Gone);
    }

    // ── 3. Wrong secret ────────────────────────────────────────────────

    [Fact]
    public async Task Bootstrap_Returns_403_OnWrongSecret()
    {
        var resp = await _http.SendAsync(
            NewBootstrapRequest(ValidRequest(), secret: "definitely-not-the-right-secret"));
        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Bootstrap_Returns_403_OnMissingSecret()
    {
        var resp = await _http.SendAsync(NewBootstrapRequest(ValidRequest(), secret: null));
        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── 4. Disabled deployments → 404 (route is invisible). ───────────

    [Fact]
    public async Task Bootstrap_Returns_404_When_Disabled()
    {
        var optsRef = _fx.ServiceProvider
            .GetRequiredService<IOptions<RedbIdentityOptions>>().Value.Bootstrap;
        optsRef.Enabled = false;
        try
        {
            var resp = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
            resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        }
        finally
        {
            optsRef.Enabled = true;
        }
    }

    // ── 5. Atomicity: pre-existing identity-web client → 409 + flag stays unset.

    [Fact]
    public async Task Bootstrap_Is_Atomic_NoSentinel_When_OIDC_Client_Exists()
    {
        // Pre-create the canonical client to force a duplicate-collision on step 10.
        using (var scope = _fx.ServiceProvider.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ProductionHttpFixture.BootstrapWebClientId,
                ClientSecret = "preexisting-secret-1234567890",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
            });
        }

        var resp = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        resp.StatusCode.Should().Be(HttpStatusCode.Conflict);

        // The bootstrap_completed sentinel must NOT be set — atomic rollback.
        await _fx.UseRedbAsync(async redb =>
        {
            var flag = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.Name == FlagName)
                .FirstOrDefaultAsync();
            flag.Should().BeNull();
        });
    }

    // ── 6. Idempotency — pre-existing scope/group is reused, not duplicated.

    [Fact]
    public async Task Bootstrap_Idempotent_When_Group_Or_Scope_Already_Exists()
    {
        // First successful bootstrap creates the scope + group.
        var first = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        first.StatusCode.Should().Be(HttpStatusCode.Created);

        // Roll back ONLY the sentinel + the OIDC client so a second call can run;
        // leave the scope + group intact so the find-branches of the processor are hit.
        using (var scope = _fx.ServiceProvider.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var app = await manager.FindByClientIdAsync(ProductionHttpFixture.BootstrapWebClientId);
            if (app is not null) await manager.DeleteAsync(app);
        }
        await _fx.UseRedbAsync(async redb =>
        {
            var flag = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.Name == FlagName).FirstOrDefaultAsync();
            if (flag is not null) await redb.DeleteAsync(flag.Id);
        });

        var second = await _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        second.StatusCode.Should().Be(HttpStatusCode.Created);

        // Exactly one scope + one group row — no duplicates were created.
        await _fx.UseRedbAsync(async redb =>
        {
            var scopeCount = (await redb.Query<ScopeProps>()
                .WhereRedb(o => o.ValueString == ProductionHttpFixture.BootstrapAdminScope)
                .ToListAsync()).Count;
            scopeCount.Should().Be(1);

            var groupCount = (await redb.Query<GroupProps>()
                .WhereRedb(o => o.Name == ProductionHttpFixture.BootstrapAdminGroup)
                .ToListAsync()).Count;
            groupCount.Should().Be(1);
        });
    }

    // ── 7. Validation guard — bad payload returns 400. ────────────────

    [Fact]
    public async Task Bootstrap_Returns_400_OnInvalidRequest()
    {
        var bad = new BootstrapAdminRequest
        {
            Email = "missing-everything-else@test.local",
            // Password missing → ValidateRequest fails.
        };
        var resp = await _http.SendAsync(NewBootstrapRequest(bad));
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ── 8. Race condition — two concurrent calls; exactly one wins. ───

    [Fact]
    public async Task Bootstrap_RaceCondition_TwoConcurrentCalls_OnlyOneSucceeds()
    {
        var t1 = _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        var t2 = _http.SendAsync(NewBootstrapRequest(ValidRequest()));
        var responses = await Task.WhenAll(t1, t2);

        var statuses = responses.Select(r => (int)r.StatusCode).OrderBy(x => x).ToArray();
        // One must succeed, the other must be 410 (lost the race) or 409 (lost on the
        // OIDC-client unique constraint before the sentinel write committed).
        statuses[0].Should().Be(201);
        statuses[1].Should().BeOneOf(409, 410);
    }
}
