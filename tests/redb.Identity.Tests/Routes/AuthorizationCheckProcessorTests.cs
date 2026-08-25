using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Configuration;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// Ф5 — the granular scope table, now that it lives in Core behind
/// <c>direct-vm://identity-authz-check</c> and serves every transport.
/// <para>
/// The table was moved verbatim, so these tests are written against the rules rather than against the
/// move: each one states a decision the table has always made, and would fail if the move had shifted an
/// ordering, dropped a branch, or reworded a refusal. The refusal wording is part of the contract — the
/// HTTP negative matrix reads it, and quietly rewording it is how that net stops catching anything.
/// </para>
/// </summary>
public class AuthorizationCheckProcessorTests
{
    [Fact]
    public async Task An_anonymous_route_is_not_checked_at_all()
    {
        var e = Request("/api/v1/identity/users", "read");
        e.Properties["identity:management-anonymous"] = true;
        // Deliberately no scopes: an anonymous route is open by design, not open by accident.

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task The_master_scope_passes_everything()
    {
        var e = Request("/api/v1/identity/signing-keys", "write", IdentityScopes.Manage);

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task A_token_with_no_scopes_is_refused_even_though_it_authenticated()
    {
        // Authentication ran and left nothing behind. Defensive deny: the alternative is granting on the
        // strength of a bug elsewhere.
        var e = Request("/api/v1/identity/users", "read");

        await Enforce(e);

        Refused(e, "Access token carries no scopes.");
    }

    // ── read-only admin ──────────────────────────────────────

    [Fact]
    public async Task Read_only_admin_may_read_any_surface()
    {
        var e = Request("/api/v1/identity/federation-providers", "read", IdentityScopes.ReadOnly);

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task Read_only_admin_may_not_write()
    {
        var e = Request("/api/v1/identity/federation-providers", "write", IdentityScopes.ReadOnly);

        await Enforce(e);

        Refused(e);
    }

    // ── the account branch ───────────────────────────────────

    [Theory]
    [InlineData("/api/v1/identity/me/profile")]
    [InlineData("/api/v1/identity/account/verify-email")]
    [InlineData("/api/v1/identity/password/reset")]
    public async Task Self_service_paths_are_admitted_on_the_account_scope(string path)
    {
        // Admitted here, narrowed downstream: RequireSelfOrAdminProcessor is what keeps one account
        // holder out of another's data.
        var e = Request(path, "write", IdentityScopes.Account);

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task The_account_scope_does_not_reach_the_admin_surface()
    {
        var e = Request("/api/v1/identity/users", "read", IdentityScopes.Account);

        await Enforce(e);

        Refused(e);
    }

    // ── per-surface scopes ───────────────────────────────────

    [Fact]
    public async Task A_surfaces_read_scope_admits_a_read()
    {
        var e = Request("/api/v1/identity/users/42", "read", IdentityScopes.UsersRead);

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task Write_implies_read_on_the_same_surface()
    {
        // RBAC convention: holding :write means a GET on that surface does not also require :read.
        var e = Request("/api/v1/identity/users/42", "read", IdentityScopes.UsersWrite);

        await Enforce(e);

        Allowed(e);
    }

    [Fact]
    public async Task Read_never_implies_write()
    {
        var e = Request("/api/v1/identity/users/42", "write", IdentityScopes.UsersRead);

        await Enforce(e);

        Refused(e, $"This endpoint requires the '{IdentityScopes.UsersWrite}' scope");
    }

    [Fact]
    public async Task A_scope_for_another_surface_does_not_carry_over()
    {
        var e = Request("/api/v1/identity/groups", "read", IdentityScopes.UsersWrite);

        await Enforce(e);

        Refused(e, $"This endpoint requires the '{IdentityScopes.GroupsRead}' scope");
    }

    [Fact]
    public async Task An_unmapped_surface_is_denied_by_default()
    {
        // Adding a management surface must not silently open it to any admin token that happens to exist.
        var e = Request("/api/v1/identity/something-brand-new", "read", IdentityScopes.UsersRead);

        await Enforce(e);

        Refused(e, "does not carry a scope authorising '/api/v1/identity/something-brand-new'");
    }

    [Fact]
    public async Task Audit_is_read_only_by_construction()
    {
        // Its read and write slots hold the same scope, so a write cannot be granted separately.
        var e = Request("/api/v1/identity/audit", "write", IdentityScopes.AuditRead);

        await Enforce(e);

        Allowed(e, "the table maps audit's write slot to the read scope; nothing else grants it");
    }

    // ── transport neutrality ─────────────────────────────────

    [Fact]
    public async Task A_caller_without_http_headers_states_resource_and_action_itself()
    {
        // What makes the endpoint reusable: no redbHttp.Path, no redbHttp.Method, same decision.
        var e = new Exchange(new Message(Array.Empty<byte>()));
        e.Properties["identity:management-scopes"] = new[] { IdentityScopes.UsersRead };
        e.Properties["identity:authz-resource"] = "/api/v1/identity/users";
        e.Properties["identity:authz-action"] = "write";

        await Enforce(e);

        Refused(e, $"This endpoint requires the '{IdentityScopes.UsersWrite}' scope");
    }

    [Fact]
    public async Task Http_headers_are_read_when_nothing_states_the_resource()
    {
        // The HTTP facade leans on this: its path is already the canonical identifier, and carrying it a
        // second time would let the two copies disagree.
        var e = new Exchange(new Message(Array.Empty<byte>()));
        e.In.Headers["redbHttp.Path"] = "/api/v1/identity/roles";
        e.In.Headers["redbHttp.Method"] = "DELETE";
        e.Properties["identity:management-scopes"] = new[] { IdentityScopes.RolesRead };

        await Enforce(e);

        Refused(e, $"This endpoint requires the '{IdentityScopes.RolesWrite}' scope");
    }

    // ── helpers ───────────────────────────────────────────────

    private static Exchange Request(string resource, string action, params string[] scopes)
    {
        var e = new Exchange(new Message(Array.Empty<byte>()));
        e.Properties["identity:authz-resource"] = resource;
        e.Properties["identity:authz-action"] = action;
        if (scopes.Length > 0) e.Properties["identity:management-scopes"] = scopes;
        return e;
    }

    private static async Task Enforce(IExchange exchange)
    {
        var type = typeof(redb.Identity.Core.RedbIdentityServiceExtensions).Assembly
            .GetType("redb.Identity.Core.Routes.Processors.AuthorizationCheckProcessor")!;
        var processor = (IProcessor)Activator.CreateInstance(type, nonPublic: true)!;
        await processor.Process(exchange, CancellationToken.None);
    }

    private static void Allowed(IExchange e, string because = "")
    {
        e.HasOut.Should().BeFalse(because.Length > 0 ? because : "an allowed call writes no refusal");
        e.IsStopped.Should().BeFalse();
    }

    private static void Refused(IExchange e, string detailContains = "")
    {
        e.HasOut.Should().BeTrue("a refusal must be written, not implied");
        e.Out!.Headers["redbHttp.ResponseCode"].Should().Be(403);
        e.IsStopped.Should().BeTrue("the request must not reach the controller");

        var body = JsonSerializer.Deserialize<JsonElement>((byte[])e.Out.Body!);
        body.GetProperty("error").GetString().Should().Be("insufficient_scope");

        if (detailContains.Length > 0)
        {
            body.GetProperty("error_description").GetString()
                .Should().Contain(detailContains, "the wording is part of the contract the HTTP matrix reads");
        }
    }
}
