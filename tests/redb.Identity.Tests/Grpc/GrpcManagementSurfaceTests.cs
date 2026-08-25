using System.Reflection;
using FluentAssertions;
using redb.Identity.Management.Controllers;
using redb.Route.Controllers.Attributes;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// Ф6 — the operation table against the controllers it claims to expose.
/// <para>
/// The table is hand-written, and the two ways it can be wrong are both silent. A missing row means an
/// operation simply is not on this transport, and nobody notices until a caller asks for it. A row whose
/// <c>Writes</c> disagrees with the controller's own HTTP verb means the authorization gate checks the
/// read scope for something that mutates — which is the bad direction. So the table is compared against
/// the controllers themselves rather than reviewed by eye.
/// </para>
/// </summary>
public class GrpcManagementSurfaceTests
{
    private static readonly Type[] ExposedControllers =
    [
        typeof(UsersController),
        typeof(ApplicationsController),
        typeof(GroupsController),
        typeof(ScopesController),
        typeof(TokensController),
    ];

    [Fact]
    public void Both_sides_were_actually_read()
    {
        // Every other test in this file compares two sets. If either read came back empty — a renamed
        // field, a reflection miss — all of them would pass on nothing at all. This is the one that says so.
        Operations().Should().NotBeEmpty("the operation table was not read; the comparisons below are vacuous");
        ControllerActions().Should().NotBeEmpty("no controller actions were found; the comparisons are vacuous");

        Operations().Should().HaveSameCount(ControllerActions(),
            "the transport exposes exactly the actions of the controllers it registers");
    }

    [Fact]
    public void Every_action_of_an_exposed_controller_has_a_route()
    {
        var wired = Operations().Select(o => o.Dispatch).ToHashSet(StringComparer.Ordinal);
        var actual = ControllerActions().Select(a => a.Dispatch).ToHashSet(StringComparer.Ordinal);

        actual.Except(wired).Should().BeEmpty(
            "an exposed controller's action with no route is invisible on this transport, and nothing says so");
    }

    [Fact]
    public void No_route_points_at_an_action_that_does_not_exist()
    {
        var wired = Operations().Select(o => o.Dispatch).ToHashSet(StringComparer.Ordinal);
        var actual = ControllerActions().Select(a => a.Dispatch).ToHashSet(StringComparer.Ordinal);

        wired.Except(actual).Should().BeEmpty(
            "a route to a method that was renamed or removed answers NotFound at dispatch time, not at build time");
    }

    [Fact]
    public void Read_and_write_match_the_controller_verb()
    {
        var byName = ControllerActions().ToDictionary(a => a.Dispatch, a => a.Writes, StringComparer.Ordinal);

        var mismatched = Operations()
            .Where(o => byName.TryGetValue(o.Dispatch, out var writes) && writes != o.Writes)
            .Select(o => $"{o.Dispatch}: table says {(o.Writes ? "write" : "read")}, controller says {(byName[o.Dispatch] ? "write" : "read")}")
            .ToList();

        mismatched.Should().BeEmpty(
            "a mutating operation marked read is checked against the read scope — the gate would admit it");
    }

    [Fact]
    public void Dispatch_names_are_qualified()
    {
        // Five controllers share method names like List and Delete. GrpcControllerDispatcher resolves an
        // unqualified name to whichever matched first, so an unqualified row here would route by accident.
        Operations().Should().OnlyContain(o => o.Dispatch.Contains('.'),
            "an unqualified dispatch name is ambiguous across five registered controllers");
    }

    // ── reading the two sides ─────────────────────────────────

    private static IEnumerable<(string Dispatch, bool Writes)> Operations()
    {
        var builderType = typeof(redb.Identity.Grpc.IdentityGrpcTransportOptions).Assembly
            .GetType("redb.Identity.Grpc.GrpcManagementRouteBuilder")!;

        var table = builderType
            .GetField("Operations", BindingFlags.NonPublic | BindingFlags.Static)!
            .GetValue(null)!;

        foreach (var entry in (System.Collections.IEnumerable)table)
        {
            var type = entry.GetType();
            yield return (
                (string)type.GetProperty("DispatchMethod")!.GetValue(entry)!,
                (bool)type.GetProperty("Writes")!.GetValue(entry)!);
        }
    }

    private static IEnumerable<(string Dispatch, bool Writes)> ControllerActions()
    {
        foreach (var controller in ExposedControllers)
        {
            var prefix = controller.Name.EndsWith("Controller", StringComparison.Ordinal)
                ? controller.Name[..^"Controller".Length]
                : controller.Name;

            foreach (var method in controller.GetMethods(
                         BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                var verb = Verb(method);
                if (verb is null) continue;   // helpers, not actions

                yield return ($"{prefix}.{method.Name}", verb != "GET");
            }
        }
    }

    /// <summary>The controller's own HTTP verb — the single statement of whether an action mutates.</summary>
    private static string? Verb(MethodInfo method)
    {
        if (method.GetCustomAttribute<HttpGetAttribute>() is not null) return "GET";
        if (method.GetCustomAttribute<HttpPostAttribute>() is not null) return "POST";
        if (method.GetCustomAttribute<HttpPutAttribute>() is not null) return "PUT";
        if (method.GetCustomAttribute<HttpPatchAttribute>() is not null) return "PATCH";
        if (method.GetCustomAttribute<HttpDeleteAttribute>() is not null) return "DELETE";
        return null;
    }
}
