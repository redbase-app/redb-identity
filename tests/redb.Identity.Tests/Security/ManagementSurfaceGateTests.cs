using System.Reflection;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// The core management surface trusts no transport.
/// <para>
/// <c>direct-vm://identity-manage-*</c>, <c>identity-manage-mfa</c>, <c>identity-me-*</c>,
/// <c>identity-scim-*</c> and <c>identity-revoked-sids</c> are reached by the facades after a bearer was
/// validated and the <c>identity:management-*</c> properties were attached. In a Tsak worker the same
/// <c>direct-vm</c> registry is shared by every module in the process, so an exchange that arrives
/// without that context is not "internal and trusted" — it is unauthenticated. Every route of the
/// surface must refuse it before any business processor runs, and the refusal must be the same
/// generic 403 the self-or-admin rule produces, so nothing about the target leaks.
/// </para>
/// </summary>
[Collection("IdentityRoute")]
public sealed class ManagementSurfaceGateTests
{
    private readonly IdentityRouteFixture _fx;

    public ManagementSurfaceGateTests(IdentityRouteFixture fx) => _fx = fx;

    /// <summary>
    /// Routes the fixture registers only when a feature is on. Absent in the fixture, they are skipped
    /// by name; anything else that is absent fails the test — a new guarded route must be covered.
    /// </summary>
    private static readonly HashSet<string> ConditionalRoutes = new(StringComparer.Ordinal)
    {
        IdentityEndpoints.ManageSigningKeys,
        IdentityEndpoints.ScimUsers,
        IdentityEndpoints.ScimGroups,
        IdentityEndpoints.ScimBulk,
        IdentityEndpoints.MeWebAuthn,
        IdentityEndpoints.MeEmailVerifySend,
        IdentityEndpoints.MeChangeEmailRequest,
    };

    /// <summary>Every endpoint constant on the guarded surface, read off <see cref="IdentityEndpoints"/>.</summary>
    public static IEnumerable<object[]> GuardedEndpoints()
    {
        var uris = typeof(IdentityEndpoints)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .Where(IsGuarded)
            .Distinct()
            .OrderBy(u => u, StringComparer.Ordinal);
        foreach (var uri in uris)
            yield return new object[] { uri };
    }

    internal static bool IsGuarded(string uri) =>
        uri.StartsWith("direct-vm://identity-manage-", StringComparison.Ordinal)
        || uri.StartsWith("direct-vm://identity-me-", StringComparison.Ordinal)
        || uri.StartsWith("direct-vm://identity-scim-", StringComparison.Ordinal)
        || string.Equals(uri, IdentityEndpoints.RevokedSids, StringComparison.Ordinal);

    [Theory]
    [MemberData(nameof(GuardedEndpoints))]
    public async Task Without_a_management_context_the_route_refuses(string endpointUri)
    {
        if (!_fx.RegisteredFromUris.Contains(endpointUri))
        {
            ConditionalRoutes.Should().Contain(endpointUri,
                "{0} is on the guarded surface but the fixture does not register it and it is not a known "
                + "feature-gated route; register it or the gate on it stays untested", endpointUri);
            return;
        }

        // An empty body and a harmless operation: the gate has to refuse before anyone reads either.
        var exchange = await _fx.RequestWithHeaders(
            endpointUri,
            new Dictionary<string, object?>(),
            new Dictionary<string, object?> { ["operation"] = "list" },
            ManagementCaller.None);

        StatusOf(exchange).Should().Be(403,
            "{0} was reached with no management context and must refuse, not run", endpointUri);
        CodeOf(exchange).Should().Be("not_authorized",
            "the refusal is the same generic problem the self-or-admin rule produces, so nothing leaks");
    }

    [Fact]
    public async Task With_an_admin_context_the_same_route_answers()
    {
        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.ManageScopes,
            new Dictionary<string, object?>(),
            new Dictionary<string, object?> { ["operation"] = "list" },
            ManagementCaller.Admin);

        StatusOf(exchange).Should().NotBe(403, "an admin context is exactly what the facades attach");
    }

    private static int? StatusOf(IExchange exchange)
    {
        var msg = exchange.Out ?? exchange.In;
        return msg.Headers.TryGetValue("redbHttp.ResponseCode", out var raw) && raw is not null
            ? Convert.ToInt32(raw)
            : null;
    }

    private static string? CodeOf(IExchange exchange)
    {
        var body = (exchange.Out ?? exchange.In).Body;
        var json = body switch
        {
            string s => s,
            byte[] b => Encoding.UTF8.GetString(b),
            _ => null,
        };
        if (json is null) return null;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
    }
}
