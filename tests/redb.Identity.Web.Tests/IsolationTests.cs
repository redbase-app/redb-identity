using System.Linq;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Enforces the BFF isolation HARDLINE at runtime (in addition to the
/// CI workflow at <c>.github/workflows/identity-web-isolation.yml</c>).
/// <para>
/// redb.Identity.Web is contractually limited to consuming the public SDK
/// surface — <c>redb.Identity.Contracts</c> and <c>redb.Identity.Client</c>.
/// Pulling any other <c>redb.Identity.*</c> assembly into the Web binary
/// breaks the "BFF talks to identity-server over HTTP" boundary and is a
/// regression.
/// </para>
/// <para>
/// This test inspects the actual referenced assemblies of the Web build
/// output, so it catches the violation even if the CI grep over csproj/
/// using statements is bypassed (e.g. via a transitive package alias).
/// </para>
/// </summary>
public class IsolationTests
{
    private static readonly string[] AllowedIdentityRefs =
    [
        "redb.Identity.Contracts",
        "redb.Identity.Client",
    ];

    [Fact]
    public void Web_AssemblyReferences_StayWithinSdkBoundary()
    {
        var webAssembly = typeof(Program).Assembly;

        var identityRefs = webAssembly
            .GetReferencedAssemblies()
            .Select(n => n.Name ?? string.Empty)
            .Where(n => n.StartsWith("redb.Identity", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        var violations = identityRefs
            .Where(n => !AllowedIdentityRefs.Contains(n, StringComparer.Ordinal))
            .ToArray();

        violations.Should().BeEmpty(
            "redb.Identity.Web MUST only reference {0}; found forbidden refs: {1}. " +
            "See redb.Identity/doc/webplan/00-PREAMBLE.md (BFF isolation HARDLINE).",
            string.Join(", ", AllowedIdentityRefs),
            string.Join(", ", violations));
    }
}
