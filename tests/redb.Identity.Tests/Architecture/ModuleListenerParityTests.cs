using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Tests.Architecture;

/// <summary>
/// Identity has two entry points, and the shipped one must not be the poorer of the two.
/// <para>
/// <c>redb.Identity.Core/Module/InitRoute.cs</c> boots Identity inside a host process — which is
/// what the test fixtures use. <c>redb.Identity.Core.Module/InitRoute.cs</c> is the entry point
/// Tsak discovers in the <c>.tpkg</c>, and it is therefore the one every deployment actually runs.
/// Each keeps its own chain of lifecycle listeners, so a listener added to the first and forgotten
/// in the second is green in every test and absent in production.
/// </para>
/// <para>
/// That is not hypothetical. The seeder that gives the admin role its management scope — the
/// upgrade path for the administrative-scope gate, the one thing standing between an upgrade and an
/// administrator locked out of their own console — was registered only in the embeddable entry
/// point. The suite passed; the running worker never ran it.
/// </para>
/// <para>
/// The check runs one way: every listener the embeddable path registers must also be registered by
/// the Tsak path. The reverse is allowed, because the module entry point legitimately owns
/// host-specific listeners (the child-container and bridge-scope disposers, the credential seeders
/// resolved from its own container).
/// </para>
/// </summary>
public class ModuleListenerParityTests
{
    private static readonly string IdentityRoot = LocateIdentityRoot();

    private static string LocateIdentityRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "redb.Identity.Core.Module");
            if (Directory.Exists(candidate)) return Path.Combine(dir.FullName, "src");
            var repoCandidate = Path.Combine(dir.FullName, "redb.Identity", "src", "redb.Identity.Core.Module");
            if (Directory.Exists(repoCandidate)) return Path.Combine(dir.FullName, "redb.Identity", "src");
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate the redb.Identity source root from the test base directory.");
    }

    /// <summary>Listener type names passed to <c>AddLifecycleListener(new Xxx(...))</c>.</summary>
    private static HashSet<string> RegisteredListeners(string initRoutePath)
    {
        File.Exists(initRoutePath).Should().BeTrue($"{initRoutePath} is the entry point this test is about");
        var source = File.ReadAllText(initRoutePath);

        // Comments mention listener names constantly - strip them, or the parity check passes on prose.
        source = Regex.Replace(source, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline);
        source = Regex.Replace(source, @"//.*?$", string.Empty, RegexOptions.Multiline);

        return Regex.Matches(source, @"AddLifecycleListener\(\s*new\s+([A-Za-z0-9_\.]+)\s*\(")
            .Select(m => m.Groups[1].Value.Split('.')[^1])
            .ToHashSet(StringComparer.Ordinal);
    }

    [Fact]
    public void The_tsak_entry_point_registers_every_listener_the_embeddable_one_does()
    {
        var embeddable = RegisteredListeners(Path.Combine(IdentityRoot, "redb.Identity.Core", "Module", "InitRoute.cs"));
        var shipped = RegisteredListeners(Path.Combine(IdentityRoot, "redb.Identity.Core.Module", "InitRoute.cs"));

        embeddable.Should().NotBeEmpty("the embeddable entry point registers the bootstrap chain");

        var missing = embeddable.Except(shipped, StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        missing.Should().BeEmpty(
            "every listener the host-embedded path runs must also run under Tsak, which is what ships - "
            + "otherwise the test suite exercises a boot sequence no deployment performs");
    }
}
