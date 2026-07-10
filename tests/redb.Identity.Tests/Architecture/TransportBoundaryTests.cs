using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Tests.Architecture;

/// <summary>
/// Architectural fitness tests guarding the redb.Identity.Core transport boundary.
/// <para>
/// Identity servers live in the HTTP world by nature — the OAuth2 / OIDC / SCIM / RFC
/// specifications are defined in HTTP terms (status codes, content-types, headers), so an
/// HTTP vocabulary inside core is legitimate. What is NOT legitimate is <b>wire-encoding</b>
/// the response into string/byte[] directly in core: that locks the response into JSON and
/// breaks the gRPC / Kafka / MQTT facade adapters, which must be able to override the
/// native serialization.
/// </para>
/// <para>
/// These tests scan <c>redb.Identity.Core</c> source for forbidden assignments to
/// <c>exchange.Out.Body</c>. Domain JSON usage (PROPS column encoding, DataProtection blobs,
/// hashing, JsonElement composition) is allowed — only Body-targeted wire encoding is banned.
/// </para>
/// </summary>
public class TransportBoundaryTests
{
    private static readonly string CoreSourceRoot = LocateCoreSourceRoot();

    private static string LocateCoreSourceRoot()
    {
        // Walk up from the test assembly location until we find redb.Identity.Core.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "redb.Identity.Core");
            if (Directory.Exists(candidate))
                return candidate;
            // Also try repo-root layout: <repo>/redb.Identity/src/redb.Identity.Core
            var repoCandidate = Path.Combine(dir.FullName, "redb.Identity", "src", "redb.Identity.Core");
            if (Directory.Exists(repoCandidate))
                return repoCandidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException(
            "Could not locate redb.Identity.Core source root from test base directory.");
    }

    private static IEnumerable<(string Path, string Source)> EnumerateCoreSources()
    {
        foreach (var file in Directory.EnumerateFiles(CoreSourceRoot, "*.cs", SearchOption.AllDirectories))
        {
            // Skip generated artefacts.
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                continue;
            if (file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                continue;
            yield return (file, StripComments(File.ReadAllText(file)));
        }
    }

    /// <summary>
    /// Strips line and block comments (including XML doc comments) so fitness regexes only
    /// match real code, not commentary that legitimately mentions HTTP types or JSON encoding.
    /// String literals are left in place — wire-encoding done via interpolated strings would
    /// still surface as code.
    /// </summary>
    private static string StripComments(string source)
    {
        // Block /* ... */
        source = Regex.Replace(source, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline);
        // Line // ... and /// ...
        source = Regex.Replace(source, @"//.*$", string.Empty, RegexOptions.Multiline);
        return source;
    }

    [Fact]
    public void CoreSource_DoesNotAssignSerializedJsonStringToOutBody()
    {
        // exchange.Out.Body = JsonSerializer.Serialize(...)   ← forbidden (locks transport to JSON string).
        // SerializeToElement / SerializeToNode / SerializeToUtf8Bytes are caught elsewhere or allowed.
        var pattern = new Regex(
            @"\.Out\.Body\s*=\s*JsonSerializer\.Serialize\b(?!ToElement|ToNode|ToUtf8Bytes)",
            RegexOptions.Compiled);

        var violations = new List<string>();
        foreach (var (path, source) in EnumerateCoreSources())
        {
            foreach (Match m in pattern.Matches(source))
            {
                var line = LineOf(source, m.Index);
                violations.Add($"{path}:{line} -> {m.Value}");
            }
        }

        violations.Should().BeEmpty(
            "core processors must keep exchange.Out.Body as a typed object; wire-encoding to JSON " +
            "string belongs to the transport facade or an explicit .Marshal(...) DSL step");
    }

    [Fact]
    public void CoreSource_DoesNotAssignUtf8BytesToOutBody()
    {
        // exchange.Out.Body = JsonSerializer.SerializeToUtf8Bytes(...)   ← forbidden (locks transport to JSON bytes).
        var pattern = new Regex(
            @"\.Out\.Body\s*=\s*JsonSerializer\.SerializeToUtf8Bytes\b",
            RegexOptions.Compiled);

        var violations = new List<string>();
        foreach (var (path, source) in EnumerateCoreSources())
        {
            foreach (Match m in pattern.Matches(source))
            {
                var line = LineOf(source, m.Index);
                violations.Add($"{path}:{line} -> {m.Value}");
            }
        }

        violations.Should().BeEmpty(
            "core processors must keep exchange.Out.Body as a typed object; pre-encoding to UTF-8 " +
            "bytes locks the response into a single wire format");
    }

    [Fact]
    public void CoreSource_DoesNotReferenceAspNetCoreHttp()
    {
        // No HttpContext / IHttpContextAccessor leakage — transport is owned by facades.
        var usingPattern = new Regex(
            @"^\s*using\s+Microsoft\.AspNetCore\.Http\b",
            RegexOptions.Compiled | RegexOptions.Multiline);
        var typeRefPattern = new Regex(
            @"\b(HttpContext|IHttpContextAccessor)\b",
            RegexOptions.Compiled);

        var violations = new List<string>();
        foreach (var (path, source) in EnumerateCoreSources())
        {
            foreach (Match m in usingPattern.Matches(source))
                violations.Add($"{path}:{LineOf(source, m.Index)} -> {m.Value.Trim()}");
            foreach (Match m in typeRefPattern.Matches(source))
                violations.Add($"{path}:{LineOf(source, m.Index)} -> {m.Value}");
        }

        violations.Should().BeEmpty(
            "redb.Identity.Core must not depend on Microsoft.AspNetCore.Http; HTTP-specific " +
            "wiring belongs to redb.Identity.Http (or another facade)");
    }

    [Fact]
    public void CoreSource_AuditEventTypeAssignments_UseCatalogConstants()
    {
        // H6/H7/H9: every <c>identity-event-type</c> must be sourced from
        // <see cref="redb.Identity.Contracts.Routes.IdentityAuditEventIds"/> (or a const ref to it).
        // String literals are forbidden so the catalog stays the single source of truth and
        // CategoryOf(...) keeps a closed switch.
        // Pattern: exchange.Properties["identity-event-type"] = "<literal>"
        var pattern = new Regex(
            "Properties\\[\"identity-event-type\"\\]\\s*=\\s*\"[^\"]+\"",
            RegexOptions.Compiled);

        var violations = new List<string>();
        foreach (var (path, source) in EnumerateCoreSources())
        {
            foreach (Match m in pattern.Matches(source))
            {
                var line = LineOf(source, m.Index);
                violations.Add($"{path}:{line} -> {m.Value}");
            }
        }

        violations.Should().BeEmpty(
            "audit event types must reference IdentityAuditEventIds.* constants; literal magic " +
            "strings break the catalog/category contract and bypass downstream routing.");
    }

    private static int LineOf(string source, int index)
    {
        var line = 1;
        for (var i = 0; i < index && i < source.Length; i++)
            if (source[i] == '\n') line++;
        return line;
    }
}
