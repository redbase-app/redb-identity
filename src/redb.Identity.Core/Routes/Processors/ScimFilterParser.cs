using System.Text.RegularExpressions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Minimal SCIM filter parser (RFC 7644 §3.4.2.2).
/// Supports single expressions: <c>attrPath op "value"</c> and <c>attrPath pr</c>.
/// Attribute names are normalized to lowercase.
/// </summary>
internal static partial class ScimFilterParser
{
    public sealed record ScimFilter(string Attribute, string Operator, string Value);

    /// <summary>
    /// Parses a SCIM filter expression like <c>userName eq "john"</c> or <c>active pr</c>.
    /// Returns null for unsupported or empty filters.
    /// </summary>
    public static ScimFilter? Parse(string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return null;

        var trimmed = filter.Trim();

        // Try presence operator first: attrPath pr (no value)
        var prMatch = PresenceRegex().Match(trimmed);
        if (prMatch.Success)
        {
            return new ScimFilter(
                prMatch.Groups[1].Value.ToLowerInvariant(),
                "pr",
                string.Empty);
        }

        // Standard comparison: attrPath SP operator SP quotedValue
        var match = FilterRegex().Match(trimmed);
        if (!match.Success) return null;

        return new ScimFilter(
            match.Groups[1].Value.ToLowerInvariant(),
            match.Groups[2].Value.ToLowerInvariant(),
            match.Groups[3].Value);
    }

    // attrPath SP operator SP quotedValue
    [GeneratedRegex(@"^(\S+)\s+(eq|ne|co|sw|ew|gt|ge|lt|le)\s+""([^""]*)""$", RegexOptions.IgnoreCase)]
    private static partial Regex FilterRegex();

    // attrPath SP pr (presence — no value)
    [GeneratedRegex(@"^(\S+)\s+pr$", RegexOptions.IgnoreCase)]
    private static partial Regex PresenceRegex();
}
