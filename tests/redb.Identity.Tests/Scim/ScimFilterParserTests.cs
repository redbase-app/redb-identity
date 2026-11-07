using redb.Identity.Core.Routes.Processors;
using Xunit;

namespace redb.Identity.Tests.Scim;

/// <summary>
/// Unit tests for ScimFilterParser (RFC 7644 §3.4.2.2).
/// Pure in-memory, no I/O.
/// </summary>
public class ScimFilterParserTests
{
    // ── eq operator ─────────────────────────────────────────────

    [Fact]
    public void Parse_Eq_ReturnsCorrectFilter()
    {
        var f = ScimFilterParser.Parse("userName eq \"john\"");
        Assert.NotNull(f);
        Assert.Equal("username", f!.Attribute);
        Assert.Equal("eq", f.Operator);
        Assert.Equal("john", f.Value);
    }

    [Fact]
    public void Parse_Eq_CaseInsensitiveAttribute()
    {
        var f = ScimFilterParser.Parse("UserName eq \"john\"");
        Assert.NotNull(f);
        Assert.Equal("username", f!.Attribute);
    }

    [Fact]
    public void Parse_Eq_CaseInsensitiveOperator()
    {
        var f = ScimFilterParser.Parse("userName EQ \"john\"");
        Assert.NotNull(f);
        Assert.Equal("eq", f!.Operator);
    }

    [Fact]
    public void Parse_Eq_DottedAttribute()
    {
        var f = ScimFilterParser.Parse("emails.value eq \"user@test.com\"");
        Assert.NotNull(f);
        Assert.Equal("emails.value", f!.Attribute);
        Assert.Equal("user@test.com", f.Value);
    }

    [Fact]
    public void Parse_Eq_EmptyValue()
    {
        var f = ScimFilterParser.Parse("userName eq \"\"");
        Assert.NotNull(f);
        Assert.Equal(string.Empty, f!.Value);
    }

    // ── Other comparison operators ──────────────────────────────

    [Theory]
    [InlineData("ne", "userName ne \"john\"")]
    [InlineData("co", "displayName co \"smith\"")]
    [InlineData("sw", "userName sw \"joh\"")]
    [InlineData("ew", "email ew \"@test.com\"")]
    [InlineData("gt", "meta.created gt \"2026-01-01\"")]
    [InlineData("ge", "meta.created ge \"2026-01-01\"")]
    [InlineData("lt", "meta.created lt \"2026-12-31\"")]
    [InlineData("le", "meta.created le \"2026-12-31\"")]
    public void Parse_ComparisonOperator_ReturnsCorrectOp(string expectedOp, string input)
    {
        var f = ScimFilterParser.Parse(input);
        Assert.NotNull(f);
        Assert.Equal(expectedOp, f!.Operator);
    }

    // ── pr (presence) operator ──────────────────────────────────

    [Fact]
    public void Parse_Pr_ReturnsPresenceFilter()
    {
        var f = ScimFilterParser.Parse("userName pr");
        Assert.NotNull(f);
        Assert.Equal("username", f!.Attribute);
        Assert.Equal("pr", f.Operator);
        Assert.Equal(string.Empty, f.Value);
    }

    [Fact]
    public void Parse_Pr_CaseInsensitive()
    {
        var f = ScimFilterParser.Parse("Active PR");
        Assert.NotNull(f);
        Assert.Equal("active", f!.Attribute);
        Assert.Equal("pr", f.Operator);
    }

    // ── Null/empty/whitespace ───────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(ScimFilterParser.Parse(input));
    }

    // ── Invalid / unsupported ───────────────────────────────────

    [Theory]
    [InlineData("userName")]
    [InlineData("userName like \"john\"")]
    [InlineData("userName eq john")]
    [InlineData("eq \"john\"")]
    [InlineData("userName eq \"john\" and displayName eq \"doe\"")]
    public void Parse_Invalid_ReturnsNull(string input)
    {
        Assert.Null(ScimFilterParser.Parse(input));
    }

    // ── Whitespace trimming ─────────────────────────────────────

    [Fact]
    public void Parse_LeadingTrailingWhitespace_Trimmed()
    {
        var f = ScimFilterParser.Parse("  userName eq \"john\"  ");
        Assert.NotNull(f);
        Assert.Equal("john", f!.Value);
    }

    // ── Value with spaces ───────────────────────────────────────

    [Fact]
    public void Parse_ValueWithSpaces()
    {
        var f = ScimFilterParser.Parse("displayName eq \"John Doe\"");
        Assert.NotNull(f);
        Assert.Equal("John Doe", f!.Value);
    }
}
