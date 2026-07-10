using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// D6 — Bearer token parsing per RFC 6750 §2.1 + RFC 7230 §3.2.4.
/// Verifies case-insensitive scheme matching and tolerance of multiple
/// whitespace characters between the scheme name and the token68 value.
/// </summary>
public class BearerParsingD6Tests
{
    [Theory]
    [InlineData("Bearer abc", "abc")]
    [InlineData("bearer abc", "abc")]
    [InlineData("BEARER abc", "abc")]
    [InlineData("BeArEr abc", "abc")]
    [InlineData("Bearer    abc", "abc")] // multiple SP per RFC 7230 OWS
    [InlineData("Bearer\tabc", "abc")]    // HTAB allowed in OWS
    [InlineData("  Bearer abc  ", "abc")]
    public void TryExtractBearerToken_AcceptsValidVariants(string header, string expected)
    {
        ManagementBearerAuthProcessor.TryExtractBearerToken(header).Should().Be(expected);
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearerabc")] // no separator — must be rejected
    [InlineData("Token abc")]
    [InlineData("")]
    [InlineData(null)]
    public void TryExtractBearerToken_RejectsNonBearerOrMalformed(string? header)
    {
        ManagementBearerAuthProcessor.TryExtractBearerToken(header).Should().BeNull();
    }

    [Fact]
    public void TryExtractBearerToken_EmptyTokenRecognised()
    {
        // "Bearer " with no token still parses to empty string — caller turns this
        // into a 401 invalid_token response per RFC 6750 §3.1.
        ManagementBearerAuthProcessor.TryExtractBearerToken("Bearer ").Should().Be(string.Empty);
        ManagementBearerAuthProcessor.TryExtractBearerToken("Bearer    ").Should().Be(string.Empty);
    }
}
