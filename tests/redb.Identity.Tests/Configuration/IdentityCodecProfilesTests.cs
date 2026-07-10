using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using redb.Identity.Core.Serialization;
using Xunit;

namespace redb.Identity.Tests.Configuration;

/// <summary>
/// Pin-tests for <see cref="IdentityCodecProfiles"/>. These intentionally fail loudly
/// if anyone "tunes" the profile constants — that would silently break SCIM / OAuth /
/// OIDC wire-level compatibility with external clients.
/// <para>
/// Rationale lives on each option's XML doc (RFC anchors). These tests are the automated
/// guardrail; the XML doc is the explanation.
/// </para>
/// </summary>
public class IdentityCodecProfilesTests
{
    [Fact]
    public void ScimOptions_MatchesRfc7643_AndRfc8259()
    {
        var opts = IdentityCodecProfiles.ScimOptions;

        // RFC 7643 §7: attribute names are specified verbatim by the schema
        opts.PropertyNamingPolicy.Should().BeNull(
            "SCIM attribute names are defined by RFC 7643 and must not be remapped by a naming policy");

        // RFC 7644 §3.8: unset attributes are omitted
        opts.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);

        // RFC 8259 §8.1: UTF-8 wire format (no \uXXXX escaping of ASCII/Cyrillic/etc.)
        opts.Encoder.Should().BeSameAs(JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        opts.WriteIndented.Should().BeFalse("production responses must not add whitespace");
    }

    [Fact]
    public void ProblemOptions_MatchesRfc9457()
    {
        var opts = IdentityCodecProfiles.ProblemOptions;

        // RFC 9457 §3.1: standard members are lowercase (type, title, status, detail, instance)
        opts.PropertyNamingPolicy.Should().Be(JsonNamingPolicy.CamelCase);
        opts.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);
        opts.Encoder.Should().BeSameAs(JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
    }

    [Fact]
    public void OAuthOptions_MatchesRfc6749_AndRfc7591()
    {
        var opts = IdentityCodecProfiles.OAuthOptions;

        // RFC 6749 §5.1 / RFC 7591 §3.2: parameter names are snake_case per spec;
        // DTOs carry [JsonPropertyName] — a naming policy would double-transform them.
        opts.PropertyNamingPolicy.Should().BeNull();
        opts.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);
        opts.Encoder.Should().BeSameAs(JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
    }

    [Fact]
    public void AllProfiles_AreSealed_AndCannotBeMutatedAtRuntime()
    {
        // System.Text.Json freezes JsonSerializerOptions after first use; assert the seal
        // is in effect by attempting to mutate and expecting InvalidOperationException.
        Action mutateScim = () => IdentityCodecProfiles.ScimOptions.WriteIndented = true;
        Action mutateProblem = () => IdentityCodecProfiles.ProblemOptions.WriteIndented = true;
        Action mutateOAuth = () => IdentityCodecProfiles.OAuthOptions.WriteIndented = true;

        mutateScim.Should().Throw<InvalidOperationException>();
        mutateProblem.Should().Throw<InvalidOperationException>();
        mutateOAuth.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void ScimOptions_EmitsUnicodeLiterals_NotEscapeSequences()
    {
        // Regression guard for the \u0022 / \u0410 escape artefacts that prompted the
        // migration to locked profiles. UTF-8 wire per RFC 8259 §8.1.
        var json = JsonSerializer.Serialize(new { name = "Café \"world\"" }, IdentityCodecProfiles.ScimOptions);

        json.Should().Contain("Café");
        json.Should().NotContain("\\u00e9"); // accented "e" — must stay a UTF-8 literal
        json.Should().NotContain("\\u0022"); // ASCII quote
    }
}
