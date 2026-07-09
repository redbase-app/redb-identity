using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Serialization;

/// <summary>
/// Locked wire-format JSON profiles for redb.Identity transports
/// (SCIM 2.0, RFC 9457 Problem Details, OAuth 2.0 / OIDC / RFC 7591 DCR).
/// <para>
/// These options are fixed by IETF RFCs and MUST NOT be made configurable. Identity acts as
/// a SCIM / OAuth 2.0 / OIDC provider — wire-level interop is negotiated by the specs listed
/// below, not by application config. Exposing options would silently break compatibility.
/// </para>
/// <para>
/// Lives in <c>redb.Identity.Contracts</c> (no Route framework dependency) so transport
/// facades — HTTP, gRPC, etc. — can consume the same locked options without taking a
/// project-reference on Core. Core re-exports these as <c>IMessageSerializer</c> singletons
/// for use by the route data-format registry.
/// </para>
/// <para>Specification anchors:</para>
/// <list type="bullet">
///   <item>RFC 8259 §8.1 — JSON between non-closed systems MUST use UTF-8.</item>
///   <item>RFC 7644 §3 — SCIM media type <c>application/scim+json</c>; attribute names
///     verbatim per RFC 7643 §7 (no naming-policy transform).</item>
///   <item>RFC 9457 §3 — Problem Details media type <c>application/problem+json</c>;
///     §3.1 lowercase members (<c>type</c>, <c>title</c>, <c>status</c>, <c>detail</c>,
///     <c>instance</c>).</item>
///   <item>RFC 6749 §5.1 — OAuth 2.0 token responses <c>application/json</c>, UTF-8,
///     snake_case members carried by DTOs via <see cref="JsonPropertyNameAttribute"/>.</item>
///   <item>RFC 7591 §3.2 — Dynamic Client Registration response naming as request
///     (snake_case, spec-defined).</item>
///   <item>OpenID Connect Discovery 1.0 §4.2 — JSON object, UTF-8.</item>
/// </list>
/// </summary>
public static class IdentityWireProfiles
{
    // ── Media-type constants ─────────────────────────────────────────────────

    /// <summary>SCIM 2.0 protocol media type — RFC 7644 §3.</summary>
    public const string ScimMediaType = "application/scim+json";

    /// <summary>Problem Details media type — RFC 9457 §3.</summary>
    public const string ProblemMediaType = "application/problem+json";

    /// <summary>OAuth / OIDC / DCR JSON media type — RFC 6749 §5.1, OIDC Discovery §4.2.</summary>
    public const string OAuthMediaType = "application/json";

    // ── Locked JsonSerializerOptions ─────────────────────────────────────────

    /// <summary>SCIM response options — RFC 7643/7644.</summary>
    public static readonly JsonSerializerOptions ScimOptions = BuildScim();

    /// <summary>Problem Details response options — RFC 9457.</summary>
    public static readonly JsonSerializerOptions ProblemOptions = BuildProblem();

    /// <summary>OAuth / OIDC / DCR response options — RFC 6749 §5.1, RFC 7591, OIDC Discovery §4.2.</summary>
    public static readonly JsonSerializerOptions OAuthOptions = BuildOAuth();

    // ── Builders (sealed via trivial serialize so MakeReadOnly() takes effect) ──

    private static JsonSerializerOptions BuildScim() => Seal(new JsonSerializerOptions
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    });

    private static JsonSerializerOptions BuildProblem() => Seal(new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    });

    private static JsonSerializerOptions BuildOAuth() => Seal(new JsonSerializerOptions
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    });

    /// <summary>
    /// Forces the options into an immutable state (a trivial <see cref="JsonSerializer.Serialize"/>
    /// triggers <c>MakeReadOnly()</c>) so accidental post-publication mutation of the
    /// shared singleton can't reshape the wire format.
    /// </summary>
    private static JsonSerializerOptions Seal(JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(0, options);
        return options;
    }
}
