using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// S2 — declarative claim schema. Defines a custom claim that may appear
/// on <see cref="UserProps.CustomClaims"/> with optional server-side
/// validation (required / type / regex) and per-destination emit control.
///
/// <para>
/// Three orthogonal mechanisms in the identity pipeline:
///   <list type="bullet">
///   <item><b>Claim mappers</b> (<see cref="ClaimMapperProps"/>) — translate
///       user attributes / groups into emitted claims at token issuance time.</item>
///   <item><b>UserProps.CustomClaims</b> — per-user value storage; what a
///       specific user actually has set.</item>
///   <item><b>Claim definitions</b> (this entity) — schema with required /
///       type / pattern; validated at user create / update time. Optional
///       <see cref="DefaultValue"/> auto-fills required claims that the
///       caller omitted, so a fresh user can never end up below schema.</item>
///   </list>
/// </para>
///
/// <para>
/// Uniqueness: (<see cref="ClaimName"/>, <see cref="Scope"/>, <see cref="ApplicationId"/>)
/// is unique. A global definition for "external_user_id" is one row; an
/// application-specific override for the same name is a separate row keyed
/// by app id.
/// </para>
/// </summary>
[RedbScheme("identity.claim_definition")]
public class ClaimDefinitionProps
{
    /// <summary>
    /// Claim key as it appears in <see cref="UserProps.CustomClaims"/> and in
    /// issued JWTs. Convention: namespaced with a colon prefix when the value
    /// is private (e.g. "redb:user_id", "myapp:tier"); bare for public OIDC
    /// extension claims.
    /// </summary>
    public string ClaimName { get; set; } = "";

    /// <summary>Human-friendly label rendered next to the input on the user
    /// profile editor. Defaults to <see cref="ClaimName"/> when null.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Operator-facing description / help text rendered as a field
    /// hint on the user profile editor.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// Value type — drives both the editor widget on the user profile UI and
    /// the server-side parse / validation. Allowed: "string" (default),
    /// "int", "long", "bool", "datetime", "url", "email".
    /// </summary>
    public string Type { get; set; } = "string";

    /// <summary>
    /// When true, user create / update will be rejected with a 400
    /// validation_error if the claim value is missing AND no
    /// <see cref="DefaultValue"/> is set. When false, the claim is optional —
    /// callers may omit it.
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// Default value applied when the caller omits a required claim. When
    /// the claim is optional and unset, no default is applied (the field
    /// simply stays absent from <see cref="UserProps.CustomClaims"/>).
    /// </summary>
    public string? DefaultValue { get; set; }

    /// <summary>
    /// Optional regex pattern. Applied to the value (string form) at user
    /// create / update; mismatches yield a 400 validation_error. Ignored for
    /// non-string types — those have type-specific parse instead.
    /// </summary>
    public string? ValidationPattern { get; set; }

    /// <summary>
    /// "global" — applies to every user.
    /// "application" — applies only when issuing a token for the specified
    /// application. Per-application definitions extend the global set
    /// additively. Defaults to "global".
    /// </summary>
    public string Scope { get; set; } = "global";

    /// <summary>FK to the application (Object id) when <see cref="Scope"/> = "application". Null for global.</summary>
    public long? ApplicationId { get; set; }

    /// <summary>
    /// When true (default), the claim is included on the issued <c>id_token</c>.
    /// Set false to keep the claim server-side / access_token only.
    /// </summary>
    public bool EmitOnIdToken { get; set; } = true;

    /// <summary>
    /// When true (default), the claim is included on the issued <c>access_token</c>.
    /// Set false to keep the claim id_token only (useful for short-lived
    /// id-token-only client-side decode scenarios).
    /// </summary>
    public bool EmitOnAccessToken { get; set; } = true;
}
