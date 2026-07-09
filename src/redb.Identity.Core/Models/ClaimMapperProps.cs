using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H5 (v1.0 DoD §5): PROPS Props for a declarative claim-mapping rule emitted into OAuth/OIDC tokens.
/// <para>
/// One rule produces one claim. A rule belongs to one of three scopes, expressed by
/// <c>parent_id</c> on the underlying object:
/// <list type="bullet">
///   <item><b>parent_id IS NULL</b> — global rule, applied to every token.</item>
///   <item><b>parent_id = ApplicationObjectId</b> — per-application overlay rule, applied
///   only to tokens issued for that client.</item>
///   <item><b>parent_id = ClaimScopeObjectId</b> — rule belongs to a reusable Client Scope
///   (see <see cref="ClaimScopeProps"/>); applies to tokens issued for any Application
///   that has the scope assigned (see <see cref="ClaimScopeAssignmentProps"/>).</item>
/// </list>
/// </para>
/// <para>
/// Resolution model is similar to Keycloak Token Mappers (per-client + Client Scope mappers)
/// and WSO2IS Claim Configuration (per-Service-Provider claim selection over a global Dialect).
/// Per-rule destinations make application uniform across <c>access_token</c>, <c>id_token</c>
/// and the userinfo endpoint.
/// </para>
/// Base fields used: <c>name</c> = administrator-facing label (unique only within scope),
/// <c>parent_id</c> = scope discriminator (see above).
/// </summary>
[RedbScheme("identity.claim_mapper")]
public class ClaimMapperProps
{
    /// <summary>
    /// Name of the claim emitted into the token (e.g. <c>"department"</c>, <c>"tenant_id"</c>).
    /// MUST be a non-empty token-safe identifier — handlers reject empty / whitespace values
    /// at apply-time so tokens never contain a nameless claim.
    /// </summary>
    public string? ClaimType { get; set; }

    /// <summary>
    /// Source of the value. One of:
    /// <list type="bullet">
    ///   <item><c>UserProps</c> — read from <see cref="SourcePath"/> against the user's
    ///   <see cref="UserProps"/> object. Supports nested dot-path
    ///   (e.g. <c>"GivenName"</c>, <c>"Address.Country"</c>).</item>
    ///   <item><c>CustomClaim</c> — read from <see cref="UserProps.CustomClaims"/> dictionary;
    ///   <see cref="SourcePath"/> is the dictionary key.</item>
    ///   <item><c>Constant</c> — emit <see cref="ConstantValue"/> verbatim. Use for
    ///   environment / audience tags.</item>
    /// </list>
    /// </summary>
    public string? SourceKind { get; set; }

    /// <summary>
    /// Path / key into the source. Dot-notation for <c>UserProps</c>, dictionary key for
    /// <c>CustomClaim</c>. Ignored for <c>Constant</c>.
    /// </summary>
    public string? SourcePath { get; set; }

    /// <summary>
    /// Value emitted when <see cref="SourceKind"/> = <c>Constant</c>. Ignored otherwise.
    /// </summary>
    public string? ConstantValue { get; set; }

    /// <summary>
    /// Required OAuth scopes for this mapper to fire (subset semantics: ALL must be present
    /// in the requested scopes). Empty / null = no scope filter (mapper always runs).
    /// </summary>
    public string[]? RequiredScopes { get; set; }

    /// <summary>
    /// Token destinations for the emitted claim. Valid values per OpenIddict:
    /// <c>access_token</c>, <c>id_token</c>. Empty / null defaults to both.
    /// The userinfo endpoint independently re-emits all non-standard claims found in the
    /// principal (see <see cref="OpenIddict.Handlers.AttachAdditionalUserinfoClaims"/>),
    /// so any mapper that targets <c>id_token</c> implicitly appears in userinfo as well.
    /// </summary>
    public string[]? Destinations { get; set; }

    /// <summary>
    /// When <c>true</c>, a missing / null source value causes token issuance to fail with
    /// <c>invalid_request</c>. When <c>false</c> (default), missing values cause silent skip.
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// Application order (ascending). When two mappers target the same <see cref="ClaimType"/>,
    /// the LAST one wins (stable Last-Write semantics). Defaults to 0.
    /// </summary>
    public int Order { get; set; }

    /// <summary>
    /// When <c>false</c>, the mapper is loaded but skipped at apply-time. Allows soft-disable
    /// without DELETE for incident response.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Free-form admin description.</summary>
    public string? Description { get; set; }
}
