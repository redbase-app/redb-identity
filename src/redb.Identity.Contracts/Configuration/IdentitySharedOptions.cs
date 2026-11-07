namespace redb.Identity.Contracts.Configuration;

/// <summary>
/// Cross-module shared options for the Identity product surface.
/// <para>
/// Lives in <c>redb.Identity.Contracts</c> so that both
/// <see cref="redb.Identity.Contracts.Configuration.IdentityFeatureFlags"/>-aware
/// modules — <c>redb.Identity.Core</c> (which gates DI registration, OpenIddict
/// configuration, and <c>direct-vm://</c> route registration on shared values)
/// and <c>redb.Identity.Http</c> (which formats discovery URIs, drives cookie
/// <c>Secure</c> detection, and gates HTTP endpoint mounting) — read from a
/// single shared contract.
/// </para>
/// <para>
/// Configuration source: a single section <c>Identity:*</c> in <c>context.json</c>.
/// Both module binders (<c>IdentityModuleConfigBinder</c> and
/// <c>IdentityHttpConfigBinder</c>) bind their own
/// <c>IOptions&lt;IdentitySharedOptions&gt;</c> from the same path, so a value
/// set once is observed identically by both modules — eliminating the
/// Core/Http duplication smell for both <see cref="Issuer"/> and
/// <see cref="Features"/> in one shared root.
/// </para>
/// <para>
/// Both <c>RedbIdentityOptions.Shared</c> (Core) and
/// <c>IdentityTransportOptions.Shared</c> (Http) reference an instance of this
/// type; in-process test fixtures that need exact alignment can simply assign
/// <c>transportOptions.Shared = identityOptions.Shared</c> instead of mirroring
/// individual properties one by one.
/// </para>
/// </summary>
public sealed class IdentitySharedOptions
{
    /// <summary>
    /// Issuer URI for the identity server. Used by Core for OpenIddict
    /// <c>SetIssuer</c> + <c>id_token</c> validation, and by Http for
    /// discovery-document URL formatting (issuer, registration_endpoint, etc.)
    /// + cookie <c>Secure</c> flag detection (https ⇒ Secure cookies).
    /// Required for production; defaults to <c>https://localhost/</c>.
    /// </summary>
    public System.Uri Issuer { get; set; } = new("https://localhost/");

    /// <summary>
    /// Cross-module feature toggles. Single source of truth for both Core
    /// (DI registration, OpenIddict configuration, direct-vm route
    /// registration) and Http (HTTP endpoint mounting). Bound from the
    /// <c>Identity:Features:*</c> section of <c>context.json</c>.
    /// </summary>
    public IdentityFeatureFlags Features { get; set; } = new();
}
