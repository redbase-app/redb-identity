namespace redb.Identity.Contracts.Configuration;

/// <summary>
/// Cross-module feature toggles for the Identity product surface.
/// <para>
/// Lives in <c>redb.Identity.Contracts</c> so that both <c>redb.Identity.Core</c>
/// (which gates DI registration, OpenIddict configuration, and <c>direct-vm://</c>
/// route registration on these flags) and <c>redb.Identity.Http</c> (which gates
/// HTTP endpoint mounting on the same flags) read from a single shared contract.
/// </para>
/// <para>
/// Configuration source: a single section <c>Identity:Features:*</c> in
/// <c>context.json</c>. Both module binders (<c>IdentityModuleConfigBinder</c> and
/// <c>IdentityHttpConfigBinder</c>) bind their own <c>IOptions&lt;IdentityFeatureFlags&gt;</c>
/// instance from the same path, so a flag set once is observed identically by both
/// modules — eliminating the previous Core/Http duplication smell.
/// </para>
/// <para>
/// Architectural invariant: <c>installed ⇔ exposed</c>. If a feature is enabled the
/// Core registers everything required to serve it (DI services, direct-vm routes,
/// OpenIddict capabilities) AND the Http facade mounts the corresponding endpoints.
/// This avoids the broken state where Core ran without HTTP exposure (or vice versa)
/// because the two flag families had drifted.
/// </para>
/// </summary>
public sealed class IdentityFeatureFlags
{
    /// <summary>
    /// SCIM 2.0 provisioning surface (RFC 7643/7644). When <c>true</c>:
    /// Core registers SCIM mapper services + <c>direct-vm://identity-scim-*</c> routes;
    /// Http mounts <c>/scim/v2/Users</c> and <c>/scim/v2/Groups</c>. Default: <c>false</c>.
    /// </summary>
    public bool EnableScim { get; set; }

    /// <summary>
    /// SCIM <c>/Bulk</c> endpoint (RFC 7644 §3.7). Has no effect unless
    /// <see cref="EnableScim"/> is also <c>true</c>. When <c>true</c>: Core registers the
    /// bulk dispatcher direct-vm route; Http mounts <c>/scim/v2/Bulk</c>. Default: <c>false</c>.
    /// </summary>
    public bool EnableScimBulk { get; set; }

    /// <summary>
    /// External federated identity providers (Google / Microsoft / Keycloak / GitHub etc).
    /// When <c>true</c> AND at least one provider is configured: Core advertises
    /// <c>acr_values_supported</c> in discovery + registers federation handlers;
    /// Http mounts the federation login + callback routes. Default: <c>false</c>.
    /// </summary>
    public bool EnableFederation { get; set; }

    /// <summary>
    /// OAuth 2.0 Dynamic Client Registration (RFC 7591) and management protocol (RFC 7592).
    /// When <c>true</c>: Core registers DCR services + <c>direct-vm://identity-dcr-*</c>
    /// routes; Http mounts <c>/connect/register</c> + per-client management endpoints.
    /// Default: <c>false</c>.
    /// </summary>
    public bool EnableDynamicRegistration { get; set; }

    /// <summary>
    /// OAuth 2.0 Pushed Authorization Requests (RFC 9126). When <c>true</c>: Core enables
    /// the OpenIddict PAR pipeline + <c>direct-vm://identity-par</c>; Http mounts
    /// <c>/connect/par</c>. Default: <c>false</c>.
    /// </summary>
    public bool EnablePushedAuthorization { get; set; }

    /// <summary>
    /// OAuth 2.0 Device Authorization Grant (RFC 8628). When <c>true</c>: Core configures
    /// OpenIddict to allow the device flow + registers the device-code direct-vm routes;
    /// Http mounts <c>/connect/deviceauthorization</c> and <c>/connect/device/verify</c>.
    /// Default: <c>false</c>.
    /// </summary>
    public bool EnableDeviceCodeFlow { get; set; }
}
