using System.Text.Json;
using System.Text.Json.Serialization;
using redb.Identity.Contracts.Serialization;
using redb.Route.Abstractions;
using redb.Route.Serialization;

namespace redb.Identity.Core.Serialization;

/// <summary>
/// Route-framework-bound view over the locked Identity wire profiles defined in
/// <see cref="IdentityWireProfiles"/> (Contracts). Wraps each profile in an
/// <see cref="IMessageSerializer"/> singleton and exposes
/// <see cref="RegisterInto(IDataFormatRegistry)"/> for the route data-format registry.
/// <para>
/// Transport facades that don't link Core (HTTP, gRPC, …) consume the raw
/// <see cref="JsonSerializerOptions"/> from <see cref="IdentityWireProfiles"/> directly.
/// Core processors and the route registry consume the serializer instances below.
/// </para>
/// </summary>
public static class IdentityCodecProfiles
{
    // ── Re-exports of locked Contracts media types (kept for back-compat call sites) ──

    /// <summary>SCIM 2.0 protocol media type — RFC 7644 §3. Re-export of <see cref="IdentityWireProfiles.ScimMediaType"/>.</summary>
    public const string ScimMediaType = IdentityWireProfiles.ScimMediaType;

    /// <summary>Problem Details media type — RFC 9457 §3. Re-export of <see cref="IdentityWireProfiles.ProblemMediaType"/>.</summary>
    public const string ProblemMediaType = IdentityWireProfiles.ProblemMediaType;

    /// <summary>OAuth / OIDC JSON media type — RFC 6749 §5.1. Re-export of <see cref="IdentityWireProfiles.OAuthMediaType"/>.</summary>
    public const string OAuthMediaType = IdentityWireProfiles.OAuthMediaType;

    // ── Re-exports of locked Contracts options (kept for in-Core call sites) ──

    /// <summary>SCIM response options. Re-export of <see cref="IdentityWireProfiles.ScimOptions"/>.</summary>
    public static JsonSerializerOptions ScimOptions => IdentityWireProfiles.ScimOptions;

    /// <summary>Problem Details response options. Re-export of <see cref="IdentityWireProfiles.ProblemOptions"/>.</summary>
    public static JsonSerializerOptions ProblemOptions => IdentityWireProfiles.ProblemOptions;

    /// <summary>OAuth / OIDC / DCR response options. Re-export of <see cref="IdentityWireProfiles.OAuthOptions"/>.</summary>
    public static JsonSerializerOptions OAuthOptions => IdentityWireProfiles.OAuthOptions;

    // ── IMessageSerializer-typed profile singletons ──────────────────────────

    /// <summary>Serializer instance for SCIM responses (<see cref="ScimMediaType"/>). Thread-safe singleton.</summary>
    public static readonly IMessageSerializer Scim =
        new JsonMessageSerializer(IdentityWireProfiles.ScimOptions, ScimMediaType, new[] { ScimMediaType });

    /// <summary>Serializer instance for Problem Details responses (<see cref="ProblemMediaType"/>). Thread-safe singleton.</summary>
    public static readonly IMessageSerializer Problem =
        new JsonMessageSerializer(IdentityWireProfiles.ProblemOptions, ProblemMediaType, new[] { ProblemMediaType });

    /// <summary>
    /// Serializer instance for OAuth / OIDC / DCR responses.
    /// <para>
    /// <b>Not</b> registered into <see cref="IDataFormatRegistry"/> by
    /// <see cref="RegisterInto(IDataFormatRegistry)"/> — OAuth/OIDC/DCR processors invoke
    /// this directly so an application-level reconfiguration of the generic
    /// <c>application/json</c> codec cannot reshape the OAuth wire format.
    /// </para>
    /// </summary>
    public static readonly IMessageSerializer OAuthJson =
        new JsonMessageSerializer(IdentityWireProfiles.OAuthOptions, OAuthMediaType, new[] { OAuthMediaType });

    /// <summary>
    /// Registers the media-type-addressable Identity profiles into the supplied
    /// route-context registry. Call site: <c>IdentityCodecProfilesConfigurator.Configure</c>.
    /// </summary>
    public static void RegisterInto(IDataFormatRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        registry.Register(ScimMediaType, Scim);
        registry.RegisterProfile("scim", Scim);

        registry.Register(ProblemMediaType, Problem);
        registry.RegisterProfile("problem", Problem);
    }
}
