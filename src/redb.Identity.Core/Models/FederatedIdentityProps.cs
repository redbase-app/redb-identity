using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H8 (v1.0 DoD §4): one federated identity link between a local user and an external IdP.
/// One row per (user, provider) tuple. Stored in PROPS with:
/// <list type="bullet">
///   <item><c>RedbObject.key = userId</c> — fast filter for "all my federations".</item>
///   <item><c>RedbObject.value_string = "{providerId}:{externalSub}"</c> — UNIQUE per
///   <c>_id_scheme</c>, enables O(1) reverse lookup at federated callback time.
///   Indexed by partial unique index on <c>_objects(_value_string)
///   WHERE _id_scheme = identity.federated_identity</c>.</item>
/// </list>
/// <para>
/// Replaces the legacy <see cref="UserProps.ExternalIdentities"/> dictionary which only
/// supported a single reverse-lookup key per user (the <c>UserProps.value_string</c> was
/// overwritten by the most-recently-linked provider, breaking lookup for older links).
/// <see cref="UserProps.ExternalIdentities"/> is kept as a denormalized read-model mirror
/// for backwards compatibility with code paths that already consumed it.
/// </para>
/// </summary>
[RedbScheme("identity.federated_identity")]
public class FederatedIdentityProps
{
    /// <summary>Provider id (e.g. <c>google</c>, <c>azure-ad</c>, <c>github</c>). Lowercase.</summary>
    public string ProviderId { get; set; } = string.Empty;

    /// <summary>External subject (the IdP's stable user identifier, e.g. <c>sub</c> for OIDC).</summary>
    public string ExternalSub { get; set; } = string.Empty;

    /// <summary>Email reported by the IdP at the time of the most recent login (may be null).</summary>
    public string? ExternalEmail { get; set; }

    /// <summary>Display name reported by the IdP at the time of the most recent login.</summary>
    public string? ExternalDisplayName { get; set; }

    /// <summary>UTC timestamp when the link was first established.</summary>
    public DateTimeOffset LinkedAt { get; set; }

    /// <summary>UTC timestamp of the last successful federated login through this link.</summary>
    public DateTimeOffset? LastLoginAt { get; set; }
}
