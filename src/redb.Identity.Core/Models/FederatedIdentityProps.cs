using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H8 (v1.0 DoD §4): one federated identity link between a local user and an external IdP.
/// One row per (user, provider) tuple. Stored in PROPS with:
/// <list type="bullet">
///   <item><c>RedbObject.key = userId</c> — fast filter for "all my federations".</item>
///   <item><see cref="LinkKey"/> = <c>"{providerId}:{externalSub}"</c> — unique per scheme
///   via <c>[RedbUnique]</c> (V4-UNIQUE), enables the O(1) reverse lookup at federated
///   callback time. Historical note: the doc used to claim a partial unique index on
///   <c>value_string</c> that no code ever created — duplicates were possible until Ф2
///   (doc/v4/02); <c>value_string</c> is a transition mirror now.</item>
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

    /// <summary>
    /// Reverse-lookup key <c>"{ProviderId}:{ExternalSub}"</c> — unique per scheme via
    /// <c>[RedbUnique]</c> on all three providers. Composed ONLY through
    /// <see cref="MakeLinkKey"/> so the writer and every reader agree on the format.
    /// Nullable on purpose: a pre-V4 row has no key until the transition backfill
    /// repairs it (NULL never participates in uniqueness).
    /// </summary>
    [RedbUnique]
    public string? LinkKey { get; set; }

    /// <summary>The one place the composite key format lives.</summary>
    public static string MakeLinkKey(string providerId, string externalSub)
        => $"{providerId}:{externalSub}";
}
