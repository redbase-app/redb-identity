namespace redb.Identity.Contracts.Federation;

/// <summary>
/// H8 (DoD §4 gap (b)): one entry returned by <c>GET /me/federated-identities</c>.
/// </summary>
public sealed class FederatedIdentityResponse
{
    /// <summary>Provider id (e.g. <c>google</c>).</summary>
    public required string ProviderId { get; init; }

    /// <summary>External subject reported by the IdP. May be useful to the user (e.g.
    /// to identify which Google account is linked when they have several).</summary>
    public required string ExternalSub { get; init; }

    /// <summary>Email associated with the external identity at the time of the most recent
    /// successful login through this link, if the IdP exposed it.</summary>
    public string? ExternalEmail { get; init; }

    /// <summary>Display name from the external IdP (e.g. <c>Иван Иванов</c>), if available.</summary>
    public string? ExternalDisplayName { get; init; }

    /// <summary>UTC timestamp when the link was first established.</summary>
    public required DateTimeOffset LinkedAt { get; init; }

    /// <summary>UTC timestamp of the last successful login through this link.</summary>
    public DateTimeOffset? LastLoginAt { get; init; }
}

/// <summary>
/// H8 (DoD §4 gap (b)): self-service request to start a "link this provider to my
/// existing account" flow. Returns a redirect URL the front-end opens in a browser
/// window. The callback (sharing the same /federation/callback URI) interprets the
/// embedded encrypted state's <c>LinkUserId</c> and links instead of logging in.
/// </summary>
public sealed class LinkFederatedIdentityRequest
{
    /// <summary>Provider id to start the link flow for. Must match a registered provider.</summary>
    public required string ProviderId { get; init; }

    /// <summary>Optional return URL to redirect the user to after the link succeeds.</summary>
    public string? ReturnUrl { get; init; }
}

/// <summary>H8: response from <c>POST /me/federated-identities/link-challenge</c>.</summary>
public sealed class LinkFederatedIdentityChallengeResponse
{
    /// <summary>The URL the front-end must navigate to in order to start the OIDC dance.</summary>
    public required string RedirectUri { get; init; }
}
