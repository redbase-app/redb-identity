namespace redb.Identity.Contracts.Tokens;

/// <summary>
/// Administrative token info (for management endpoint, not OAuth flow).
/// </summary>
public class TokenInfoResponse
{
    public long Id { get; set; }
    public long ApplicationObjectId { get; set; }

    /// <summary>OIDC public sub claim (GUID) of the token's owning user.</summary>
    public string? Subject { get; set; }

    /// <summary>Numeric user id resolved from <see cref="Subject"/>. Populated by the
    /// admin list path for table rendering. Null when reverse lookup fails.</summary>
    public long? SubjectUserId { get; set; }

    /// <summary>Login of the token's owning user, resolved by the admin list path.</summary>
    public string? SubjectLogin { get; set; }

    /// <summary>OAuth client_id of the application the token was issued to.</summary>
    public string? ClientId { get; set; }

    /// <summary>Display name of the application the token was issued to.</summary>
    public string? ApplicationName { get; set; }

    public string? Status { get; set; }
    public string? Type { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Token expiration timestamp (_objects.date_complete).</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
}
