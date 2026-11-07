namespace redb.Identity.Contracts.Endpoints;

/// <summary>
/// Phase 9d cross-context request DTO for <c>direct-vm://identity-validate-post-logout</c>.
/// HTTP <c>/connect/logout</c> processor needs to ensure an unauthenticated logout request
/// (no id_token_hint, expired session) does not redirect to an arbitrary URL — open-redirect
/// protection per RFC 8414 §4. Core scans <c>OpenIddictApplications.PostLogoutRedirectUris</c>
/// for any registered URI matching the supplied value.
/// </summary>
public sealed class ValidatePostLogoutRedirectRequest
{
    /// <summary>The <c>post_logout_redirect_uri</c> to validate. Null/empty returns false.</summary>
    public string? RedirectUri { get; set; }
}

/// <summary>
/// Reply DTO for <c>direct-vm://identity-validate-post-logout</c>.
/// </summary>
public sealed class ValidatePostLogoutRedirectResponse
{
    /// <summary>True when at least one registered application has the URI as a post-logout target.</summary>
    public bool Allowed { get; set; }
}
