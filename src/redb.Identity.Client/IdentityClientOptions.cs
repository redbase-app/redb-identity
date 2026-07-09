namespace redb.Identity.Client;

/// <summary>
/// Configuration for <c>redb.Identity.Client</c> typed HttpClient SDK.
/// </summary>
public sealed class IdentityClientOptions
{
    /// <summary>Base URL of Identity HTTP API (e.g. https://identity.local).</summary>
    public Uri BaseUrl { get; set; } = new("https://localhost/");

    /// <summary>Optional separate base for SCIM (defaults to <see cref="BaseUrl"/> + "/scim/v2").</summary>
    public Uri? ScimBaseUrl { get; set; }

    /// <summary>Used by <c>ClientCredentialsAccessTokenProvider</c> (CLI / server-to-server).</summary>
    public string? ClientId { get; set; }

    /// <summary>Used by <c>ClientCredentialsAccessTokenProvider</c> (CLI / server-to-server).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Scopes requested by <c>ClientCredentialsAccessTokenProvider</c>.</summary>
    public string[] Scopes { get; set; } = ["identity.admin"];

    /// <summary>Per-request timeout. Default 30s.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}
