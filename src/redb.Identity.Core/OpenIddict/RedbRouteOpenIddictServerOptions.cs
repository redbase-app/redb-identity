namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Configuration options for the redb.Route OpenIddict Server host adapter.
/// </summary>
public sealed class RedbRouteOpenIddictServerOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether the transport security requirement
    /// (HTTPS) should be disabled. Default is <c>false</c>.
    /// </summary>
    public bool DisableTransportSecurityRequirement { get; set; }
}
