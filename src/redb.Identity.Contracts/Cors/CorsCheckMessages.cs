namespace redb.Identity.Contracts.Cors;

/// <summary>
/// Phase 9d cross-context request DTO for <c>direct-vm://identity-cors-check</c>.
/// HTTP transport facade asks Core «is this browser <c>Origin</c> allowed for CORS?».
/// Carried as <see cref="System.Collections.Generic.IDictionary{TKey,TValue}"/> on the
/// wire so the Route message body stays JSON-friendly.
/// </summary>
public sealed class CorsCheckRequest
{
    /// <summary>Browser-supplied <c>Origin</c> request header value (raw, unnormalised).</summary>
    public string? Origin { get; set; }
}

/// <summary>
/// Reply DTO for <c>direct-vm://identity-cors-check</c>.
/// </summary>
public sealed class CorsCheckResponse
{
    /// <summary>True when <see cref="CorsCheckRequest.Origin"/> matches a registered client.</summary>
    public bool Allowed { get; set; }
}
