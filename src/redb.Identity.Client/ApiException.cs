using System.Net;

namespace redb.Identity.Client;

/// <summary>
/// Thrown by Identity client methods when the server returns a non-success HTTP status.
/// Carries the status code, parsed RFC 7807 problem details (when available) and the raw body.
/// </summary>
public sealed class ApiException : Exception
{
    public HttpStatusCode StatusCode { get; }
    public ProblemDetails? ProblemDetails { get; }
    public string? RawBody { get; }

    public ApiException(
        HttpStatusCode statusCode,
        string message,
        ProblemDetails? problemDetails = null,
        string? rawBody = null,
        Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
        ProblemDetails = problemDetails;
        RawBody = rawBody;
    }
}

/// <summary>RFC 7807 problem details (incl. ASP.NET <c>ValidationProblemDetails.errors</c>).</summary>
public sealed class ProblemDetails
{
    public string? Type { get; set; }
    public string? Title { get; set; }
    public int? Status { get; set; }
    public string? Detail { get; set; }
    public string? Instance { get; set; }

    /// <summary>Per-field validation errors (for ASP.NET <c>ValidationProblemDetails</c>).</summary>
    public Dictionary<string, string[]>? Errors { get; set; }

    /// <summary>RFC 7807 extension members (e.g. trace_id, correlation_id).</summary>
    public Dictionary<string, object>? Extensions { get; set; }
}
