using System.Globalization;

namespace redb.Identity.Contracts;

/// <summary>
/// What the identity core decided about a request, said once in a form no transport owns.
/// <para>
/// Every facade has to answer the same question — was this refused, and why — in its own vocabulary:
/// HTTP with a status code, gRPC with a status, SOAP with a fault. The vocabularies cannot be shared;
/// the <em>reading</em> can, and it is the reading that kept being copied. Each facade maps
/// <see cref="IdentityVerdictKind"/> onto its own names with a switch of a few lines, and nothing else.
/// </para>
/// </summary>
public enum IdentityVerdictKind
{
    /// <summary>The request succeeded.</summary>
    Ok,

    /// <summary>The request is malformed, or asks for something that makes no sense.</summary>
    BadRequest,

    /// <summary>The caller could not be authenticated, or the credentials presented were refused.</summary>
    Unauthenticated,

    /// <summary>The caller is known but not allowed to do this.</summary>
    Forbidden,

    /// <summary>The thing addressed does not exist.</summary>
    NotFound,

    /// <summary>The operation is not supported here.</summary>
    Unsupported,

    /// <summary>The change conflicts with what already exists.</summary>
    Conflict,

    /// <summary>A precondition the caller stated does not hold.</summary>
    PreconditionFailed,

    /// <summary>The caller is sending too much, too fast, and should come back later.</summary>
    RateLimited,

    /// <summary>The scope asked for is not one this caller may have.</summary>
    InvalidScope,

    /// <summary>We are temporarily unable to serve this.</summary>
    Unavailable,

    /// <summary>The deadline passed before an answer was ready.</summary>
    Timeout,

    /// <summary>Our side failed.</summary>
    ServerError,

    /// <summary>
    /// Something was refused, and nothing in the answer says what kind of refusal it was. Kept distinct
    /// from <see cref="ServerError"/> on purpose: claiming our own failure for an outcome we cannot read
    /// is a guess, and a caller acts differently on «we broke» than on «we do not know».
    /// </summary>
    Unknown,
}

/// <summary>
/// Reads the identity core's verdict out of an answer.
/// <para>
/// Core states its verdict as an HTTP status code on <c>redbHttp.ResponseCode</c>, on every transport,
/// because that is the vocabulary its own processors speak. The OAuth <c>error</c> value in the body is
/// the second source and the weaker one: it is defined by RFC 6749, and Core answers plenty of things
/// that RFC never named. <c>rate_limited</c> is the standing example — read from the error string alone
/// it falls through to «bad request», which tells a caller to fix their request when what they must do
/// is wait.
/// </para>
/// <para>
/// This type holds no route, no exchange and no transport type on purpose: <c>redb.Identity.Contracts</c>
/// is dependency-free, and a facade passes in the two values it already has.
/// </para>
/// </summary>
public static class IdentityVerdict
{
    /// <summary>Header Core states its verdict on, the same on every transport.</summary>
    public const string ResponseCodeHeader = "redbHttp.ResponseCode";

    /// <summary>Header carrying how long to wait before retrying a rate-limited call.</summary>
    public const string RetryAfterHeader = "Retry-After";

    /// <summary>
    /// Parses a <c>redbHttp.ResponseCode</c> header value. Returns null when the header is absent or is
    /// not a number, which are the same thing to a caller: Core stated nothing.
    /// </summary>
    public static int? ParseResponseCode(object? rawHeaderValue)
    {
        var text = rawHeaderValue?.ToString();
        if (string.IsNullOrWhiteSpace(text)) return null;

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code)
            ? code
            : null;
    }

    /// <summary>
    /// The verdict for a request, given what the answer carried. The status code wins where there is
    /// one; the OAuth error is consulted only when Core stated no code.
    /// </summary>
    /// <param name="responseCode">Value of <see cref="ResponseCodeHeader"/>, already parsed, or null.</param>
    /// <param name="oauthError">The <c>error</c> value from the answer body, or null.</param>
    public static IdentityVerdictKind Resolve(int? responseCode, string? oauthError)
    {
        if (responseCode is { } code)
        {
            var fromCode = FromStatusCode(code);

            // A 2xx alongside an error document is contradictory, and the error document is the one that
            // says a refusal happened. Falling through to the error keeps such an answer a refusal
            // instead of a success carrying an explanation nobody reads.
            if (fromCode != IdentityVerdictKind.Ok || string.IsNullOrEmpty(oauthError))
                return fromCode;
        }

        return string.IsNullOrEmpty(oauthError)
            ? IdentityVerdictKind.Ok
            : FromOAuthError(oauthError!);
    }

    /// <summary>The verdict an HTTP status code states.</summary>
    public static IdentityVerdictKind FromStatusCode(int code) => code switch
    {
        >= 200 and <= 299 => IdentityVerdictKind.Ok,
        400 or 422 => IdentityVerdictKind.BadRequest,
        401 => IdentityVerdictKind.Unauthenticated,
        403 => IdentityVerdictKind.Forbidden,
        404 => IdentityVerdictKind.NotFound,
        405 or 501 => IdentityVerdictKind.Unsupported,
        409 => IdentityVerdictKind.Conflict,
        412 or 428 => IdentityVerdictKind.PreconditionFailed,
        429 => IdentityVerdictKind.RateLimited,
        503 => IdentityVerdictKind.Unavailable,
        504 => IdentityVerdictKind.Timeout,
        >= 500 => IdentityVerdictKind.ServerError,

        // A code outside every band above says a refusal happened and nothing more. Reading it as a bad
        // request would tell the caller to fix something we never claimed was wrong.
        _ => IdentityVerdictKind.Unknown,
    };

    /// <summary>
    /// The verdict an OAuth error value states, per RFC 6749 §5.2 and RFC 6750 §3.1.
    /// <para>
    /// This is the reading the HTTP and gRPC facades already applied, moved here rather than rewritten:
    /// the point of this type is that the three transports agree, and «agree» means on what shipped, not
    /// on a fresh opinion. RFC 6749 answers most of these with 400, so anything not named below is a
    /// defect in the request — the reading that keeps an unknown error visible instead of reporting it
    /// as our own failure.
    /// </para>
    /// <para>
    /// This path runs only when Core stated no status code. Where Core did state one it is the code that
    /// decides, and that is what keeps <c>rate_limited</c> — a value no RFC names — from reading as a
    /// malformed request.
    /// </para>
    /// </summary>
    public static IdentityVerdictKind FromOAuthError(string error) => error switch
    {
        "" => IdentityVerdictKind.Ok,

        "invalid_client" or "invalid_token" => IdentityVerdictKind.Unauthenticated,

        "access_denied" or "unauthorized_client" => IdentityVerdictKind.Forbidden,

        // Named separately from the generic bad request because WS-Trust has a fault for exactly this
        // and would otherwise lose it. Transports without one render it as they render a bad request,
        // which is what they did before this type existed.
        "invalid_scope" or "insufficient_scope" => IdentityVerdictKind.InvalidScope,

        "server_error" => IdentityVerdictKind.ServerError,
        "temporarily_unavailable" => IdentityVerdictKind.Unavailable,

        _ => IdentityVerdictKind.BadRequest,
    };

    /// <summary>Whether this verdict means the request was refused.</summary>
    public static bool IsRefusal(this IdentityVerdictKind kind) => kind != IdentityVerdictKind.Ok;
}
