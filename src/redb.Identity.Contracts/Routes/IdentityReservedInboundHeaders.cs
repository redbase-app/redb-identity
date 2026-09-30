namespace redb.Identity.Contracts.Routes;

/// <summary>
/// Exchange header names that carry internal, server-derived state and must never arrive from a
/// caller. Every transport connector (HTTP, gRPC metadata and envelope headers, SOAP over HTTP)
/// copies the caller's headers into <c>In.Headers</c> verbatim, while Core processors trust these
/// names as if a facade processor had set them: <c>session_user_id</c> becomes the authenticated
/// principal on the authorize route, <c>user_id</c> / <c>ip_address</c> / <c>user_agent</c> /
/// <c>client_id</c> sign the audit log, <c>access_token</c> / <c>client_secret</c> feed
/// authentication. Each facade removes them as its first step, so only its own trusted processors
/// (cookie, Authorization header, body, path, method address) can populate them afterwards. The one
/// list lives here so a name added for one transport is stripped on all of them.
/// <para>
/// Deliberately NOT here: <c>operation</c>. Over HTTP it is internal (derived from the method and
/// path, so the HTTP facade strips it on its own), but on the gRPC envelope route the caller names
/// the operation in metadata by design — that transport's equivalent of a URL path.
/// </para>
/// <para>
/// Also here: <c>Set-Cookie</c>, a response header no caller has any business sending. The routes
/// answer on the request message, and the cookie writers add to whatever <c>Set-Cookie</c> is already
/// on it — so a caller's own value ended up in the same array as ours and went back out with it. The
/// transport refuses to echo a request header only while it is the untouched object the client sent,
/// and an array built around it is not.
/// </para>
/// </summary>
public static class IdentityReservedInboundHeaders
{
    public static readonly string[] Names =
    {
        "session_user_id", "session_username", "session_id", "reauth_marked_sid",
        "client_id", "client_secret", "access_token",
        "user_id", "ip_address", "user_agent",
        "Set-Cookie",
    };

    /// <summary>Removes every reserved name from <paramref name="headers"/> (case-insensitive dictionaries remove any casing).</summary>
    public static void Strip(IDictionary<string, object?> headers)
    {
        foreach (var name in Names)
            headers.Remove(name);
    }
}
