using redb.Identity.Contracts;
using redb.Route.Abstractions;

namespace redb.Identity.Management;

/// <summary>
/// What a management controller's error document means, as a status code.
/// <para>
/// The controllers answer failures with a JSON body carrying an <c>error</c> string and no status of their
/// own — the transport decides how to say "no". That decision is the same one on every transport, so it
/// lives here, in the package that owns the controllers, rather than once per facade. Two copies of this
/// table would drift, and the drift that matters is a refusal that arrives as a success.
/// </para>
/// <para>
/// The values are HTTP status codes because that is the vocabulary the rest of the codebase already
/// speaks — Core writes verdicts as <c>redbHttp.ResponseCode</c>, and each facade translates from there
/// into its own protocol. Nothing here is HTTP-specific beyond the spelling.
/// </para>
/// </summary>
public static class ManagementErrorCodes
{
    /// <summary>Maps an <c>error</c> value from a controller's error document to a status code.</summary>
    public static int ToStatusCode(string error) => error switch
    {
        "not_found" => 404,
        "duplicate" => 409,
        "validation_error" => 400,
        "invalid_request" => 400,
        "invalid_operation" => 400,
        "invalid_password" => 400,
        "weak_password" => 400,
        "registration_disabled" => 403,
        "server_error" => 500,
        _ => 400,
    };

    /// <summary>
    /// The error status already decided for an answer, or <c>null</c> when the table above should decide.
    /// <para>
    /// The table exists for one case: a controller that returned an error document, which the dispatcher
    /// then wrapped in a success status. It must not reach past that. The controller dispatcher writes its
    /// own verdict when it has one — <c>NotFound</c> 404 for a path no action matches, <c>InternalError</c>
    /// 500 for an action that threw — and so does Core, through the controller, when it states a code
    /// (a 503 during an outage, say). None of those strings are in the table, so a mapper that consulted it
    /// anyway turned every one into 400: a missing route told the caller their request was malformed, and
    /// an exception in our own code reached the client as the client's fault. <see cref="IdentityVerdict"/>
    /// has always said it the other way round — the status wins where there is one, and the error document
    /// is read only when nobody stated a code.
    /// </para>
    /// <para>
    /// Read from the two headers the dispatchers write: <c>redbHttp.ResponseCode</c> (the HTTP dispatcher,
    /// and Core through the controller) and <c>status.code</c> (every controller dispatcher, gRPC
    /// included, which writes nothing else).
    /// </para>
    /// </summary>
    public static int? DecidedErrorStatus(IMessage answer)
    {
        ArgumentNullException.ThrowIfNull(answer);

        foreach (var header in DecidingHeaders)
        {
            if (answer.Headers.TryGetValue(header, out var raw)
                && IdentityVerdict.ParseResponseCode(raw) is >= 400 and var code)
            {
                return code;
            }
        }

        return null;
    }

    private static readonly string[] DecidingHeaders = ["redbHttp.ResponseCode", "status.code"];
}
