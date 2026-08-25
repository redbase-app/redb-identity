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
}
