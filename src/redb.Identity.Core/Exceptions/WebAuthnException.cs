namespace redb.Identity.Core.Exceptions;

/// <summary>
/// MFA-3: thrown by <see cref="Services.IWebAuthnMfaMethod"/> when a WebAuthn ceremony fails
/// for a reason that the caller (a processor) needs to surface as a structured client error
/// rather than a 500. Each instance carries a short, stable <see cref="ErrorCode"/> suitable
/// for inclusion in the JSON response (<c>{"error":"uv_downgrade", ...}</c>).
/// </summary>
public sealed class WebAuthnException : Exception
{
    public WebAuthnException(string errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }

    public WebAuthnException(string errorCode, string message, Exception inner) : base(message, inner)
    {
        ErrorCode = errorCode;
    }

    /// <summary>Short, stable identifier (e.g. <c>uv_downgrade</c>, <c>sign_counter_rollback</c>).</summary>
    public string ErrorCode { get; }
}
