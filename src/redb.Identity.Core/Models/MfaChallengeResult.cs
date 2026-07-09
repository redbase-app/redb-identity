namespace redb.Identity.Core.Models;

/// <summary>
/// Result of <see cref="Services.MfaService.CreateChallengeAsync"/>.
/// On success: returns the new encrypted state (with embedded OTP) and masked destination for UI.
/// On failure: returns error code (e.g. "rate_limited", "delivery_failed", "method_not_configured").
/// </summary>
public sealed class MfaChallengeResult
{
    public bool Success { get; init; }

    /// <summary>New encrypted MFA state to use for the verify step. Null on failure.</summary>
    public string? MfaState { get; init; }

    /// <summary>Masked destination for UI (e.g. "+7***1234"). Null on failure.</summary>
    public string? MaskedDestination { get; init; }

    /// <summary>Method that issued the challenge ("sms" or "email"). Null on failure.</summary>
    public string? Method { get; init; }

    /// <summary>Seconds until next challenge can be requested (rate limit).</summary>
    public int? RetryAfterSeconds { get; init; }

    /// <summary>Error code on failure: "rate_limited", "delivery_failed", "method_not_configured", "no_channel".</summary>
    public string? Error { get; init; }

    public static MfaChallengeResult Failed(string error, int? retryAfter = null) =>
        new() { Success = false, Error = error, RetryAfterSeconds = retryAfter };

    public static MfaChallengeResult Ok(string method, string mfaState, string maskedDestination) =>
        new() { Success = true, Method = method, MfaState = mfaState, MaskedDestination = maskedDestination };
}
