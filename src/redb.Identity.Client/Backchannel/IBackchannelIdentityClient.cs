using redb.Identity.Contracts.Sessions;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client.Backchannel;

/// <summary>
/// Narrow service-to-service client for the W6-0 backchannel revoked-sids API.
/// Authenticates via <c>client_credentials</c> using credentials supplied through
/// <see cref="BackchannelIdentityClientOptions"/> and is independent from the
/// user-context <see cref="IIdentityClient"/> registration.
/// </summary>
public interface IBackchannelIdentityClient
{
    /// <summary>
    /// Publish a backchannel revocation entry. At least one of <paramref name="sid"/>
    /// / <paramref name="sub"/> must be supplied.
    /// </summary>
    Task<RevokedSidEntry> AddRevokedSidAsync(
        string? sid, string? sub, string? clientId,
        DateTimeOffset? expiresAt = null,
        CancellationToken ct = default);

    /// <summary>
    /// Incremental poll. Omit <paramref name="cursor"/> for the first call (server
    /// returns a baseline window of size <c>RevokedSidsMaxRetention</c>); on
    /// subsequent calls pass <see cref="RevokedSidsSinceResponse.NextCursor"/>.
    /// </summary>
    Task<RevokedSidsSinceResponse> GetRevokedSidsSinceAsync(
        DateTimeOffset? cursor = null,
        CancellationToken ct = default);

    /// <summary>
    /// N-4 (Session C): proxy the anonymous password-recovery initiation to the Identity
    /// host. Always succeeds from the caller's perspective per the anti-enumeration
    /// contract — callers MUST NOT branch on the return value to leak account existence.
    /// </summary>
    Task<PasswordForgotResponse> ForgotPasswordAsync(
        PasswordForgotRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// N-4 (Session C): proxy the anonymous password-reset consumption to the Identity
    /// host. Returns the structured response so the BFF UI can distinguish
    /// <c>invalid_token</c> / <c>weak_password</c> / success.
    /// </summary>
    Task<PasswordResetResponse> ResetPasswordAsync(
        PasswordResetRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// N4-6: proxy the anonymous e-mail-verification confirmation to the Identity host.
    /// Returns the structured response collapsed to a generic <c>invalid_token</c> on
    /// any non-2xx outcome — mirrors <see cref="ResetPasswordAsync"/>.
    /// </summary>
    Task<EmailVerifyConfirmResponse> VerifyEmailConfirmAsync(
        EmailVerifyConfirmRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// N4-7: proxy the anonymous change-of-e-mail confirmation to the Identity host.
    /// Returns the structured response collapsed to a generic <c>invalid_token</c> on any
    /// non-2xx outcome — mirrors <see cref="VerifyEmailConfirmAsync"/>.
    /// </summary>
    Task<ChangeEmailConfirmResponse> ChangeEmailConfirmAsync(
        ChangeEmailConfirmRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// N-3 (sub-step N3-7): proxy the anonymous self-service account registration to the
    /// Identity host. Returns the structured response verbatim — unlike
    /// <see cref="ForgotPasswordAsync"/> the registration surface is NOT anti-enumeration,
    /// so failure codes (<c>duplicate</c> / <c>weak_password</c> / <c>validation_error</c> /
    /// <c>registration_disabled</c>) propagate to the caller so the UI can render actionable
    /// messages.
    /// </summary>
    Task<RegisterAccountResponse> RegisterAccountAsync(
        RegisterAccountRequest request,
        CancellationToken ct = default);
}
