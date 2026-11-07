using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace redb.Identity.Core.Services;

/// <summary>
/// The proof that the End-User, not a page they happened to visit, asked to sign out.
/// <para>
/// <c>/connect/logout</c> is the OIDC <c>end_session_endpoint</c> and works on the browser's own session
/// cookie, which a cross-site top-level navigation carries (<c>SameSite=Lax</c>): a link on any page could
/// end the visitor's OP session. A relying party proves its intent with a valid <c>id_token_hint</c> whose
/// <c>sub</c> is the session's user; a request without one gets a confirmation page instead, and the page's
/// form carries a state issued here. The state is bound to the user and the session it was shown for and
/// lives five minutes; a foreign page cannot read it (same-origin policy) nor forge it (DataProtection), so
/// presenting it is the confirmation. Same shape as Duende's logout prompt and Keycloak's confirmation
/// without <c>id_token_hint</c>.
/// </para>
/// </summary>
public sealed class LogoutConfirmationProtector
{
    private const string Purpose = "redb.identity.logout-confirmation";
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    public LogoutConfirmationProtector(IDataProtectionProvider provider, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Issues a state for the confirmation page shown to <paramref name="userId"/> in session <paramref name="sessionId"/>.</summary>
    public string Issue(long userId, long sessionId)
    {
        var state = new State(userId, sessionId, _timeProvider.GetUtcNow());
        return Convert.ToBase64String(_protector.Protect(JsonSerializer.SerializeToUtf8Bytes(state)));
    }

    /// <summary>
    /// True when <paramref name="protectedState"/> is a state this server issued for exactly this user and
    /// session, and it is not older than five minutes. Anything else — absent, altered, foreign, another
    /// session's, expired — is not a confirmation, and the caller shows the page again.
    /// </summary>
    public bool Accepts(string? protectedState, long userId, long sessionId)
    {
        if (string.IsNullOrEmpty(protectedState)) return false;

        State? state;
        try
        {
            var payload = _protector.Unprotect(Convert.FromBase64String(protectedState));
            state = JsonSerializer.Deserialize<State>(payload);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException)
        {
            // Not something this server issued: a tampered envelope, foreign bytes or a malformed value.
            // That is the answer, not a fault.
            return false;
        }

        return state is not null
            && state.UserId == userId
            && state.SessionId == sessionId
            && _timeProvider.GetUtcNow() - state.IssuedAt <= MaxAge;
    }

    private sealed record State(long UserId, long SessionId, DateTimeOffset IssuedAt);
}
