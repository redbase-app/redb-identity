using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS entity tracking user login sessions.
/// Key = userId (subject). Each record represents one login event.
/// Revoking a session cascades to revoking all authorizations and tokens for that user.
/// </summary>
[RedbScheme("identity.session")]
public class SessionProps
{
    /// <summary>FK to the application (client) the user logged into.</summary>
    public long ApplicationObjectId { get; set; }

    /// <summary>"active" or "revoked".</summary>
    public string? Status { get; set; }

    /// <summary>Whether session was established with MFA verification.</summary>
    public bool MfaVerified { get; set; }

    /// <summary>MFA method used (totp, recovery). Null if no MFA.</summary>
    public string? MfaMethod { get; set; }

    /// <summary>
    /// Client IP address captured from the authenticating request (<c>redbHttp.RemoteAddress</c>,
    /// sanitized through <c>TrustedProxyResolverProcessor</c> when the hop is whitelisted).
    /// Surfaced in <c>GET /me/sessions</c> so the user can recognize their devices.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>Raw <c>User-Agent</c> header captured at login time. May be <c>null</c> for non-HTTP transports.</summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Human-friendly device label derived from <see cref="UserAgent"/> (e.g. "Chrome 135 on Windows 10"),
    /// parsed at login time. Displayed in the self-service sessions list UI.
    /// </summary>
    public string? DeviceLabel { get; set; }

    /// <summary>
    /// S-track: last time this session was used. Updated on every activity that
    /// proves the session is still in use — refresh_token grant, cookie
    /// validation, /connect/userinfo call. Drives idle-timeout expiration:
    /// (now - LastAccessedAt) &gt; RedbIdentityOptions.SessionIdleTimeout →
    /// auto-revoked. Mirrors industry pattern (Keycloak, Auth0, Okta).
    /// Null on legacy rows created before this field landed.
    /// </summary>
    public DateTimeOffset? LastAccessedAt { get; set; }

    /// <summary>
    /// S-track: label of the most recent activity that bumped
    /// <see cref="LastAccessedAt"/> — "refresh_token", "cookie", "userinfo",
    /// "introspect". Diagnostic only; the timeout calculation cares only about
    /// the timestamp.
    /// </summary>
    public string? LastAccessedBy { get; set; }
}
