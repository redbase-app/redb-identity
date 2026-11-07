using Microsoft.Extensions.Logging;

namespace redb.Identity.Core.Security;

/// <summary>
/// E5 — security-event logging channel. All audit/security-sensitive events
/// (login denial, MFA lockout, rate-limit breach, RBAC rejection) should be
/// routed to the <c>RedbIdentity.Security</c> logger category so operators
/// can surface them to a dedicated sink (SIEM / audit pipeline) without
/// interleaving with routine operational logs.
/// </summary>
public static class IdentitySecurityLog
{
    /// <summary>
    /// Logger category used for all security-sensitive events in redb.Identity.
    /// Keep stable: downstream log-routing rules key off this string.
    /// </summary>
    public const string CategoryName = "RedbIdentity.Security";

    /// <summary>
    /// Creates a security-channel logger from the given factory. Callers that
    /// already hold an <see cref="ILoggerFactory"/> should call this helper
    /// rather than hand-formatting the category string.
    /// </summary>
    public static ILogger CreateLogger(ILoggerFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        return factory.CreateLogger(CategoryName);
    }
}
