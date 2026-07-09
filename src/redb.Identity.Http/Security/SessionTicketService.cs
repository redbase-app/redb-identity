using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace redb.Identity.Http.Security;

/// <summary>
/// Encrypts/decrypts session tickets using ASP.NET DataProtection.
/// A session ticket is a compact encrypted blob containing the user ID, session ID, and username.
/// Cookie-based: self-contained, no DB lookup on every request (except revocation check).
/// </summary>
public sealed class SessionTicketService
{
    private const string Purpose = "redb.identity.session";
    private const byte Version1 = 1;
    private const byte Version2 = 2;

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SessionTicketService>? _logger;

    public SessionTicketService(IDataProtectionProvider provider)
        : this(provider, TimeProvider.System, null)
    {
    }

    public SessionTicketService(IDataProtectionProvider provider, TimeProvider? timeProvider)
        : this(provider, timeProvider, null)
    {
    }

    public SessionTicketService(
        IDataProtectionProvider provider,
        TimeProvider? timeProvider,
        ILogger<SessionTicketService>? logger)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    /// <summary>
    /// Creates an encrypted session ticket for the given user and session.
    /// Format v2: [version:1][userId:8][sessionId:8][issuedUtcTicks:8][usernameUtf8:rest]
    /// </summary>
    public string Protect(long userId, long sessionId, string username)
    {
        ArgumentNullException.ThrowIfNull(username);

        var usernameBytes = System.Text.Encoding.UTF8.GetBytes(username);
        var payload = new byte[1 + 8 + 8 + 8 + usernameBytes.Length];

        payload[0] = Version2;
        BitConverter.TryWriteBytes(payload.AsSpan(1, 8), userId);
        BitConverter.TryWriteBytes(payload.AsSpan(9, 8), sessionId);
        BitConverter.TryWriteBytes(payload.AsSpan(17, 8), _timeProvider.GetUtcNow().UtcTicks);
        usernameBytes.CopyTo(payload.AsSpan(25));

        var encrypted = _protector.Protect(payload);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Decrypts a session ticket. Returns null if the ticket is invalid, tampered, or expired.
    /// Supports both v1 (no sessionId) and v2 (with sessionId) formats for rolling upgrade.
    /// </summary>
    public SessionTicket? Unprotect(string ticket, TimeSpan maxAge)
    {
        if (string.IsNullOrEmpty(ticket))
            return null;

        try
        {
            var encrypted = Convert.FromBase64String(ticket);
            var payload = _protector.Unprotect(encrypted);

            if (payload.Length < 17)
                return null;

            var version = payload[0];

            if (version == Version2 && payload.Length >= 25)
            {
                var userId = BitConverter.ToInt64(payload, 1);
                var sessionId = BitConverter.ToInt64(payload, 9);
                var issuedTicks = BitConverter.ToInt64(payload, 17);
                var issuedAt = new DateTimeOffset(issuedTicks, TimeSpan.Zero);

                if (_timeProvider.GetUtcNow() - issuedAt > maxAge)
                    return null;

                var username = System.Text.Encoding.UTF8.GetString(payload, 25, payload.Length - 25);
                return new SessionTicket(userId, username, issuedAt, sessionId);
            }

            if (version == Version1)
            {
                var userId = BitConverter.ToInt64(payload, 1);
                var issuedTicks = BitConverter.ToInt64(payload, 9);
                var issuedAt = new DateTimeOffset(issuedTicks, TimeSpan.Zero);

                if (_timeProvider.GetUtcNow() - issuedAt > maxAge)
                    return null;

                var username = System.Text.Encoding.UTF8.GetString(payload, 17, payload.Length - 17);
                return new SessionTicket(userId, username, issuedAt, SessionId: 0);
            }

            return null;
        }
        catch (Exception ex)
        {
            // Tampered ciphertext OR DataProtection key rotation. Return null to keep the
            // public contract intact (treated as "no valid session"), but make sure operators
            // see decrypt failures \u2014 a sustained run is a security signal.
            _logger?.LogWarning(ex,
                "SessionTicketService: failed to decrypt session ticket (length={Length}).",
                ticket.Length);
            return null;
        }
    }
}

/// <summary>
/// Decrypted session ticket data.
/// </summary>
public sealed record SessionTicket(long UserId, string Username, DateTimeOffset IssuedAt, long SessionId = 0);
