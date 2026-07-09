using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Users;
using redb.Core.Query;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.PasswordReset;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session C): anonymous password-recovery initiation backing
/// <c>direct-vm://identity-password-forgot</c>.
/// <para>
/// Strict anti-enumeration contract: <b>always</b> writes a 200/success response and
/// emits a <see cref="IdentityAuditEventIds.PasswordResetRequested"/> audit event, even
/// when the e-mail does not resolve to a user, the client is unknown, or the
/// <c>callerResetUrl</c> is not on the per-client <c>ApplicationProps.PasswordResetUris</c>
/// whitelist. Only when all three gates pass does the processor issue a single-use reset
/// token via <see cref="IPasswordResetTokenStore.IssueAsync"/> and dispatch the e-mail
/// through <see cref="IEmailNotificationChannel"/> (audit event
/// <see cref="IdentityAuditEventIds.PasswordResetTokenIssued"/>).
/// </para>
/// </summary>
internal sealed class PasswordForgotProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public PasswordForgotProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as PasswordForgotRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrWhiteSpace(request.ClientId)
            || string.IsNullOrWhiteSpace(request.CallerResetUrl))
        {
            // Hard validation error — body shape is not a legitimate user submission.
            // This branch is NOT covered by anti-enumeration: malformed bodies must be
            // visible to API callers / SDKs.
            Reject(exchange, 400, "validation_error",
                "Email, ClientId and CallerResetUrl are required.");
            return;
        }

        // Always respond success — set up before any branching so silent-drop paths still
        // emit the standard envelope.
        exchange.Out ??= new Message();
        exchange.Out.Body = new PasswordForgotResponse { Success = true };

        // Always emit the "requested" audit event so abuse telemetry can trace volume per
        // IP / email even when the request is silently dropped.
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordResetRequested;
        exchange.Properties["identity-event-data"] = new
        {
            EmailHash = HashEmailForAudit(request.Email),
            ClientId = request.ClientId,
            CallerResetUrl = request.CallerResetUrl
        };

        var redb = _context.GetRedbService(_redbName, exchange);
        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("PasswordForgotProcessor");

        // ── Gate 1: client + whitelist check (per C.6 / variant A) ────────────────
        var app = await redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == request.ClientId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (app is null)
        {
            logger?.LogInformation("Password-forgot silently dropped: unknown client_id");
            return;
        }
        var whitelist = app.Props.PasswordResetUris;
        if (whitelist is null || whitelist.Length == 0)
        {
            logger?.LogInformation(
                "Password-forgot silently dropped: client {ClientId} has no PasswordResetUris configured (feature disabled)",
                request.ClientId);
            return;
        }
        var allowed = false;
        for (var i = 0; i < whitelist.Length; i++)
        {
            if (string.Equals(whitelist[i], request.CallerResetUrl, StringComparison.Ordinal))
            { allowed = true; break; }
        }
        if (!allowed)
        {
            logger?.LogWarning(
                "Password-forgot silently dropped: CallerResetUrl not whitelisted for client {ClientId}",
                request.ClientId);
            return;
        }

        // ── Gate 2: user lookup by email (exact, case-insensitive at storage level) ──
        var usersAny = await redb.UserProvider.GetUsersAsync(new UserSearchCriteria
        {
            EmailExact = request.Email,
            // Enabled NOT set — list every match so the dropped-on-Enabled case is observable.
        }).ConfigureAwait(false);
        var users = await redb.UserProvider.GetUsersAsync(new UserSearchCriteria
        {
            EmailExact = request.Email,
            Enabled = true,
        }).ConfigureAwait(false);
        // Console.WriteLine($"[Diag-PF] email='{request.Email}' anyMatch={(usersAny?.Count ?? 0)} enabledMatch={(users?.Count ?? 0)}");
        if (usersAny is not null && usersAny.Count > 0)
        {
            for (int i = 0; i < usersAny.Count; i++)
            {
                var u = usersAny[i];
                // Console.WriteLine($"[Diag-PF]   user[{i}] id={u.Id} login='{u.Login}' email='{u.Email}' enabled={u.Enabled}");
            }
        }
        if (users is null || users.Count == 0)
        {
            logger?.LogInformation("Password-forgot silently dropped: no enabled user for supplied email");
            return;
        }
        var user = users[0];
        if (string.IsNullOrEmpty(user.Email))
        {
            // Should not happen given EmailExact matched, but guard anyway.
            return;
        }

        // ── Issue token + send e-mail ─────────────────────────────────────────────
        var store = _sp.GetRequiredService<IPasswordResetTokenStore>();
        var emailChannel = _sp.GetService<IEmailNotificationChannel>();
        if (emailChannel is null)
        {
            logger?.LogError(
                "Password-forgot: no IEmailNotificationChannel registered — silently dropping (host misconfiguration)");
            return;
        }

        var ttl = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value.PasswordRecovery.TokenTtl;
        var issued = await store.IssueAsync(user.Id, request.CallerResetUrl, ttl, ct)
            .ConfigureAwait(false);

        var resetLink = BuildResetLink(request.CallerResetUrl, issued.Jti, issued.PlaintextToken);
        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["userName"] = user.Name ?? user.Login,
            ["resetLink"] = resetLink,
            ["ttlMinutes"] = ((int)ttl.TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        try
        {
            await emailChannel.SendTemplateAsync(user.Email, IdentityEmailTemplates.PasswordReset, vars, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Anti-enumeration: never bubble e-mail failures to the caller. Log + audit only.
            logger?.LogError(ex,
                "Password-forgot: e-mail delivery failed for user {UserId} — request remains acknowledged",
                user.Id);
            return;
        }

        // Upgrade audit envelope: the request actually produced a token + e-mail.
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.PasswordResetTokenIssued;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = user.Id,
            Login = user.Login,
            ClientId = request.ClientId,
            Jti = issued.Jti.ToString("N"),
            ExpiresAt = issued.ExpiresAt,
        };
    }

    /// <summary>
    /// Composes the final reset link the user clicks on in the e-mail. URL-encodes both
    /// the plaintext token (base64url chars are URL-safe, but encoding is defence-in-depth)
    /// and the jti. Preserves any existing query string the caller's URL may already have.
    /// </summary>
    private static string BuildResetLink(string callerResetUrl, Guid jti, string plaintextToken)
    {
        var sep = callerResetUrl.Contains('?') ? '&' : '?';
        var sb = new StringBuilder(callerResetUrl.Length + 128);
        sb.Append(callerResetUrl);
        sb.Append(sep);
        sb.Append("token=");
        sb.Append(Uri.EscapeDataString(plaintextToken));
        sb.Append("&jti=");
        sb.Append(jti.ToString("N"));
        return sb.ToString();
    }

    /// <summary>
    /// Hashes the supplied e-mail for audit storage (SHA-256 hex). We do not store the
    /// plaintext e-mail of a NON-matching request — leaving it un-hashed would let an
    /// attacker who later compromises the audit log enumerate every e-mail an attacker
    /// has ever tried against the system.
    /// </summary>
    private static string HashEmailForAudit(string email)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant()));
        return Convert.ToHexString(bytes);
    }

    private static void Reject(IExchange exchange, int status, string error, string description)
    {
        exchange.Out ??= new Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = status;
        exchange.Out.Body = new { error, error_description = description };
    }
}
