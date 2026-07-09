using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.EmailVerification;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-4 (Session C, sub-step N4-6): anonymous e-mail-verification confirmation backing
/// <c>direct-vm://identity-email-verify-confirm</c>.
/// <para>
/// Verifies + atomically consumes the single-use token via
/// <see cref="IEmailVerificationTokenStore.VerifyAndConsumeAsync"/>. On success it loads
/// the user, ensures the user's current e-mail still matches the snapshot captured at
/// issue time (double-change race protection), then flips
/// <see cref="UserProps.EmailVerified"/> to <c>true</c> in the OIDC props extension.
/// </para>
/// <para>
/// All failure modes return the generic OAuth-style <c>invalid_token</c> error — the
/// granular reason from the store (or <c>email_changed</c>) is only persisted to audit
/// (<see cref="IdentityAuditEventIds.EmailVerificationFailed"/>) so an anonymous caller
/// cannot enumerate which jti values exist.
/// </para>
/// </summary>
internal sealed class EmailVerifyConfirmProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public EmailVerifyConfirmProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as EmailVerifyConfirmRequest;
        if (request is null
            || string.IsNullOrWhiteSpace(request.Jti)
            || string.IsNullOrWhiteSpace(request.Token))
        {
            Reject(exchange, 400, "validation_error", "Jti and Token are required.");
            return;
        }

        if (!Guid.TryParseExact(request.Jti, "N", out var jti)
            && !Guid.TryParse(request.Jti, out jti))
        {
            EmitFailureAudit(exchange, "bad_jti_format", userId: 0);
            Reject(exchange, 400, "invalid_token", "The verification token is invalid or has expired.");
            return;
        }

        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("EmailVerifyConfirmProcessor");
        var store = _sp.GetRequiredService<IEmailVerificationTokenStore>();

        var verify = await store.VerifyAndConsumeAsync(jti, request.Token, ct).ConfigureAwait(false);
        if (!verify.Success)
        {
            EmitFailureAudit(exchange, verify.Reason, verify.UserId);
            Reject(exchange, 400, "invalid_token", "The verification token is invalid or has expired.");
            return;
        }

        var redb = _context.GetRedbService(_redbName, exchange);

        var user = await redb.UserProvider.GetUserByIdAsync(verify.UserId).ConfigureAwait(false);
        if (user is null)
        {
            EmitFailureAudit(exchange, "user_not_found", verify.UserId);
            Reject(exchange, 400, "invalid_token", "The verification token is invalid or has expired.");
            return;
        }

        // Double-change race guard: the token vouches for the e-mail value that was bound
        // at issue time. If the user has since changed their e-mail, this token must NOT
        // promote the new value to "verified".
        var currentEmail = (user.Email ?? string.Empty).Trim().ToLowerInvariant();
        if (!string.Equals(currentEmail, verify.Email, StringComparison.Ordinal))
        {
            EmitFailureAudit(exchange, "email_changed", user.Id);
            Reject(exchange, 400, "invalid_token", "The verification token is invalid or has expired.");
            return;
        }

        // Flip OIDC EmailVerified flag. Load (or create) the props extension.
        var oidcObj = await MeProcessorHelpers.LoadOidcProps(redb, user.Id).ConfigureAwait(false);
        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps { EmailVerified = true });
            oidcObj.name = user.Login;
            oidcObj.key = user.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }
        else
        {
            oidcObj.Props.EmailVerified = true;
        }
        await redb.SaveAsync(oidcObj).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = new EmailVerifyConfirmResponse { Success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailVerificationCompleted;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = user.Id,
            Login = user.Login,
            Email = verify.Email,
            Jti = jti.ToString("N"),
        };
    }

    private static void EmitFailureAudit(IExchange exchange, string reason, long userId)
    {
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.EmailVerificationFailed;
        exchange.Properties["identity-event-data"] = new { Reason = reason, UserId = userId };
    }

    private static void Reject(IExchange exchange, int status, string error, string description)
    {
        exchange.Out ??= new Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = status;
        exchange.Out.Body = new EmailVerifyConfirmResponse
        {
            Success = false,
            Error = error,
            ErrorDescription = description,
        };
    }
}
