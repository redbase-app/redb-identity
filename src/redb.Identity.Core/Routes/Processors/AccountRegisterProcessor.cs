using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Models.Users;
using redb.Core.Query;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using CoreCreateUserRequest = redb.Core.Models.Users.CreateUserRequest;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N-3 (sub-step N3-7): anonymous self-service account-registration processor backing
/// <c>direct-vm://identity-account-register</c>.
/// <para>
/// Distinct from <see cref="UserManagementProcessor"/> (admin <c>create</c>): runs on the
/// anonymous prefix <c>/api/v1/identity/account/</c>, is per-IP throttled by the upstream
/// route chain, validates inputs against the same helpers, and \u2014 unlike the password
/// recovery flow \u2014 deliberately surfaces <c>duplicate</c> / <c>weak_password</c>
/// errors so the sign-up UI can render actionable feedback. Duplicate-login attempts are
/// an expected user mistake; treating them as anti-enumeration would block legitimate
/// users without preventing the trivial probe (anyone can already attempt to log in).
/// </para>
/// <para>
/// The processor does NOT dispatch the verify-e-mail link itself \u2014 after the BFF
/// auto-signs the user in it calls <c>/api/auth/account/verify-email/send</c>, which
/// already routes through the dedicated <c>EmailVerifySendProcessor</c> with full
/// per-client URL whitelist enforcement.
/// </para>
/// </summary>
internal sealed class AccountRegisterProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public AccountRegisterProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as RegisterAccountRequest;
        if (request is null)
        {
            Reject(exchange, 400, "validation_error", "Request body is required.");
            return;
        }

        var options = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value;
        var regOptions = options.Registration;

        // Master switch \u2014 even if the route is wired at startup but disabled later
        // via config reload, refuse with 403 so the BFF/SDK can show a deterministic
        // "sign-up is disabled" message.
        if (!regOptions.Enabled)
        {
            Reject(exchange, 403, "registration_disabled",
                "Self-service account registration is disabled on this server.");
            return;
        }

        // Hard input validation \u2014 mirrors UserManagementProcessor.Create except that
        // e-mail is REQUIRED here (the anonymous flow has no other recovery surface).
        var err = IdentityProcessorHelpers.ValidateIdentifier(request.Login, "Login");
        if (err is not null) { Reject(exchange, 400, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
        if (err is not null) { Reject(exchange, 400, "validation_error", err); return; }

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            Reject(exchange, 400, "validation_error", "Email is required.");
            return;
        }
        err = IdentityProcessorHelpers.ValidateEmail(request.Email);
        if (err is not null) { Reject(exchange, 400, "validation_error", err); return; }

        // Normalise before the uniqueness check and the INSERT: e-mail is case-insensitive in
        // practice, but the UX_users_email unique index is a plain index on _email, so "A@x.com"
        // and "a@x.com" would otherwise slip past it as distinct rows. Lower-invariant + trim makes
        // the stored value canonical, so the index (and EmailExact lookups) enforce one identity.
        request.Email = request.Email.Trim().ToLowerInvariant();

        // Full password policy gate (length + composition + breach). userId is null
        // because we have not minted the row yet.
        err = await IdentityProcessorHelpers.ValidatePasswordPolicyAsync(
            exchange, _context, request.Password, userId: null, "Password", ct).ConfigureAwait(false);
        if (err is not null) { Reject(exchange, 400, "weak_password", err); return; }

        var redb = _context.GetRedbService(_redbName, exchange);
        var logger = _sp.GetService<ILoggerFactory>()?.CreateLogger("AccountRegisterProcessor");

        // S2.3 — enforce global claim schema BEFORE creating the relational
        // user row. Failed validation here must NOT leave a half-created
        // user behind. account/register has no inbound customClaims yet, so
        // we pass null — defaults are filled in, required claims without a
        // default fail with 400.
        var (defaultClaims, schemaErr) = await Services.ClaimSchemaValidator.EnforceGlobalAsync(redb, null, ct)
            .ConfigureAwait(false);
        if (schemaErr is not null)
        {
            Reject(exchange, 400, "validation_error", schemaErr);
            return;
        }

        // Pre-check e-mail uniqueness when the option is on. UserProvider.CreateUserAsync
        // enforces login uniqueness atomically; e-mail is not enforced at the relational
        // layer, so we surface a deterministic error before allocating a row.
        if (regOptions.RequireUniqueEmail)
        {
            var existing = await redb.UserProvider.GetUsersAsync(new UserSearchCriteria
            {
                EmailExact = request.Email,
            }).ConfigureAwait(false);
            if (existing is { Count: > 0 })
            {
                Reject(exchange, 409, "duplicate",
                    $"An account with email '{request.Email}' already exists.");
                return;
            }
        }

        // Create the relational user row.
        redb.Core.Models.Contracts.IRedbUser coreUser;
        try
        {
            coreUser = await redb.UserProvider.CreateUserAsync(new CoreCreateUserRequest
            {
                Login = request.Login,
                Password = request.Password,
                Name = request.DisplayName ?? request.Login,
                Email = request.Email,
                Phone = null,
                Enabled = true,
            }).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already taken"))
        {
            Reject(exchange, 409, "duplicate", $"Login '{request.Login}' is already taken.");
            return;
        }
        catch (Exception ex) when (
            (ex.Message?.Contains("UX_users_email", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (ex.InnerException?.Message?.Contains("UX_users_email", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            // The UX_users_email unique index fired: another registration committed the same e-mail
            // between our advisory check and this INSERT. This is the atomic backstop the advisory
            // GetUsersAsync check cannot provide — surface it as the same 409 the check would have.
            Reject(exchange, 409, "duplicate", $"An account with email '{request.Email}' already exists.");
            return;
        }
        catch (Exception ex)
        {
            throw;
        }

        // Persist OIDC profile extension (UserProps) linked via key = _users._id.
        // value_guid: stable, instance-unique public identity used as the OIDC `sub` claim.
        // PasswordChangedAt + HasUserPassword are baked into THIS save so we do not need
        // a follow-up read-modify-write in the password-history helper. The helper's
        // stamp path opens a fresh DI scope (separate Npgsql connection) and would race
        // for 30 s on row locks against the row we are inserting right here \u2014 one save
        // is enough, the row is up-to-date as of registration time.
        var nowUtc = DateTimeOffset.UtcNow;
        var propsObj = new RedbObject<UserProps>(new UserProps
        {
            EmailVerified = false,
            PasswordChangedAt = nowUtc,
            HasUserPassword = true,
            CustomClaims = defaultClaims is { Count: > 0 } ? defaultClaims : null,
        })
        {
            name = coreUser.Login,
            key = coreUser.Id,
            value_guid = Guid.NewGuid(),
        };
        await redb.SaveAsync(propsObj).ConfigureAwait(false);

        // Record initial password in history so subsequent change attempts cannot
        // immediately reuse the sign-up password. We call the store directly (rather
        // than through RecordPasswordHistoryAsync) to skip its stamp path \u2014 see above.
        var historyStore = _sp.GetService<redb.Identity.Core.Security.IPasswordHistoryStore>();
        var keep = options.PasswordPolicy?.HistoryCount ?? 0;
        if (historyStore is not null && keep > 0)
        {
            try
            {
                await historyStore.RecordAsync(coreUser.Id, request.Password, keep, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Non-fatal: history is best-effort, mirrors the helper's swallow contract.
            }
        }

        logger?.LogDebug(
            "AccountRegister: user {UserId} ({Login}) created via self-service",
            coreUser.Id, coreUser.Login);

        exchange.Out ??= new Message();
        exchange.Out.Body = new RegisterAccountResponse
        {
            Success = true,
            UserId = coreUser.Id,
            Login = coreUser.Login,
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserCreated;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = coreUser.Id,
            Login = coreUser.Login,
            SelfService = true,
        };
    }

    private static void Reject(IExchange exchange, int status, string error, string description)
    {
        exchange.Out ??= new Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = status;
        exchange.Out.Body = new RegisterAccountResponse
        {
            Success = false,
            Error = error,
            ErrorDescription = description,
        };
    }
}
