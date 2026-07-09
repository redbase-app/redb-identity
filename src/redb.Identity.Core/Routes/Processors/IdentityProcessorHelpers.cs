using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Security;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Security;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Shared extraction and validation helpers used by identity management processors.
/// </summary>
internal static partial class IdentityProcessorHelpers
{
    // ── Limits (defaults; configurable via Configure(IdentityValidationOptions)) ──
    public static int MaxIdentifierLength { get; private set; } = 128;
    public static int MaxDisplayNameLength { get; private set; } = 256;
    public static int MaxDescriptionLength { get; private set; } = 1024;
    public static int MinPasswordLength { get; private set; } = 8;
    public static int MaxPasswordLength { get; private set; } = 512;

    // Active regex (defaults = source-generated; overridable via Configure()).
    private static Regex _identifierRegex = DefaultIdentifierRegex();
    private static Regex _emailRegex = DefaultEmailRegex();
    private static Regex _phoneRegex = DefaultE164Regex();

    /// <summary>
    /// Applies length limits and regex overrides from configuration. Called once during
    /// Identity server bootstrap (see <c>AddRedbIdentityServer</c>). Idempotent; null input
    /// is a no-op. Invalid override patterns fall back to defaults.
    /// </summary>
    public static void Configure(IdentityValidationOptions? options)
    {
        if (options is null) return;
        MaxIdentifierLength = options.MaxIdentifierLength;
        MaxDisplayNameLength = options.MaxDisplayNameLength;
        MaxDescriptionLength = options.MaxDescriptionLength;
        MinPasswordLength = options.MinPasswordLength;
        MaxPasswordLength = options.MaxPasswordLength;
        _identifierRegex = Compile(options.IdentifierPattern, DefaultIdentifierRegex());
        _emailRegex = Compile(options.EmailPattern, DefaultEmailRegex());
        _phoneRegex = Compile(options.PhonePattern, DefaultE164Regex());
    }

    private static Regex Compile(string? pattern, Regex fallback)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return fallback;
        try { return new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant); }
        catch (ArgumentException) { return fallback; }
    }

    // ── Regex (source-generated defaults) ──
    [GeneratedRegex(@"^[a-zA-Z0-9\-_.]+$")]
    private static partial Regex DefaultIdentifierRegex();

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    private static partial Regex DefaultEmailRegex();

    [GeneratedRegex(@"^\+[1-9]\d{1,14}$")]
    private static partial Regex DefaultE164Regex();

    // ── Error helper ──
    public static void SetError(IExchange exchange, string error, string description)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { error, error_description = description };
    }

    // ── Validation helpers (return error message or null) ──

    public static string? ValidateIdentifier(string? value, string fieldName)
    {
        if (string.IsNullOrEmpty(value))
            return $"{fieldName} is required";
        if (value.Length > MaxIdentifierLength)
            return $"{fieldName} must not exceed {MaxIdentifierLength} characters";
        if (!_identifierRegex.IsMatch(value))
            return $"{fieldName} contains invalid characters (allowed: a-z, 0-9, '-', '_', '.')";
        return null;
    }

    public static string? ValidateDisplayName(string? value, string fieldName)
    {
        if (value is not null && value.Length > MaxDisplayNameLength)
            return $"{fieldName} must not exceed {MaxDisplayNameLength} characters";
        return null;
    }

    public static string? ValidateDescription(string? value, string fieldName)
    {
        if (value is not null && value.Length > MaxDescriptionLength)
            return $"{fieldName} must not exceed {MaxDescriptionLength} characters";
        return null;
    }

    public static string? ValidatePassword(string? value, string fieldName = "Password")
    {
        if (string.IsNullOrEmpty(value))
            return $"{fieldName} is required";
        if (value.Length < MinPasswordLength)
            return $"{fieldName} must be at least {MinPasswordLength} characters";
        if (value.Length > MaxPasswordLength)
            return $"{fieldName} must not exceed {MaxPasswordLength} characters";
        return null;
    }

    /// <summary>
    /// H10 — full password policy gate (length + composition + history + breach).
    /// Resolves <see cref="IPasswordPolicyValidator"/> from the current request scope
    /// (preferred) or the route-context root provider; falls back to the legacy
    /// length-only <see cref="ValidatePassword(string?, string)"/> when no validator is
    /// registered (unit-test paths without a full DI container). Returns <c>null</c> on
    /// success or a single-line joined error message suitable for
    /// <c>error_description</c> fields.
    /// </summary>
    public static async ValueTask<string?> ValidatePasswordPolicyAsync(
        IExchange exchange,
        IRouteContext context,
        string? password,
        long? userId,
        string fieldName = "Password",
        CancellationToken ct = default)
    {
        // The validator is registered in the Identity child SP — under tpkg deployment
        // exchange.ServiceProvider is a per-exchange scope of the HOST root, not the child.
        // GetIdentityServiceOrDefault bridges the two SPs (cf. IdentityRouteContextExtensions);
        // without this, the policy validator silently misses and we fall back to the
        // legacy length-only check, swallowing composition rules (digit/upper/lower).
        var validator = context?.GetIdentityServiceOrDefault<IPasswordPolicyValidator>(exchange);
        if (validator is null)
        {
            var sp = exchange?.ServiceProvider ?? context?.GetServiceProvider();
            validator = sp?.GetService<IPasswordPolicyValidator>();
        }
        if (validator is null)
            return ValidatePassword(password, fieldName);

        var result = await validator.ValidateAsync(password, userId, ct).ConfigureAwait(false);
        return result.IsValid ? null : result.ToErrorMessage();
    }

    /// <summary>
    /// H10 Phase 2 — record the just-set password in the per-user history (via the
    /// registered <see cref="IPasswordHistoryStore"/>) so future change attempts can
    /// reject reuse. Best-effort: if no store is registered or
    /// <see cref="Configuration.PasswordPolicyOptions.HistoryCount"/> is 0, this is a
    /// no-op. Failures are logged but never propagate — the password change has already
    /// succeeded at this point and the user must not be rolled back over a history I/O.
    /// </summary>
    public static async ValueTask RecordPasswordHistoryAsync(
        IExchange exchange,
        IRouteContext context,
        long userId,
        string password,
        CancellationToken ct = default)
        => await RecordPasswordHistoryAsync(exchange, context, redb: null, userId, password, ct).ConfigureAwait(false);

    /// <summary>
    /// PERF overload: callers that already hold the in-tx <see cref="IRedbService"/>
    /// (everyone inside a <c>WithRedbTx</c>-wrapped processor) pass it in here. We reuse
    /// that instance for the history write and the PasswordChangedAt stamp, avoiding
    /// the historic 30 s deadlock where opening a fresh scope acquired an independent
    /// connection that blocked on the un-committed outer tx until
    /// <c>TransactionPolicy.Timeout</c> elapsed.
    /// </summary>
    public static async ValueTask RecordPasswordHistoryAsync(
        IExchange exchange,
        IRouteContext context,
        IRedbService? redb,
        long userId,
        string password,
        CancellationToken ct = default)
    {
        if (userId <= 0 || string.IsNullOrEmpty(password)) return;
        var sp = exchange?.ServiceProvider ?? context?.GetServiceProvider();
        if (sp is null) return;

        var policy = sp.GetService<Configuration.PasswordPolicyOptions>();
        var keep = policy?.HistoryCount ?? 0;
        if (keep > 0)
        {
            try
            {
                if (redb is not null)
                {
                    // Fast path — caller's IRedbService is enlisted in the outer tx.
                    await RecordPasswordHistoryWithRedbAsync(sp, redb, userId, password, keep, ct).ConfigureAwait(false);
                }
                else
                {
                    // Out-of-exchange fallback (unit tests / cleanup hooks).
                    var store = sp.GetService<IPasswordHistoryStore>();
                    if (store is not null)
                        await store.RecordAsync(userId, password, keep, ct).ConfigureAwait(false);
                }
            }
            catch
            {
                // Swallow: history recording must not fail an otherwise-successful password
                // change. Underlying store has its own logging.
            }
        }

        // H10 Phase 3 — stamp PasswordChangedAt on the user's OIDC props so future logins
        // can enforce MaxAge expiration. Always done, even when history is disabled.
        if (redb is not null)
        {
            // Use the in-tx IRedbService directly — same anti-deadlock reasoning as above.
            await UpdatePasswordChangedAtWithRedbAsync(sp, redb, userId, ct).ConfigureAwait(false);
        }
        else
        {
            await UpdatePasswordChangedAtAsync(sp, exchange, userId, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// PERF inline of <see cref="PropsPasswordHistoryStore.RecordAsync"/> that runs against the
    /// supplied exchange's <see cref="IRedbService"/>/<see cref="IPasswordHasher"/>. Same
    /// logic as the store; lives here so it doesn't need to be wired through a new method on
    /// <see cref="IPasswordHistoryStore"/>. The trimming branch swallows failures so the
    /// password-change write succeeds even when the trim query throws.
    /// </summary>
    private static async Task RecordPasswordHistoryWithRedbAsync(
        IServiceProvider sp, IRedbService redb, long userId, string password, int keep, CancellationToken ct)
    {
        var hasher = sp.GetRequiredService<IPasswordHasher>();
        var timeProvider = sp.GetService<TimeProvider>() ?? TimeProvider.System;
        var now = timeProvider.GetUtcNow();

        var entry = new RedbObject<PasswordHistoryProps>(new PasswordHistoryProps
        {
            UserId = userId,
            HashedPassword = hasher.HashPassword(password),
            CreatedAt = now,
        })
        {
            name = $"pwhist:{userId}:{now.ToUnixTimeMilliseconds()}",
        };
        await redb.SaveAsync(entry).ConfigureAwait(false);

        try
        {
            var staleIds = await redb.Query<PasswordHistoryProps>()
                .Where(o => o.UserId == userId)
                .OrderByDescending(o => o.CreatedAt)
                .Skip(keep)
                .Select(o => o.id)
                .ToListAsync()
                .ConfigureAwait(false);
            if (staleIds.Count > 0)
                await redb.SoftDeleteAsync(staleIds).ConfigureAwait(false);
        }
        catch
        {
            // Trim is advisory — failures must not block password change.
        }
    }

    /// <summary>
    /// H10 Phase 3 — upsert <see cref="redb.Identity.Core.Models.UserProps.PasswordChangedAt"/>
    /// to the current UTC time for <paramref name="userId"/>. Creates the OIDC props row
    /// if missing (covers users created before H10). Best-effort.
    /// <para>
    /// PERF: when an exchange is supplied we prefer its <see cref="IExchange.ServiceProvider"/>
    /// because it shares the in-flight <c>IRedbService</c> already enlisted in the route's
    /// transaction (cf. <c>WithRedbTx</c>). Opening a separate scope here used to acquire a
    /// fresh DB connection that immediately blocked on the still-open outer tx, and only
    /// returned when the connection pool's <c>TransactionPolicy.Timeout</c> (30 s default)
    /// expired — admin <c>POST /users</c> and SCIM <c>POST /scim/v2/Users</c> were both
    /// observed taking ~30 s/op for that reason. The exchange-SP path is now the fast path
    /// for in-route callers; the scope-factory fallback remains for code that runs outside
    /// an exchange (e.g. unit tests).
    /// </para>
    /// </summary>
    /// <summary>
    /// PERF fast path mirroring <see cref="UpdatePasswordChangedAtAsync(IServiceProvider, IExchange?, long, CancellationToken)"/>
    /// but using the supplied <paramref name="redb"/> directly so the upsert lands inside
    /// the caller's in-flight transaction.
    /// </summary>
    private static async Task UpdatePasswordChangedAtWithRedbAsync(
        IServiceProvider sp, IRedbService redb, long userId, CancellationToken ct)
    {
        try
        {
            var timeProvider = sp.GetService<TimeProvider>() ?? TimeProvider.System;
            var existing = await redb.Query<Models.UserProps>()
                .WhereRedb(o => o.Key == userId)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);

            var now = timeProvider.GetUtcNow();
            if (existing is not null)
            {
                existing.Props.PasswordChangedAt = now;
                existing.Props.HasUserPassword = true;
                await redb.SaveAsync(existing).ConfigureAwait(false);
            }
            else
            {
                var fresh = new redb.Core.Models.Entities.RedbObject<Models.UserProps>(
                    new Models.UserProps { PasswordChangedAt = now, HasUserPassword = true })
                {
                    key = userId,
                };
                await redb.SaveAsync(fresh).ConfigureAwait(false);
            }
        }
        catch
        {
            // Advisory — same swallow contract as the scope-factory variant.
        }
    }

    private static async Task UpdatePasswordChangedAtAsync(
        IServiceProvider sp, IExchange? exchange, long userId, CancellationToken ct)
    {
        try
        {
            redb.Core.IRedbService redbService;
            IServiceScope? scope = null;

            if (exchange?.ServiceProvider is { } exSp)
            {
                // Fast path: reuse the exchange's scope (same outer tx, same connection).
                redbService = exSp.GetRequiredService<redb.Core.IRedbService>();
            }
            else
            {
                // Out-of-exchange path: open a fresh scope.
                var scopeFactory = sp.GetService<IServiceScopeFactory>();
                if (scopeFactory is not null)
                {
                    scope = scopeFactory.CreateScope();
                    redbService = scope.ServiceProvider.GetRequiredService<redb.Core.IRedbService>();
                }
                else
                {
                    redbService = sp.GetRequiredService<redb.Core.IRedbService>();
                }
            }

            try
            {
                var timeProvider = sp.GetService<TimeProvider>() ?? TimeProvider.System;
                var existing = await redbService.Query<Models.UserProps>()
                    .WhereRedb(o => o.Key == userId)
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);

                var now = timeProvider.GetUtcNow();
                if (existing is not null)
                {
                    existing.Props.PasswordChangedAt = now;
                    // H8 (DoD §4 gap (d)): mark that the user has set their own password.
                    // Used by MeFederatedIdentitiesProcessor to refuse unlinking the last
                    // social provider when no local password exists.
                    existing.Props.HasUserPassword = true;
                    await redbService.SaveAsync(existing).ConfigureAwait(false);
                }
                else
                {
                    var fresh = new redb.Core.Models.Entities.RedbObject<Models.UserProps>(
                        new Models.UserProps { PasswordChangedAt = now, HasUserPassword = true })
                    {
                        key = userId,
                    };
                    await redbService.SaveAsync(fresh).ConfigureAwait(false);
                }
            }
            finally
            {
                scope?.Dispose();
            }
        }
        catch
        {
            // Swallow: stamping is advisory; failure must not roll back the password
            // change that has already been persisted in _users.
        }
    }

    public static string? ValidateEmail(string? value)
    {
        if (value is not null && !_emailRegex.IsMatch(value))
            return "Invalid email format";
        return null;
    }

    public static string? ValidatePhoneNumber(string? value)
    {
        if (value is not null && !_phoneRegex.IsMatch(value))
            return "Phone number must be in E.164 format (e.g. +12345678901)";
        return null;
    }

    public static string? ValidateUris(IEnumerable<string>? uris, string fieldName)
    {
        if (uris is null) return null;
        foreach (var u in uris)
        {
            if (!Uri.IsWellFormedUriString(u, UriKind.Absolute))
                return $"Invalid {fieldName} format: {u}";
            // OAuth 2.1 / RFC 6749 §3.1.2: redirect URIs MUST NOT contain wildcards,
            // and MUST NOT include a fragment component. Server-side matching is exact.
            if (u.Contains('*'))
                return $"Wildcards are not allowed in {fieldName}: {u}";
            if (u.Contains('#'))
                return $"Fragment component is not allowed in {fieldName}: {u}";
        }
        return null;
    }

    public static long ExtractRequiredLong(IExchange exchange, string key)
    {
        if (exchange.In.Body is Dictionary<string, object?> dict)
            return ExtractLong(dict, key)
                ?? throw new InvalidOperationException($"{key} is required");
        throw new InvalidOperationException($"{key} is required");
    }

    public static long? ExtractLong(Dictionary<string, object?> dict, string key)
    {
        if (dict.TryGetValue(key, out var val) && val is not null
            && long.TryParse(val.ToString(), out var result) && result > 0)
            return result;
        return null;
    }
}
