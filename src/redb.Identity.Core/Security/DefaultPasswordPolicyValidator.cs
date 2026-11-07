using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Security;

/// <summary>
/// H10 — default <see cref="IPasswordPolicyValidator"/> implementation backed by
/// <see cref="PasswordPolicyOptions"/>. Phase 1: length + ASCII composition rules.
/// Phase 2 (history) and Phase 5 (breach) hooks are wired through optional dependencies
/// so the same instance keeps working as the stack grows.
/// </summary>
public sealed class DefaultPasswordPolicyValidator : IPasswordPolicyValidator
{
    private readonly PasswordPolicyOptions _options;
    // Phase 2 hook — null = history check disabled.
    private readonly IPasswordHistoryStore? _history;
    // Phase 5 hook — null = breach check disabled even if BreachCheckEnabled=true.
    private readonly IBreachedPasswordChecker? _breachChecker;

    public DefaultPasswordPolicyValidator(
        PasswordPolicyOptions options,
        IPasswordHistoryStore? history = null,
        IBreachedPasswordChecker? breachChecker = null)
    {
        _options = options ?? throw new System.ArgumentNullException(nameof(options));
        _history = history;
        _breachChecker = breachChecker;
    }

    /// <inheritdoc />
    public async ValueTask<PasswordValidationResult> ValidateAsync(
        string? password,
        long? userId = null,
        CancellationToken ct = default)
    {
        var errors = new List<string>();

        if (string.IsNullOrEmpty(password))
        {
            errors.Add("Password is required");
            return PasswordValidationResult.Fail(errors);
        }

        // ── Length ──
        if (password.Length < _options.MinLength)
            errors.Add($"Password must be at least {_options.MinLength} characters");
        if (password.Length > _options.MaxLength)
            errors.Add($"Password must not exceed {_options.MaxLength} characters");

        // ── Composition (ASCII; non-ASCII letters/digits are NOT counted to keep
        //    classification deterministic across cultures) ──
        bool hasDigit = false, hasUpper = false, hasLower = false, hasSpecial = false;
        var specials = _options.SpecialChars ?? string.Empty;
        for (int i = 0; i < password.Length; i++)
        {
            var c = password[i];
            if (c >= '0' && c <= '9') hasDigit = true;
            else if (c >= 'A' && c <= 'Z') hasUpper = true;
            else if (c >= 'a' && c <= 'z') hasLower = true;
            else if (specials.IndexOf(c) >= 0) hasSpecial = true;
        }

        if (_options.RequireDigit && !hasDigit)
            errors.Add("Password must contain at least one digit");
        if (_options.RequireUppercase && !hasUpper)
            errors.Add("Password must contain at least one uppercase letter");
        if (_options.RequireLowercase && !hasLower)
            errors.Add("Password must contain at least one lowercase letter");
        if (_options.RequireSpecial && !hasSpecial)
            errors.Add("Password must contain at least one special character");

        // Stop short-circuit before more expensive checks if basic rules failed —
        // user gets the cheap rule violations first, history/breach only when shape is OK.
        if (errors.Count > 0)
            return PasswordValidationResult.Fail(errors);

        // ── Phase 2: history reuse ──
        if (_history is not null && _options.HistoryCount > 0 && userId.HasValue)
        {
            var reused = await _history.IsRecentlyUsedAsync(
                userId.Value, password, _options.HistoryCount, ct).ConfigureAwait(false);
            if (reused)
                errors.Add($"Password matches one of the last {_options.HistoryCount} passwords");
        }

        // ── Phase 5: breach check (HIBP or other registered checker) ──
        if (_options.BreachCheckEnabled && _breachChecker is not null)
        {
            var breached = await _breachChecker.IsBreachedAsync(password, ct).ConfigureAwait(false);
            if (breached)
                errors.Add("Password has appeared in a known data breach and cannot be used");
        }

        return errors.Count == 0
            ? PasswordValidationResult.Ok()
            : PasswordValidationResult.Fail(errors);
    }
}

/// <summary>
/// Phase 2 — pluggable per-user password-history store. Implemented in a follow-up
/// phase; declared here so <see cref="DefaultPasswordPolicyValidator"/> can take an
/// optional dependency without a circular reference.
/// </summary>
public interface IPasswordHistoryStore
{
    /// <summary>Returns <c>true</c> if <paramref name="password"/> matches any of the
    /// last <paramref name="count"/> hashes recorded for <paramref name="userId"/>.</summary>
    Task<bool> IsRecentlyUsedAsync(long userId, string password, int count, CancellationToken ct);

    /// <summary>Records a new password hash for the user and trims older entries beyond
    /// <paramref name="keep"/>.</summary>
    Task RecordAsync(long userId, string password, int keep, CancellationToken ct);
}

/// <summary>
/// Phase 5 — pluggable breached-password checker (e.g. HIBP k-anonymity, local
/// dictionary). Default deployment registers no implementation; the policy validator
/// then skips the check entirely regardless of
/// <see cref="PasswordPolicyOptions.BreachCheckEnabled"/>.
/// </summary>
public interface IBreachedPasswordChecker
{
    Task<bool> IsBreachedAsync(string password, CancellationToken ct);
}
