using System.Threading;
using System.Threading.Tasks;
using redb.Core;

namespace redb.Identity.Core.Security;

/// <summary>
/// H10 — central server-side gate for every password mutation (admin Create/Change,
/// self-service /me/password, SCIM Create/PATCH). Validates length + composition rules
/// from <see cref="Configuration.PasswordPolicyOptions"/>, history reuse (Phase 2) and
/// breach checking (Phase 5). Always invoked BEFORE
/// <c>IUserProvider.SetPasswordAsync</c>/<c>ChangePasswordAsync</c>.
/// </summary>
public interface IPasswordPolicyValidator
{
    /// <summary>
    /// Validates the candidate password against all configured rules.
    /// </summary>
    /// <param name="password">Candidate password (plaintext).</param>
    /// <param name="userId">User the password is being set for (used for history lookup); null for new accounts.</param>
    /// <param name="ct">Cancellation token.</param>
    ValueTask<PasswordValidationResult> ValidateAsync(
        string? password,
        long? userId = null,
        CancellationToken ct = default);

    /// <summary>
    /// The same validation with the database reads (the history lookup) through <paramref name="redb"/>: what a
    /// processor on a transacted route calls with the exchange's <see cref="IRedbService"/>, so no second
    /// connection opens inside the route's transaction. A validator without its own implementation validates
    /// as above.
    /// </summary>
    ValueTask<PasswordValidationResult> ValidateAsync(
        string? password,
        long? userId,
        IRedbService redb,
        CancellationToken ct = default)
        => ValidateAsync(password, userId, ct);
}

/// <summary>
/// Aggregated outcome of a password policy check. <see cref="IsValid"/> is <c>true</c>
/// iff <see cref="Errors"/> is empty.
/// </summary>
public sealed class PasswordValidationResult
{
    public bool IsValid { get; init; }
    public System.Collections.Generic.IReadOnlyList<string> Errors { get; init; }
        = System.Array.Empty<string>();

    public static PasswordValidationResult Ok() => new() { IsValid = true };

    public static PasswordValidationResult Fail(params string[] errors) =>
        new() { IsValid = false, Errors = errors };

    public static PasswordValidationResult Fail(System.Collections.Generic.IReadOnlyList<string> errors) =>
        new() { IsValid = errors.Count == 0, Errors = errors };

    /// <summary>
    /// Joins all errors with "; " for legacy single-line error_description fields.
    /// </summary>
    public string ToErrorMessage() => string.Join("; ", Errors);
}
