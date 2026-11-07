using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// Admin-side password reset for a user, bypassing the "old password" challenge
/// that the user-facing <see cref="ChangePasswordRequest"/> requires. Reserved for
/// the management API (gated by <c>identity:users.manage</c> / <c>identity:manage</c>
/// scope) — never invoked from the user's own profile flow.
/// </summary>
public class AdminResetPasswordRequest
{
    /// <summary>Internal numeric user id (server fills this from the route).</summary>
    [Required]
    public long Id { get; set; }

    /// <summary>
    /// New password. Server-side validation runs the same complexity policy as
    /// the user-facing change-password endpoint (length, history, banned list).
    /// </summary>
    [Required]
    public required string NewPassword { get; set; }
}
