namespace redb.Identity.Core.Models;

/// <summary>
/// A snapshot of recovery-code hashes that were active before being retired
/// (for example because MFA was disabled or because the user regenerated the set).
/// <para>
/// Stored append-only on <see cref="MfaProps.ArchivedRecoveryCodes"/>. The hashes here
/// are NOT consulted by <c>MfaService.VerifyRecoveryCodeAsync</c> and cannot be used
/// to log in — keeping them is purely audit/forensic so that an admin can answer
/// «which codes were active for this user when MFA was disabled at <c>ArchivedAt</c>?»
/// without weakening the security promise that <c>Disable</c> revokes the codes.
/// </para>
/// <para>B9 / BUG-8.</para>
/// </summary>
public sealed class MfaArchivedRecoveryCodeBatch
{
    /// <summary>UTC timestamp at which the batch was retired.</summary>
    public DateTimeOffset ArchivedAt { get; set; }

    /// <summary>
    /// Reason the batch was retired ("disable", "regenerate", etc.). Free-form short tag,
    /// not surfaced to end users.
    /// </summary>
    public string? Reason { get; set; }

    /// <summary>The hashed codes (same wire format as <see cref="MfaProps.RecoveryCodes"/>).</summary>
    public List<string> HashedCodes { get; set; } = new();
}
