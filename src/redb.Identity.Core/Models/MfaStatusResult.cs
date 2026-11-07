namespace redb.Identity.Core.Models;

/// <summary>
/// MFA status for a user, returned by management API.
/// </summary>
public sealed class MfaStatusResult
{
    public bool Enabled { get; set; }
    public string[] Methods { get; set; } = [];
    public int RecoveryCodesRemaining { get; set; }
}
