namespace redb.Identity.Ldap;

/// <summary>
/// Active Directory userAccountControl bitmask flags.
/// See https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate
/// </summary>
[Flags]
public enum UserAccountControlFlags
{
    None            = 0,
    AccountDisable  = 0x0002,
    Lockout         = 0x0010,
    NormalAccount   = 0x0200,
    PasswordExpired = 0x800000,
}
