using redb.Core.Attributes;

namespace redb.Identity.DataProtection;

/// <summary>
/// When the DataProtection key ring moved from the file system into redb (the first start of 4.4 on this
/// database). Only file-ring elements older than this are imported: the Tsak worker, the Tsak dashboard and
/// Identity Web keep writing their own rings to the same default directory, and their later keys are not
/// Identity's. Two nodes writing it at once leave two rows; the earliest one counts.
/// </summary>
[RedbScheme("identity.dp_key_import")]
public class DataProtectionKeyImportProps
{
    /// <summary>The moment the key ring started to live in redb.</summary>
    public DateTimeOffset StartedAt { get; set; }
}
