using redb.Core.Attributes;

namespace redb.Identity.DataProtection;

/// <summary>
/// PROPS Props for ASP.NET DataProtection XML key storage.
/// Persists encryption keys across restarts and cluster nodes.
/// Base fields: name = friendly key name.
/// </summary>
[RedbScheme("identity.dp_key")]
public class DataProtectionKeyProps
{
    /// <summary>Friendly name for the key.</summary>
    public string? FriendlyName { get; set; }

    /// <summary>Serialized XML content of the DataProtection key.</summary>
    public string? XmlContent { get; set; }
}
