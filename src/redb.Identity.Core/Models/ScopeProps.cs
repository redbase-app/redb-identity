using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS Props for OAuth 2.0 scope definition.
/// Base fields: name = scope display name.
/// </summary>
[RedbScheme("identity.scope")]
public class ScopeProps
{
    /// <summary>
    /// Unique scope identifier (e.g. "openid", "profile", "api").
    /// Stored in root <c>_objects.value_string</c> (indexed), not in PROPS.
    /// </summary>
    [RedbIgnore]
    public string? ScopeName { get; set; }

    /// <summary>Human-readable description.</summary>
    public string? Description { get; set; }

    /// <summary>Resource servers this scope grants access to.</summary>
    public string[]? Resources { get; set; }

    /// <summary>Localized display names: { "en": "Profile", "ru": "Профиль" }.</summary>
    public Dictionary<string, string>? DisplayNames { get; set; }

    /// <summary>Localized descriptions.</summary>
    public Dictionary<string, string>? Descriptions { get; set; }

    /// <summary>Extensible properties bag.</summary>
    public Dictionary<string, string>? Properties { get; set; }
}
