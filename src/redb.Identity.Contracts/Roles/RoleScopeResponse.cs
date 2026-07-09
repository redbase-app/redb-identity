using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Roles;

/// <summary>
/// One attached scope on a role's permission tab.
/// </summary>
public sealed class RoleScopeResponse
{
    [JsonPropertyName("roleId")]
    public long RoleId { get; set; }

    [JsonPropertyName("scopeId")]
    public long ScopeId { get; set; }

    [JsonPropertyName("scopeName")]
    public string? ScopeName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("attachedAt")]
    public DateTimeOffset AttachedAt { get; set; }
}
