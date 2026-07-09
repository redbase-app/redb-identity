using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Roles;

/// <summary>
/// Null fields preserve the existing value (PATCH semantics). Name +
/// Audience + ApplicationId are IMMUTABLE post-create — rename = delete +
/// re-create. IsSystem is server-managed.
/// </summary>
public sealed class UpdateRoleRequest
{
    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
