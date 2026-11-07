using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class UpdateGroupRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("groupType")]
    public string? GroupType { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
