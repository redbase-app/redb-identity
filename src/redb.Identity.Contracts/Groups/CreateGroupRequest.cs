using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class CreateGroupRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "name is required.")]
    [StringLength(200, MinimumLength = 1)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = null!;

    [JsonPropertyName("groupType")]
    public string? GroupType { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("parentGroupId")]
    public long? ParentGroupId { get; set; }
}
