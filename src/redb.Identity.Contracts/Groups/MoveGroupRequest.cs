using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class MoveGroupRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "newParentGroupId must be a positive integer.")]
    [JsonPropertyName("newParentGroupId")]
    public long NewParentGroupId { get; set; }
}
