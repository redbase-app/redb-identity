using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class UpdateMemberRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "role is required.")]
    [JsonPropertyName("role")]
    public string Role { get; set; } = null!;
}
