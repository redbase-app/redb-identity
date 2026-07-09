using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class AddMemberRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    [JsonPropertyName("userId")]
    public long UserId { get; set; }

    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; set; }
}
