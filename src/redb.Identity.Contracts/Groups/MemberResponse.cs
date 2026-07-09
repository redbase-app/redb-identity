using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Groups;

public sealed class MemberResponse
{
    [JsonPropertyName("membershipId")]
    public long MembershipId { get; set; }

    [JsonPropertyName("userId")]
    public long UserId { get; set; }

    [JsonPropertyName("groupId")]
    public long GroupId { get; set; }

    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("joinedAt")]
    public DateTimeOffset? JoinedAt { get; set; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; set; }
}
