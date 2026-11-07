using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 ListResponse (RFC 7644 §3.4.2).
/// </summary>
public class ScimListResponse<T>
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.ListResponseSchema];

    [JsonPropertyName("totalResults")]
    public int TotalResults { get; set; }

    /// <summary>1-based start index (RFC 7644 §3.4.2.4).</summary>
    [JsonPropertyName("startIndex")]
    public int StartIndex { get; set; } = 1;

    [JsonPropertyName("itemsPerPage")]
    public int ItemsPerPage { get; set; }

    [JsonPropertyName("Resources")]
    public List<T> Resources { get; set; } = [];
}
