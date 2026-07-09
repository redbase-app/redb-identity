using System.Text.Json;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 Bulk request (RFC 7644 §3.7).
/// </summary>
public class ScimBulkRequest
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.BulkRequestSchema];

    /// <summary>Number of errors before stopping. 0 = continue on all errors.</summary>
    [JsonPropertyName("failOnErrors")]
    public int FailOnErrors { get; set; }

    [JsonPropertyName("Operations")]
    public List<ScimBulkOperation> Operations { get; set; } = [];
}

/// <summary>
/// Single bulk operation (RFC 7644 §3.7).
/// </summary>
public class ScimBulkOperation
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = null!;

    [JsonPropertyName("path")]
    public string Path { get; set; } = null!;

    [JsonPropertyName("bulkId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BulkId { get; set; }

    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Data { get; set; }
}

/// <summary>
/// SCIM 2.0 Bulk response (RFC 7644 §3.7).
/// </summary>
public class ScimBulkResponse
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.BulkResponseSchema];

    [JsonPropertyName("Operations")]
    public List<ScimBulkOperationResponse> Operations { get; set; } = [];
}

/// <summary>
/// Single bulk operation result (RFC 7644 §3.7).
/// </summary>
public class ScimBulkOperationResponse
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = null!;

    [JsonPropertyName("bulkId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BulkId { get; set; }

    [JsonPropertyName("location")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Location { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = null!;

    [JsonPropertyName("response")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Response { get; set; }
}
