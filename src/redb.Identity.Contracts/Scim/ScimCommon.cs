using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 resource metadata (RFC 7643 §3.1).
/// </summary>
public class ScimMeta
{
    [JsonPropertyName("resourceType")]
    public string? ResourceType { get; set; }

    [JsonPropertyName("created")]
    public DateTimeOffset? Created { get; set; }

    [JsonPropertyName("lastModified")]
    public DateTimeOffset? LastModified { get; set; }

    [JsonPropertyName("location")]
    public string? Location { get; set; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; set; }
}

/// <summary>
/// Multi-valued attribute entry (emails, phoneNumbers, etc.) per RFC 7643 §2.4.
/// </summary>
public class ScimMultiValuedAttribute
{
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Type { get; set; }

    [JsonPropertyName("primary")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Primary { get; set; }
}

/// <summary>
/// Member reference (for groups) per RFC 7643 §4.2.
/// </summary>
public class ScimMemberRef
{
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("display")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Display { get; set; }

    [JsonPropertyName("$ref")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ref { get; set; }
}

/// <summary>
/// Group reference (read-only on User) per RFC 7643 §4.1.2.
/// </summary>
public class ScimGroupRef
{
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("display")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Display { get; set; }

    [JsonPropertyName("$ref")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ref { get; set; }
}
