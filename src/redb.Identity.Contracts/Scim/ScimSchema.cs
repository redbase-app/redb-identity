using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 Schema resource (RFC 7643 §7).
/// </summary>
public class ScimSchema
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.SchemaSchema];

    [JsonPropertyName("id")]
    public string Id { get; set; } = null!;

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }

    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }

    [JsonPropertyName("attributes")]
    public List<ScimSchemaAttribute> Attributes { get; set; } = [];

    [JsonPropertyName("meta")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ScimMeta? Meta { get; set; }
}

/// <summary>
/// SCIM Schema attribute definition (RFC 7643 §7).
/// </summary>
public class ScimSchemaAttribute
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = null!;

    [JsonPropertyName("type")]
    public string Type { get; set; } = "string";

    [JsonPropertyName("multiValued")]
    public bool MultiValued { get; set; }

    [JsonPropertyName("required")]
    public bool Required { get; set; }

    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }

    [JsonPropertyName("mutability")]
    public string Mutability { get; set; } = "readWrite";

    [JsonPropertyName("returned")]
    public string Returned { get; set; } = "default";

    [JsonPropertyName("uniqueness")]
    public string Uniqueness { get; set; } = "none";

    [JsonPropertyName("caseExact")]
    public bool CaseExact { get; set; }

    [JsonPropertyName("subAttributes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ScimSchemaAttribute>? SubAttributes { get; set; }
}
