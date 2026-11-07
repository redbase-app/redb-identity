using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 ServiceProviderConfig resource (RFC 7643 §5).
/// </summary>
public class ScimServiceProviderConfig
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.ServiceProviderConfigSchema];

    [JsonPropertyName("patch")]
    public ScimSupported Patch { get; set; } = new() { Supported = true };

    [JsonPropertyName("bulk")]
    public ScimBulkConfig Bulk { get; set; } = new();

    [JsonPropertyName("filter")]
    public ScimFilterConfig Filter { get; set; } = new();

    [JsonPropertyName("changePassword")]
    public ScimSupported ChangePassword { get; set; } = new() { Supported = false };

    [JsonPropertyName("sort")]
    public ScimSupported Sort { get; set; } = new() { Supported = true };

    [JsonPropertyName("etag")]
    public ScimSupported Etag { get; set; } = new() { Supported = true };

    [JsonPropertyName("authenticationSchemes")]
    public List<ScimAuthenticationScheme> AuthenticationSchemes { get; set; } =
    [
        new()
        {
            Type = "oauthbearertoken",
            Name = "OAuth 2.0 Bearer Token",
            Description = "Authentication scheme using OAuth 2.0 Bearer Token (RFC 6750)"
        }
    ];

    [JsonPropertyName("meta")]
    public ScimMeta? Meta { get; set; }
}

public class ScimSupported
{
    [JsonPropertyName("supported")]
    public bool Supported { get; set; }
}

public class ScimBulkConfig
{
    [JsonPropertyName("supported")]
    public bool Supported { get; set; } = false;

    [JsonPropertyName("maxOperations")]
    public int MaxOperations { get; set; } = 1000;

    [JsonPropertyName("maxPayloadSize")]
    public int MaxPayloadSize { get; set; } = 1048576;
}

public class ScimFilterConfig
{
    [JsonPropertyName("supported")]
    public bool Supported { get; set; } = true;

    [JsonPropertyName("maxResults")]
    public int MaxResults { get; set; } = 100;
}

public class ScimAuthenticationScheme
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = null!;

    [JsonPropertyName("name")]
    public string Name { get; set; } = null!;

    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }
}

/// <summary>
/// SCIM 2.0 ResourceType (RFC 7643 §6).
/// </summary>
public class ScimResourceType
{
    [JsonPropertyName("schemas")]
    public string[] Schemas { get; set; } = [ScimConstants.ResourceTypeSchema];

    [JsonPropertyName("id")]
    public string Id { get; set; } = null!;

    [JsonPropertyName("name")]
    public string Name { get; set; } = null!;

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = null!;

    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }

    [JsonPropertyName("schema")]
    public string Schema { get; set; } = null!;

    /// <summary>
    /// RFC 7643 §6 — the schema extensions this resource type carries. Omitted when there are none,
    /// so the Group resource type stays byte-identical to what it was.
    /// </summary>
    [JsonPropertyName("schemaExtensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ScimSchemaExtension>? SchemaExtensions { get; set; }

    [JsonPropertyName("meta")]
    public ScimMeta? Meta { get; set; }
}

/// <summary>
/// A schema extension declared on a ResourceType (RFC 7643 §6). <c>required</c> says whether the
/// extension MUST be present on every resource of that type — for Enterprise User it is false: a
/// user without a department is a perfectly ordinary user.
/// </summary>
public class ScimSchemaExtension
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = null!;

    [JsonPropertyName("required")]
    public bool Required { get; set; }
}
