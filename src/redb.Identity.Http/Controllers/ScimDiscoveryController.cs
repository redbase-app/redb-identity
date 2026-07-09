using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Scim;
using redb.Route.Abstractions;
using redb.Route.Controllers;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// SCIM 2.0 discovery endpoints (RFC 7644 §4).
/// No authentication required — returns server capabilities.
/// </summary>
[Route("")]
public class ScimDiscoveryController : RedbController
{
    [HttpGet("ServiceProviderConfig")]
    public Task<object?> ServiceProviderConfig()
    {
        // H1: reflect runtime SCIM Bulk capability + limits per the configured options.
        var opts = Context.GetServiceProvider()?.GetService<IOptions<IdentityTransportOptions>>()?.Value;
        var bulk = new ScimBulkConfig
        {
            Supported = opts?.Features.EnableScimBulk ?? false,
            MaxOperations = opts?.ScimBulk.MaxOperations ?? 1000,
            MaxPayloadSize = opts?.ScimBulk.MaxPayloadSize ?? 1_048_576
        };
        var config = new ScimServiceProviderConfig
        {
            Bulk = bulk,
            Meta = new ScimMeta
            {
                ResourceType = "ServiceProviderConfig",
                Location = "/scim/v2/ServiceProviderConfig"
            }
        };
        return Task.FromResult<object?>(config);
    }

    [HttpGet("ResourceTypes")]
    public Task<object?> ResourceTypes()
    {
        var types = new ScimListResponse<ScimResourceType>
        {
            TotalResults = 2,
            ItemsPerPage = 2,
            Resources =
            [
                new ScimResourceType
                {
                    Id = "User",
                    Name = "User",
                    Endpoint = "/Users",
                    Schema = ScimConstants.UserSchema,
                    Description = "User Account",
                    Meta = new ScimMeta { ResourceType = "ResourceType", Location = "/scim/v2/ResourceTypes/User" }
                },
                new ScimResourceType
                {
                    Id = "Group",
                    Name = "Group",
                    Endpoint = "/Groups",
                    Schema = ScimConstants.GroupSchema,
                    Description = "Group",
                    Meta = new ScimMeta { ResourceType = "ResourceType", Location = "/scim/v2/ResourceTypes/Group" }
                }
            ]
        };
        return Task.FromResult<object?>(types);
    }

    [HttpGet("ResourceTypes/{id}")]
    public Task<object?> ResourceType([FromRoute("id")] string id)
    {
        ScimResourceType? rt = id switch
        {
            "User" => new ScimResourceType
            {
                Id = "User", Name = "User", Endpoint = "/Users",
                Schema = ScimConstants.UserSchema, Description = "User Account",
                Meta = new ScimMeta { ResourceType = "ResourceType", Location = "/scim/v2/ResourceTypes/User" }
            },
            "Group" => new ScimResourceType
            {
                Id = "Group", Name = "Group", Endpoint = "/Groups",
                Schema = ScimConstants.GroupSchema, Description = "Group",
                Meta = new ScimMeta { ResourceType = "ResourceType", Location = "/scim/v2/ResourceTypes/Group" }
            },
            _ => null
        };

        if (rt is null)
            return Task.FromResult<object?>(new ScimError { Status = "404", Detail = $"ResourceType '{id}' not found" });

        return Task.FromResult<object?>(rt);
    }

    [HttpGet("Schemas")]
    public Task<object?> Schemas()
    {
        var schemas = new ScimListResponse<ScimSchema>
        {
            TotalResults = 2,
            ItemsPerPage = 2,
            Resources = [ScimSchemaDefinitions.UserSchema, ScimSchemaDefinitions.GroupSchema]
        };
        return Task.FromResult<object?>(schemas);
    }

    [HttpGet("Schemas/{id}")]
    public Task<object?> Schema([FromRoute("id")] string id)
    {
        ScimSchema? schema = id switch
        {
            ScimConstants.UserSchema => ScimSchemaDefinitions.UserSchema,
            ScimConstants.GroupSchema => ScimSchemaDefinitions.GroupSchema,
            _ => null
        };

        if (schema is null)
            return Task.FromResult<object?>(new ScimError { Status = "404", Detail = $"Schema '{id}' not found" });

        return Task.FromResult<object?>(schema);
    }
}
