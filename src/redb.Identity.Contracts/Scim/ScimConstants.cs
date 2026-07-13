namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 constants (RFC 7643/7644).
/// </summary>
public static class ScimConstants
{
    // ── Schema URIs (RFC 7643 §8) ──

    public const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    public const string GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";

    /// <summary>
    /// Enterprise User extension (RFC 7643 §4.3) — department / manager / employeeNumber and friends.
    /// Doubles as the JSON member name on the User resource: an extension is namespaced by its URN,
    /// not by a plain attribute name.
    /// </summary>
    public const string EnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    public const string ServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
    public const string ResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
    public const string SchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema";

    // ── Message schemas (RFC 7644) ──

    public const string ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public const string PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    public const string BulkRequestSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    public const string BulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
    public const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";

    // ── Content type (RFC 7644 §3.1) ──

    public const string MediaType = "application/scim+json";

    // ── Endpoints ──

    public const string UsersEndpoint = "/Users";
    public const string GroupsEndpoint = "/Groups";
    public const string BulkEndpoint = "/Bulk";
    public const string ServiceProviderConfigEndpoint = "/ServiceProviderConfig";
    public const string SchemasEndpoint = "/Schemas";
    public const string ResourceTypesEndpoint = "/ResourceTypes";
}
