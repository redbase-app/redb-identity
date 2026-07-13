namespace redb.Identity.Contracts.Scim;

/// <summary>
/// Provides static SCIM 2.0 schema definitions for User and Group (RFC 7643 §7).
/// </summary>
public static class ScimSchemaDefinitions
{
    public static ScimSchema UserSchema { get; } = new()
    {
        Id = ScimConstants.UserSchema,
        Name = "User",
        Description = "User Account",
        Meta = new ScimMeta { ResourceType = "Schema", Location = "/scim/v2/Schemas/" + ScimConstants.UserSchema },
        Attributes =
        [
            Attr("userName", required: true, mutability: "immutable", uniqueness: "server", description: "Unique identifier for the User, typically used by the user to directly authenticate."),
            Attr("name", type: "complex", description: "The components of the user's real name.", subAttributes:
            [
                Attr("formatted", description: "The full name."),
                Attr("familyName", description: "The family name."),
                Attr("givenName", description: "The given name.")
            ]),
            Attr("displayName", description: "The name displayed to end-users."),
            Attr("active", type: "boolean", description: "Administrative status of the user."),
            Attr("password", mutability: "writeOnly", returned: "never", description: "The user's cleartext password. Write-only."),
            Attr("emails", type: "complex", multiValued: true, description: "Email addresses for the user.", subAttributes:
            [
                Attr("value", description: "The email address value."),
                Attr("type", description: "The type of email (e.g., work, home)."),
                Attr("primary", type: "boolean", description: "Whether this is the primary email.")
            ]),
            Attr("phoneNumbers", type: "complex", multiValued: true, description: "Phone numbers for the user.", subAttributes:
            [
                Attr("value", description: "The phone number."),
                Attr("type", description: "The type (e.g., work, mobile)."),
                Attr("primary", type: "boolean", description: "Whether this is the primary phone number.")
            ]),
            Attr("addresses", type: "complex", multiValued: true, description: "Addresses for the user.", subAttributes:
            [
                Attr("streetAddress"), Attr("locality"), Attr("region"),
                Attr("postalCode"), Attr("country"), Attr("formatted"),
                Attr("type"), Attr("primary", type: "boolean")
            ]),
            Attr("photos", type: "complex", multiValued: true, description: "URLs of photos of the user.", subAttributes:
            [
                Attr("value", type: "reference", description: "The photo URI."),
                Attr("type", description: "The type (e.g., photo, thumbnail).")
            ]),
            Attr("groups", type: "complex", multiValued: true, mutability: "readOnly", description: "A list of groups to which the user belongs.", subAttributes:
            [
                Attr("value", mutability: "readOnly", description: "The group id."),
                Attr("$ref", mutability: "readOnly", type: "reference", description: "The URI of the group."),
                Attr("display", mutability: "readOnly", description: "The group display name.")
            ]),
            Attr("externalId", description: "An identifier for the resource as defined by the provisioning client.", caseExact: true),
            Attr("id", mutability: "readOnly", returned: "always", uniqueness: "server", description: "Unique identifier assigned by the service provider.", caseExact: true),
            Attr("meta", type: "complex", mutability: "readOnly", description: "Resource metadata.", subAttributes:
            [
                Attr("resourceType", mutability: "readOnly"),
                Attr("created", type: "dateTime", mutability: "readOnly"),
                Attr("lastModified", type: "dateTime", mutability: "readOnly"),
                Attr("location", mutability: "readOnly", type: "reference")
            ])
        ]
    };

    public static ScimSchema GroupSchema { get; } = new()
    {
        Id = ScimConstants.GroupSchema,
        Name = "Group",
        Description = "Group",
        Meta = new ScimMeta { ResourceType = "Schema", Location = "/scim/v2/Schemas/" + ScimConstants.GroupSchema },
        Attributes =
        [
            Attr("displayName", required: true, description: "A human-readable name for the Group."),
            Attr("members", type: "complex", multiValued: true, description: "A list of members of the Group.", subAttributes:
            [
                Attr("value", description: "Identifier of the member."),
                Attr("$ref", type: "reference", description: "The URI of the member."),
                Attr("display", mutability: "readOnly", description: "The display name of the member.")
            ]),
            Attr("externalId", description: "An identifier for the resource as defined by the provisioning client.", caseExact: true),
            Attr("id", mutability: "readOnly", returned: "always", uniqueness: "server", description: "Unique identifier assigned by the service provider.", caseExact: true),
            Attr("meta", type: "complex", mutability: "readOnly", description: "Resource metadata.", subAttributes:
            [
                Attr("resourceType", mutability: "readOnly"),
                Attr("created", type: "dateTime", mutability: "readOnly"),
                Attr("lastModified", type: "dateTime", mutability: "readOnly"),
                Attr("location", mutability: "readOnly", type: "reference")
            ])
        ]
    };

    /// <summary>
    /// Enterprise User extension (RFC 7643 §4.3) — the attribute set corporate provisioning sends.
    /// <c>manager.displayName</c> and <c>manager.$ref</c> are declared readOnly because the provider
    /// resolves them from the referenced user; a client that writes them is ignored, by design.
    /// </summary>
    public static ScimSchema EnterpriseUserSchema { get; } = new()
    {
        Id = ScimConstants.EnterpriseUserSchema,
        Name = "EnterpriseUser",
        Description = "Enterprise User",
        Meta = new ScimMeta { ResourceType = "Schema", Location = "/scim/v2/Schemas/" + ScimConstants.EnterpriseUserSchema },
        Attributes =
        [
            Attr("employeeNumber", description: "Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization."),
            Attr("costCenter", description: "Identifies the name of a cost center."),
            Attr("organization", description: "Identifies the name of an organization."),
            Attr("division", description: "Identifies the name of a division."),
            Attr("department", description: "Identifies the name of a department."),
            Attr("manager", type: "complex", description: "The user's manager.", subAttributes:
            [
                Attr("value", description: "The id of the SCIM resource representing the user's manager."),
                Attr("$ref", type: "reference", description: "The URI of the SCIM resource representing the user's manager."),
                Attr("displayName", mutability: "readOnly", description: "The displayName of the user's manager, resolved by the service provider.")
            ])
        ]
    };

    private static ScimSchemaAttribute Attr(
        string name,
        string type = "string",
        bool multiValued = false,
        bool required = false,
        string? description = null,
        string mutability = "readWrite",
        string returned = "default",
        string uniqueness = "none",
        bool caseExact = false,
        List<ScimSchemaAttribute>? subAttributes = null)
    {
        return new ScimSchemaAttribute
        {
            Name = name,
            Type = type,
            MultiValued = multiValued,
            Required = required,
            Description = description,
            Mutability = mutability,
            Returned = returned,
            Uniqueness = uniqueness,
            CaseExact = caseExact,
            SubAttributes = subAttributes
        };
    }
}
