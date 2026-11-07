using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Scim;

/// <summary>
/// SCIM 2.0 Enterprise User extension (RFC 7643 §4.3).
/// <para>
/// This is the extension corporate provisioning actually sends. Okta, Entra ID and Workday all
/// push <c>department</c>, <c>manager</c> and <c>employeeNumber</c> on the very first sync — a
/// provider that advertises only the core User schema forces them to drop that data on the floor.
/// </para>
/// <para>
/// It travels as a namespaced member of the User resource, keyed by its schema URN rather than a
/// plain attribute name, and the URN must also appear in the resource's <c>schemas</c> array —
/// that is what tells the client the extension is present rather than merely permitted.
/// </para>
/// </summary>
public class ScimEnterpriseUser
{
    /// <summary>Numeric or alphanumeric identifier assigned by the organisation (RFC 7643 §4.3).</summary>
    [JsonPropertyName("employeeNumber")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EmployeeNumber { get; set; }

    /// <summary>Cost centre the user is booked against.</summary>
    [JsonPropertyName("costCenter")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CostCenter { get; set; }

    /// <summary>Name of the organisation.</summary>
    [JsonPropertyName("organization")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Organization { get; set; }

    /// <summary>Name of the division.</summary>
    [JsonPropertyName("division")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Division { get; set; }

    /// <summary>Name of the department.</summary>
    [JsonPropertyName("department")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Department { get; set; }

    /// <summary>The user's manager (RFC 7643 §4.3 — a complex attribute, not a bare string).</summary>
    [JsonPropertyName("manager")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ScimManager? Manager { get; set; }

    /// <summary>True when nothing is populated — used to decide whether to emit the member at all.</summary>
    [JsonIgnore]
    public bool IsEmpty =>
        string.IsNullOrEmpty(EmployeeNumber)
        && string.IsNullOrEmpty(CostCenter)
        && string.IsNullOrEmpty(Organization)
        && string.IsNullOrEmpty(Division)
        && string.IsNullOrEmpty(Department)
        && string.IsNullOrEmpty(Manager?.Value);
}

/// <summary>
/// The <c>manager</c> complex attribute of the Enterprise User extension (RFC 7643 §4.3).
/// <c>value</c> is the manager's SCIM <c>id</c>; <c>$ref</c> is the URI of that User resource;
/// <c>displayName</c> is read-only and resolved by the provider.
/// </summary>
public class ScimManager
{
    /// <summary>The <c>id</c> of the manager's User resource.</summary>
    [JsonPropertyName("value")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; set; }

    /// <summary>URI of the manager's User resource (RFC 7643 §4.3 — the attribute is literally named "$ref").</summary>
    [JsonPropertyName("$ref")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ref { get; set; }

    /// <summary>The manager's display name. Read-only: the provider resolves it, the client never sets it.</summary>
    [JsonPropertyName("displayName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; set; }
}
