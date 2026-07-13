using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// OIDC profile extension for a user stored in <c>_users</c>.
/// Credentials (login, password), email, phone and status live in the relational
/// <c>_users</c> table. This PROPS extension stores OIDC-specific profile claims.
/// Linked via <c>RedbObject.key = _users._id</c>.
/// </summary>
[RedbScheme("identity.user")]
public class UserProps
{
    // --- OIDC Standard Claims (profile scope) ---
    //
    // The full set OIDC Core §5.1 defines for `scope=profile`. The OIDF conformance suite
    // (oidcc-scope-profile / oidcc-scope-all) checks userinfo against exactly this list and warns
    // for every one the OP fails to return. They are plain PROPS fields — adding them needed no
    // migration and no schema deploy; the next request simply saw them.

    /// <summary>Given name (first name). OIDC: given_name.</summary>
    public string? GivenName { get; set; }

    /// <summary>Family name (last name). OIDC: family_name.</summary>
    public string? FamilyName { get; set; }

    /// <summary>Middle name. OIDC: middle_name.</summary>
    public string? MiddleName { get; set; }

    /// <summary>Casual name the user prefers to be called (e.g. "Mike" for Michael). OIDC: nickname.</summary>
    public string? Nickname { get; set; }

    /// <summary>Shorthand name the RP may use to identify the user in its UI. Defaults to the
    /// login when unset (emitted by <c>IdentityPrincipalBuilder</c>). OIDC: preferred_username.</summary>
    public string? PreferredUsername { get; set; }

    /// <summary>URL of the user's profile page. OIDC: profile.</summary>
    public string? Profile { get; set; }

    /// <summary>URL of the user's profile picture. OIDC: picture.</summary>
    public string? Picture { get; set; }

    /// <summary>URL of the user's web page or blog. OIDC: website.</summary>
    public string? Website { get; set; }

    /// <summary>Gender. OIDC: gender ("female" / "male" / other values are allowed).</summary>
    public string? Gender { get; set; }

    /// <summary>Birthday as ISO 8601 <c>YYYY-MM-DD</c> (year alone is allowed). OIDC: birthdate.</summary>
    public string? Birthdate { get; set; }

    /// <summary>IANA time-zone name, e.g. "Europe/Moscow". OIDC: zoneinfo.</summary>
    public string? ZoneInfo { get; set; }

    /// <summary>BCP 47 language tag, e.g. "ru-RU". OIDC: locale.</summary>
    public string? Locale { get; set; }

    /// <summary>When the profile was last changed. Emitted as the OIDC <c>updated_at</c> claim
    /// (a JSON number — seconds since the epoch). Falls back to the user's registration date.</summary>
    public DateTimeOffset? UpdatedAt { get; set; }

    // --- OIDC Standard Claims (email scope) ---

    /// <summary>Whether the email has been verified. OIDC: email_verified.</summary>
    public bool EmailVerified { get; set; }

    // --- OIDC Standard Claims (phone scope) ---

    /// <summary>Whether the phone number has been verified. OIDC: phone_number_verified.</summary>
    public bool PhoneNumberVerified { get; set; }

    // --- OIDC Standard Claims (address scope) ---

    /// <summary>Structured address claim (OIDC §5.1.1). Stored as nested PROPS object.</summary>
    public AddressClaim? Address { get; set; }

    // --- Custom claims ---

    /// <summary>Arbitrary key-value claims emitted into tokens. Keys become claim types, values become claim values.</summary>
    public Dictionary<string, string>? CustomClaims { get; set; }

    // --- SCIM provisioning ---

    /// <summary>SCIM externalId (RFC 7643 §3.1) — identifier assigned by the provisioning client. NOT related to federation.</summary>
    public string? ScimExternalId { get; set; }

    // --- SCIM Enterprise User extension (RFC 7643 §4.3) ---
    //
    // What corporate provisioning (Okta / Entra ID / Workday) pushes on the first sync. Props, so
    // adding them costs no migration: an existing user simply has them null until someone writes one.

    /// <summary>RFC 7643 §4.3 — employeeNumber.</summary>
    public string? EmployeeNumber { get; set; }

    /// <summary>RFC 7643 §4.3 — costCenter.</summary>
    public string? CostCenter { get; set; }

    /// <summary>RFC 7643 §4.3 — organization.</summary>
    public string? Organization { get; set; }

    /// <summary>RFC 7643 §4.3 — division.</summary>
    public string? Division { get; set; }

    /// <summary>RFC 7643 §4.3 — department.</summary>
    public string? Department { get; set; }

    /// <summary>
    /// RFC 7643 §4.3 — <c>manager.value</c>: the <c>_users._id</c> of this user's manager, as a
    /// string because SCIM ids are strings on the wire. <c>$ref</c> and <c>displayName</c> are NOT
    /// stored: the spec marks displayName read-only (the provider resolves it) and $ref is derived
    /// from the id plus the request's base URL. Storing either would let them rot out of sync with
    /// the manager's actual record.
    /// </summary>
    public string? ManagerId { get; set; }

    // --- Federation linking (multi-provider) ---

    /// <summary>
    /// Federation identities keyed by provider ID (e.g. "google", "corp-ldap").
    /// Stored natively in PROPS as separate rows (not JSON).
    /// Hot-path reverse lookup uses <c>RedbObject.value_string</c> = "{providerId}:{sub}".
    /// </summary>
    public Dictionary<string, ExternalIdentity>? ExternalIdentities { get; set; }

    // --- H10: password policy state ---

    /// <summary>
    /// UTC timestamp of the last password change for this user. Updated by every successful
    /// admin Create / admin Change / self-service Change / SCIM Create / SCIM PATCH path
    /// (see <c>IdentityProcessorHelpers.RecordPasswordChangedAsync</c>). When
    /// <see cref="Configuration.PasswordPolicyOptions.MaxAge"/> is greater than zero, login
    /// compares <c>now - PasswordChangedAt</c> against MaxAge and forces a change when
    /// expired. Null means the value was never recorded — treated as "not expired" for
    /// backward compatibility with users created before H10.
    /// </summary>
    public DateTimeOffset? PasswordChangedAt { get; set; }

    /// <summary>
    /// H8 (v1.0 DoD §4 gap (d)): true iff the user has set their own password through any
    /// of the password-change paths (admin <c>SetPassword</c>, self-service
    /// <c>/me/password</c>, SCIM PATCH, registration with explicit password). Federated
    /// auto-provisioning leaves this false even though <c>_users.password_hash</c> is filled
    /// with a random value (so the local row is internally consistent). Used by the
    /// <c>MeFederatedIdentitiesProcessor</c> "unlink last social" safeguard: a user whose
    /// only authentication factor is a federated link cannot remove that link without
    /// first setting a local password.
    /// </summary>
    public bool HasUserPassword { get; set; }
}
