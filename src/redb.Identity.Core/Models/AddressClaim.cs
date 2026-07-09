namespace redb.Identity.Core.Models;

/// <summary>
/// OIDC structured address claim (§5.1.1).
/// Stored as nested PROPS object inside <see cref="UserProps"/>.
/// Serialized to JSON when emitted as the <c>address</c> claim.
/// </summary>
public class AddressClaim
{
    /// <summary>Full street address (may include house number, street name, PO BOX, etc.).</summary>
    public string? StreetAddress { get; set; }

    /// <summary>City or locality.</summary>
    public string? Locality { get; set; }

    /// <summary>State, province, prefecture, or region.</summary>
    public string? Region { get; set; }

    /// <summary>Zip code or postal code.</summary>
    public string? PostalCode { get; set; }

    /// <summary>Country name or ISO 3166-1 alpha-2 code.</summary>
    public string? Country { get; set; }

    /// <summary>Full mailing address, formatted for display or use on a mailing label.</summary>
    public string? Formatted { get; set; }
}
