using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using redb.Identity.Contracts.Scim;

namespace redb.Identity.Contracts.Validation;

/// <summary>
/// SCIM 2.0 request DTO validation. Returns a populated <see cref="ScimError"/>
/// (RFC 7644 §3.12) when validation fails so the SCIM status mapper turns
/// the response into HTTP 400 with <c>scimType=invalidValue</c>.
/// </summary>
public static class ScimRequestValidator
{
    /// <summary>Validates the SCIM request DTO.</summary>
    public static ScimError? Validate(object? request)
    {
        if (request is null)
        {
            return new ScimError
            {
                Status = "400",
                ScimType = "invalidValue",
                Detail = "Request body is required."
            };
        }

        var ctx = new ValidationContext(request);
        var results = new List<ValidationResult>();
        if (Validator.TryValidateObject(request, ctx, results, validateAllProperties: true))
            return null;

        var detail = results
            .Select(r => r.ErrorMessage ?? "Invalid value.")
            .FirstOrDefault() ?? "Request validation failed.";

        return new ScimError
        {
            Status = "400",
            ScimType = "invalidValue",
            Detail = detail
        };
    }
}
