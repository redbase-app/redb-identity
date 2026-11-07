using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace redb.Identity.Contracts.Validation;

/// <summary>
/// Centralised DataAnnotations-driven request DTO validation.
/// Returns a uniform problem response compatible with the management API
/// error contract — <c>{ error = "invalid_request", error_description, validation_errors[] }</c> —
/// which <see cref="redb.Identity.Http.Processors.HttpIdentityProcessors"/>
/// then maps to HTTP 400 (E6 / D5 unified error format).
/// </summary>
public static class RequestValidator
{
    /// <summary>
    /// Validates <paramref name="request"/> using <see cref="Validator.TryValidateObject"/>.
    /// Returns <c>null</c> if the DTO is valid; otherwise a problem object the controller
    /// can return as-is (the post-dispatch status mapper turns it into HTTP 400).
    /// </summary>
    public static object? Validate(object? request)
    {
        if (request is null)
        {
            return new
            {
                error = "validation_error",
                error_description = "Request body is required.",
                validation_errors = System.Array.Empty<string>()
            };
        }

        var ctx = new ValidationContext(request);
        var results = new List<ValidationResult>();
        if (Validator.TryValidateObject(request, ctx, results, validateAllProperties: true))
            return null;

        var errors = results
            .Select(r => r.ErrorMessage ?? "Invalid value.")
            .ToArray();

        return new
        {
            error = "validation_error",
            error_description = errors.Length > 0 ? errors[0] : "Request validation failed.",
            validation_errors = errors
        };
    }
}
