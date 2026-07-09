using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Shared helpers for self-service <c>/me/*</c> processors: extracts the caller user id
/// from the bearer-auth context (populated upstream by
/// <see cref="ManagementBearerAuthProcessor"/>), loads the OIDC profile extension, and
/// projects core user + OIDC props into the public <see cref="UserResponse"/> DTO used
/// by both admin and self-service endpoints.
/// </summary>
internal static class MeProcessorHelpers
{
    /// <summary>
    /// Extracts the internal numeric caller id from the auth context populated by
    /// <see cref="ManagementBearerAuthProcessor"/>. The public <c>sub</c> claim is now a
    /// GUID, so the bigint <c>_users._id</c> is mirrored in the
    /// <c>identity:management-user-id</c> exchange property (sourced from the
    /// <c>redb:user_id</c> access-token claim). Returns <c>null</c> when the property is
    /// absent — e.g., client_credentials tokens or genuinely anonymous endpoints — so
    /// callers can decide whether to reject or treat as anonymous.
    /// </summary>
    public static long? TryGetCallerUserId(IExchange exchange)
    {
        if (!exchange.Properties.TryGetValue("identity:management-user-id", out var raw))
            return null;

        return raw switch
        {
            long l when l > 0 => l,
            int i when i > 0 => i,
            string s when long.TryParse(s, out var id) && id > 0 => id,
            _ => null
        };
    }

    /// <summary>
    /// Diagnostic accessor: returns the raw <c>identity:management-subject</c> value
    /// (or <c>null</c> if the property is not set). Used by <c>/me/*</c> processors to
    /// surface the actual subject in the rejection message so misconfigured hosts can
    /// be debugged without enabling trace logging.
    /// </summary>
    public static string? GetRawCallerSubject(IExchange exchange)
        => exchange.Properties.TryGetValue("identity:management-subject", out var raw)
            && raw is string s ? s : null;

    /// <summary>
    /// Halts the exchange with a structured error body and an HTTP-status hint. Mirrors
    /// <c>MeSessionsProcessor.Reject</c> so every <c>/me/*</c> processor reports failures
    /// identically — including the <c>exchange.Stop()</c> that ensures downstream
    /// processors on the same route do not execute.
    /// </summary>
    public static void Reject(IExchange exchange, int statusCode, string error, string description)
    {
        exchange.Out = new Message(new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        });
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
        exchange.Exception = new InvalidOperationException(description);
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }

    /// <summary>Loads the OIDC extension <see cref="UserProps"/> linked via <c>key=userId</c>.</summary>
    public static Task<RedbObject<UserProps>?> LoadOidcProps(IRedbService redb, long userId)
        => redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();

    /// <summary>
    /// Projects a Core user + OIDC extension into the public <see cref="UserResponse"/>
    /// DTO. Mirrors <c>UserManagementProcessor.MapToResponse</c>; both paths return the
    /// same wire shape so that admin and self-service clients can reuse a single model.
    /// </summary>
    public static UserResponse MapToResponse(
        IRedbUser user, UserProps? oidc,
        DateTimeOffset? createdAt, DateTimeOffset? modifiedAt) => new()
    {
        Id = user.Id,
        Login = user.Login,
        DisplayName = user.Name,
        Status = user.Enabled ? "active" : "blocked",
        Email = user.Email,
        EmailVerified = oidc?.EmailVerified ?? false,
        PhoneNumber = user.Phone,
        PhoneNumberVerified = oidc?.PhoneNumberVerified ?? false,
        GivenName = oidc?.GivenName,
        FamilyName = oidc?.FamilyName,
        Picture = oidc?.Picture,
        Address = oidc?.Address is { } addr ? new AddressDto
        {
            StreetAddress = addr.StreetAddress,
            Locality = addr.Locality,
            Region = addr.Region,
            PostalCode = addr.PostalCode,
            Country = addr.Country,
            Formatted = addr.Formatted
        } : null,
        CustomClaims = oidc?.CustomClaims,
        ExternalIdentities = oidc?.ExternalIdentities is { Count: > 0 } extIds
            ? extIds.ToDictionary(
                kvp => kvp.Key,
                kvp => new ExternalIdentityDto
                {
                    Sub = kvp.Value.Sub,
                    LinkedAt = kvp.Value.LinkedAt
                })
            : null,
        CreatedAt = createdAt ?? user.DateRegister,
        ModifiedAt = modifiedAt ?? user.DateRegister
    };
}

