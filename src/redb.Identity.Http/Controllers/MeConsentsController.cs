using redb.Identity.Contracts.Consents;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H3 (v1.0 DoD §6): self-service consent management at
/// <c>/api/v1/identity/me/consents</c>. Returns / revokes the caller's own valid
/// permanent OAuth/OIDC consent grants. Caller id is taken from the access-token
/// subject; admins manage consents for other users via <c>/users/{id}/consents</c>.
/// Auth: Bearer with <c>identity:manage</c> or <c>identity:account</c> scope.
/// </summary>
[Route("me/consents")]
public class MeConsentsController : IdentityControllerBase
{
    /// <summary>List the caller's valid permanent consent grants.</summary>
    [HttpGet]
    public async Task<object?> List()
    {
        return await Forward(IdentityEndpoints.MeConsents, "list",
            new Dictionary<string, object?>());
    }

    /// <summary>Revoke the caller's permanent consent grant for a single client.</summary>
    [HttpDelete("{clientId}")]
    public async Task<object?> Revoke([FromRoute("clientId")] string clientId)
    {
        return await Forward(IdentityEndpoints.MeConsents, "revoke",
            new MeRevokeConsentRequest { ClientId = clientId });
    }

    /// <summary>
    /// Grant or extend the caller's permanent consent for an application. Used by native
    /// consent UIs (e.g. the BFF Razor page) after the user approves a <c>consent_required</c>
    /// dialog raised by <c>/connect/authorize</c>. Existing valid permanent grants are
    /// merged (union of scopes) rather than replaced.
    /// </summary>
    [HttpPost]
    public async Task<object?> Grant([FromBody] GrantMyConsentRequest request)
    {
        return await Forward(IdentityEndpoints.MeConsents, "grant", request);
    }
}
