using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Contracts.Federation;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H8 (DoD §4 gap (b)/(d)): self-service federated identity management at
/// <c>/api/v1/identity/me/federated-identities</c>. Lets the authenticated user
/// list, link (start a new IdP flow), or unlink one of their federated identities.
/// Auth: Bearer with <c>identity:account</c> scope.
/// </summary>
[Route("me/federated-identities")]
public class MeFederatedIdentitiesController : IdentityControllerBase
{
    /// <summary>List all federated identities linked to the caller's account.</summary>
    [HttpGet]
    public async Task<object?> List()
    {
        return await Forward(IdentityEndpoints.MeFederatedIdentities, "list",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// Start an OIDC link flow for an additional provider. Returns a redirect URL the
    /// front-end opens; on success the existing <c>/connect/federation/callback</c>
    /// detects the embedded LinkUserId and links the new identity instead of logging in.
    /// </summary>
    [HttpPost("link-challenge")]
    public async Task<object?> LinkChallenge([FromBody] LinkFederatedIdentityRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;

        // The HTTP transport's standalone /connect/external-login route injects callbackUrl
        // automatically; this controller-driven endpoint must compute it explicitly from
        // the configured issuer + transport path so the generated state encodes the same
        // callback the IdP will redirect to.
        // callbackUrl is intentionally not computed here. The server-side processor
        // (MeFederatedIdentitiesProcessor.LinkChallenge) now falls back to its own
        // RedbIdentityOptions.Issuer + the standard /connect/federation/callback path
        // when the dict carries no callbackUrl, which is reliable across DI scopes.
        return await Forward(IdentityEndpoints.MeFederatedIdentities, "link-challenge",
            new Dictionary<string, object?>
            {
                ["providerId"] = request.ProviderId,
                ["returnUrl"] = request.ReturnUrl,
            });
    }

    /// <summary>
    /// Remove a federated identity from the caller's account. Refuses with
    /// <c>last_credential_method</c> when the link is the user's only sign-in method
    /// (no other federated identities AND no local password).
    /// </summary>
    [HttpDelete("{providerId}")]
    public async Task<object?> Unlink([FromRoute("providerId")] string providerId)
    {
        return await Forward(IdentityEndpoints.MeFederatedIdentities, "unlink",
            new Dictionary<string, object?> { ["providerId"] = providerId });
    }
}

