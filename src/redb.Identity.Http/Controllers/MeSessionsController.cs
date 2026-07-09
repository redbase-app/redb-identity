using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H3-SSO (v1.0 DoD §6 scoped-subset): self-service session API at
/// <c>/api/v1/identity/me/sessions</c>. Callers target <b>only</b> their own sessions —
/// user id is derived from the authenticated access-token subject, never from the
/// request body or query.
/// <para>
/// Bearer auth is enforced by the shared management API gate
/// (<c>ManagementBearerAuthProcessor</c>) which accepts either <c>identity:manage</c>
/// or <c>identity:account</c> scope. The downstream <c>MeSessionsProcessor</c> uses
/// the <c>sub</c> claim as the caller id; non-numeric subjects are rejected.
/// </para>
/// </summary>
[Route("me/sessions")]
public class MeSessionsController : IdentityControllerBase
{
    /// <summary>List the caller's own active sessions.</summary>
    [HttpGet]
    public async Task<object?> List()
    {
        return await Forward(IdentityEndpoints.MeSessions, "list",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// Revoke the session bound to the caller's current access token. The session id is
    /// taken from the <c>sid</c> claim \u2014 no body is required. Returns 400
    /// <c>sid_unavailable</c> for tokens without a session binding (e.g. client_credentials).
    /// Declared before <see cref="Revoke"/> so the literal <c>current</c> segment is
    /// registered first; <c>ControllerRegistry</c> also prefers literal over
    /// <c>{sessionId}</c> during resolution, making the ordering a belt-and-braces
    /// protection rather than a correctness requirement.
    /// </summary>
    [HttpDelete("current")]
    public async Task<object?> RevokeCurrent()
    {
        return await Forward(IdentityEndpoints.MeSessions, "revoke-current",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// Revoke all sessions of the caller except the current one (identified by the
    /// <c>sid</c> claim of the access token). If the token carries no <c>sid</c> all
    /// sessions are revoked. Declared before <see cref="Revoke"/> so the literal
    /// <c>others</c> segment is registered first — same defensive ordering as
    /// <see cref="RevokeCurrent"/>.
    /// </summary>
    [HttpDelete("others")]
    public async Task<object?> RevokeOthers()
    {
        return await Forward(IdentityEndpoints.MeSessions, "revoke-others",
            new Dictionary<string, object?>());
    }

    /// <summary>Revoke one of the caller's own sessions by id. 404 on any other session.</summary>
    [HttpDelete("{sessionId}")]
    public async Task<object?> Revoke([FromRoute("sessionId")] string sessionId)
    {
        return await Forward(IdentityEndpoints.MeSessions, "revoke",
            new Dictionary<string, object?>
            {
                ["sessionId"] = long.TryParse(sessionId, out var id) ? id : 0
            });
    }
}
