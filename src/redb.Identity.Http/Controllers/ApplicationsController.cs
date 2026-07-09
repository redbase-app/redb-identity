using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for OAuth 2.0 applications (clients).
/// Forwards to <c>direct-vm://identity-manage-apps</c> route.
/// </summary>
[Route("applications")]
public class ApplicationsController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        return await Forward(IdentityEndpoints.ManageApps, "list",
            new ListRequest { Offset = offset, Count = count });
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageApps, "read", ParseIdBody(id, stringKey: "clientId"));
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateApplicationRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageApps, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateApplicationRequest request)
    {
        request.Id = id;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageApps, "update", request);
    }

    /// <summary>
    /// Rotates the <c>client_secret</c> of a confidential OAuth application. Returns the
    /// new plaintext secret <b>once</b> in the response body; subsequent reads will not
    /// expose it (only BCrypt hash is stored). The previous secret is invalidated
    /// immediately — any client_credentials/refresh flow holding the old value will get
    /// 401 from the next call onward.
    /// <para>
    /// Declared before <see cref="Delete"/> so that the literal <c>rotate-secret</c>
    /// segment cannot be swallowed by the <c>{id}</c> template (the <c>id</c> would
    /// otherwise contain the slash). <c>ControllerRegistry</c> also prefers literal
    /// over template during resolution; the ordering is belt-and-braces protection.
    /// </para>
    /// </summary>
    [HttpPost("{id}/rotate-secret")]
    public async Task<object?> RotateSecret([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageApps, "rotate-secret", ParseIdBody(id));
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageApps, "delete", ParseIdBody(id, stringKey: "clientId"));
    }
}
