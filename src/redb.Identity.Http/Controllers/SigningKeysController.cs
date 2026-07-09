using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.SigningKeys;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// Admin signing-key lifecycle endpoint. Forwards to
/// <c>direct-vm://identity-manage-signing-keys</c>.
/// </summary>
/// <remarks>
/// Routes:
/// <list type="bullet">
///   <item><c>GET    /signing-keys</c> — list every key row (active + retired, full audit trail).</item>
///   <item><c>POST   /signing-keys/rotate</c> — mint a fresh active key, demote previously-active
///   keys of the same kind. Body: <see cref="RotateSigningKeyRequest"/> (omit to rotate the default
///   "signing" kind).</item>
///   <item><c>DELETE /signing-keys/{kid}</c> — retire (set NotAfter=now) so the key drops out of
///   the live JWKS on the next request and tokens signed under it stop validating.</item>
/// </list>
/// Gated by <c>identity:applications.manage</c> (or master <c>identity:manage</c>) — signing-key
/// rotation is an application-layer concern from a least-privilege standpoint.
/// </remarks>
[Route("signing-keys")]
public class SigningKeysController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List()
    {
        return await Forward(IdentityEndpoints.ManageSigningKeys, "list", null);
    }

    [HttpPost("rotate")]
    public async Task<object?> Rotate([FromBody] RotateSigningKeyRequest? request)
    {
        return await Forward(IdentityEndpoints.ManageSigningKeys, "rotate",
            request ?? new RotateSigningKeyRequest());
    }

    [HttpDelete("{kid}")]
    public async Task<object?> Retire([FromRoute("kid")] string kid)
    {
        return await Forward(IdentityEndpoints.ManageSigningKeys, "retire",
            new Dictionary<string, object?> { ["kid"] = kid });
    }
}
