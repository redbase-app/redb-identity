using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// MFA-3: self-service WebAuthn (FIDO2 / Passkey) management at
/// <c>/api/v1/identity/me/webauthn/*</c>. Mirrors the dispatch shape of
/// <see cref="MeMfaController"/> \u2014 the user id is always derived from the access-token
/// subject by <see cref="MeWebAuthnProcessor"/>; under no circumstances may a caller
/// register, rename, or delete credentials for someone else.
/// Auth: Bearer with <c>identity:manage</c> or <c>identity:account</c> scope.
/// </summary>
[Route("me/webauthn")]
public class MeWebAuthnController : IdentityControllerBase
{
    /// <summary>Return WebAuthn enrollment status for the caller.</summary>
    [HttpGet]
    public async Task<object?> Status()
    {
        return await Forward(IdentityEndpoints.MeWebAuthn, "status",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// Begin a WebAuthn registration ceremony. Body may carry <c>username</c>,
    /// <c>display_name</c>; returns <c>options</c> (CredentialCreateOptions) + an opaque
    /// <c>setup_token</c> the client must echo back at <c>register/complete</c>.
    /// </summary>
    [HttpPost("register/begin")]
    public async Task<object?> RegisterBegin([FromBody] Dictionary<string, object?> body)
    {
        return await Forward(IdentityEndpoints.MeWebAuthn, "register-begin", body);
    }

    /// <summary>Complete a WebAuthn registration with the browser's attestation.</summary>
    [HttpPost("register/complete")]
    public async Task<object?> RegisterComplete([FromBody] Dictionary<string, object?> body)
    {
        return await Forward(IdentityEndpoints.MeWebAuthn, "register-complete", body);
    }

    /// <summary>List the caller's registered WebAuthn credentials.</summary>
    [HttpGet("credentials")]
    public async Task<object?> Credentials()
    {
        return await Forward(IdentityEndpoints.MeWebAuthn, "credentials",
            new Dictionary<string, object?>());
    }

    /// <summary>Rename a single credential.</summary>
    [HttpPatch("credentials/{key}")]
    public async Task<object?> Rename(
        [FromRoute("key")] string key,
        [FromBody] Dictionary<string, object?> body)
    {
        body["key"] = key;
        return await Forward(IdentityEndpoints.MeWebAuthn, "credential-rename", body);
    }

    /// <summary>Delete a single credential by key.</summary>
    [HttpDelete("credentials/{key}")]
    public async Task<object?> Delete([FromRoute("key")] string key)
    {
        return await Forward(IdentityEndpoints.MeWebAuthn, "credential-delete",
            new Dictionary<string, object?> { ["key"] = key });
    }
}
