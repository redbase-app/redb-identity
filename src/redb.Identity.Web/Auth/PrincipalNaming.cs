using System.Security.Claims;

namespace redb.Identity.Web.Auth;

/// <summary>
/// Which claim answers "who is signed in" on the cookie principal.
/// <para>
/// The OP deliberately keeps <c>preferred_username</c> and <c>name</c> out of the id_token — their
/// destination is the access token, so that a relying party cannot forward the user's PII inside a
/// token it passes on (see <c>IdentityPrincipalBuilder.GetDestinations</c>). At id_token time the only
/// candidate left is <c>sub</c>, which is an opaque GUID, and that is what the UI used to show in the
/// top bar. The login arrives a moment later, with the userinfo response — so the name claim has to be
/// chosen <b>after</b> that merge, not before it.
/// </para>
/// </summary>
internal static class PrincipalNaming
{
    /// <summary>Candidates in falling order of usefulness to a human reading the screen.</summary>
    private static readonly string[] Candidates = ["preferred_username", "name", "email", "sub"];

    /// <summary>
    /// The claim type <see cref="ClaimsIdentity.Name"/> should resolve through. Falls back to
    /// <c>sub</c>: an opaque subject is a poor label but an honest one, and it is never null.
    /// </summary>
    public static string PickNameClaimType(ClaimsIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        foreach (var candidate in Candidates)
        {
            if (identity.HasClaim(c => string.Equals(c.Type, candidate, StringComparison.Ordinal)
                                       && !string.IsNullOrWhiteSpace(c.Value)))
            {
                return candidate;
            }
        }

        return "sub";
    }

    /// <summary>Returns the same identity's claims under a freshly chosen name claim type.</summary>
    public static ClaimsIdentity WithPickedNameClaimType(ClaimsIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return new ClaimsIdentity(
            identity.Claims,
            identity.AuthenticationType,
            PickNameClaimType(identity),
            identity.RoleClaimType);
    }
}
