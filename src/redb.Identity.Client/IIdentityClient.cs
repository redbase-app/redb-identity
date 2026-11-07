namespace redb.Identity.Client;

/// <summary>
/// Single facade for Identity HTTP API (admin / account / token / scim).
/// Methods are grouped by domain into partial interface files
/// (<c>IIdentityClient.Users.cs</c>, etc.) and implemented in matching
/// <c>IdentityClient.&lt;Domain&gt;.cs</c> partial classes.
/// </summary>
public partial interface IIdentityClient
{
    // Methods will be added by partial interfaces in W1-5..W1-7.
}
