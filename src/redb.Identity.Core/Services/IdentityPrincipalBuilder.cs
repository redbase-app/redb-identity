using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using redb.Core.Models.Contracts;
using redb.Identity.Core.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Core.Services;

/// <summary>
/// Builds a <see cref="ClaimsPrincipal"/> for an authenticated user.
/// Single source of truth for claim construction — used by both
/// session-based auth and ROPC grant.
/// </summary>
public static class IdentityPrincipalBuilder
{
    private static readonly JsonSerializerOptions AddressJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Internal claim carrying the bigint <c>_users._id</c> alongside the public GUID
    /// <c>sub</c>. Identity-internal processors (e.g. <c>/me/*</c>, scope/group resolvers)
    /// read this claim to query redb without needing a GUID→long round-trip. Emitted only
    /// to the access token, never to the id_token, since RPs should rely on the GUID
    /// <c>sub</c> for cross-Identity-instance correctness.
    /// </summary>
    public const string InternalUserIdClaim = "redb:user_id";

    /// <summary>
    /// Builds a ClaimsPrincipal from a Core user and optional OIDC profile extension.
    /// Credentials (login, email, phone) come from <paramref name="user"/> (<c>_users</c> table).
    /// OIDC profile claims (given_name, family_name, picture, *_verified) come from <paramref name="oidcProps"/>.
    /// The <paramref name="subjectGuid"/> is emitted as the public <c>sub</c> claim; the
    /// bigint <paramref name="user"/>.Id is mirrored into the internal <see cref="InternalUserIdClaim"/>
    /// for redb queries.
    /// </summary>
    public static ClaimsPrincipal Build(
        IRedbUser user, Guid subjectGuid, UserProps? oidcProps, IEnumerable<string> scopes,
        bool mfaVerified = false, string? mfaMethod = null)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (subjectGuid == Guid.Empty)
            throw new ArgumentException("Subject GUID must not be empty.", nameof(subjectGuid));

        var scopeList = scopes as IReadOnlyList<string> ?? scopes.ToList();

        var identity = new ClaimsIdentity(
            authenticationType: "OpenIddict.Server",
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, subjectGuid.ToString("D"));
        identity.SetClaim(InternalUserIdClaim, user.Id.ToString());
        identity.SetClaim(Claims.Name, user.Login);
        identity.SetScopes(scopeList);

        // Profile scope claims (from OIDC extension)
        if (scopeList.Contains(Scopes.Profile) && oidcProps is not null)
        {
            if (!string.IsNullOrEmpty(oidcProps.GivenName))
                identity.SetClaim(Claims.GivenName, oidcProps.GivenName);
            if (!string.IsNullOrEmpty(oidcProps.FamilyName))
                identity.SetClaim(Claims.FamilyName, oidcProps.FamilyName);
            if (!string.IsNullOrEmpty(oidcProps.Picture))
                identity.SetClaim(Claims.Picture, oidcProps.Picture);
        }

        // Email scope claims (email from _users, verified flag from OIDC extension)
        if (scopeList.Contains(Scopes.Email))
        {
            if (!string.IsNullOrEmpty(user.Email))
            {
                identity.SetClaim(Claims.Email, user.Email);
                var verified = oidcProps?.EmailVerified ?? false;
                // OIDC Core §5.1 — email_verified MUST be a JSON boolean. OpenIddict's bool
                // SetClaim overload stamps ClaimValueTypes.Boolean so it serialises as true/false
                // (not the string "true"), which the conformance suite requires.
                identity.SetClaim(Claims.EmailVerified, verified);
            }
        }

        // Phone scope claims (phone from _users, verified flag from OIDC extension)
        if (scopeList.Contains(Scopes.Phone))
        {
            if (!string.IsNullOrEmpty(user.Phone))
            {
                identity.SetClaim(Claims.PhoneNumber, user.Phone);
                var verified = oidcProps?.PhoneNumberVerified ?? false;
                // OIDC Core §5.1 — phone_number_verified MUST be a JSON boolean (see email_verified above).
                identity.SetClaim(Claims.PhoneNumberVerified, verified);
            }
        }

        // Address scope claim (OIDC §5.1.1 — structured JSON object)
        if (scopeList.Contains(Scopes.Address) && oidcProps?.Address is not null)
        {
            var addressJson = JsonSerializer.Serialize(oidcProps.Address, AddressJsonOptions);
            identity.SetClaim(Claims.Address, addressJson);
        }

        // Custom claims (arbitrary key-value pairs, always emitted if present)
        if (oidcProps?.CustomClaims is not null)
        {
            foreach (var (key, value) in oidcProps.CustomClaims)
            {
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value))
                    identity.SetClaim(key, value);
            }
        }

        // OIDC Core §2 — `auth_time` (epoch seconds when the End-User auth occurred).
        // Must be a NumericDate (RFC 7519 §2). OpenIddict's ValidateSignInDemand parses
        // this claim as Int64; passing a plain string-valued Claim ("12345") trips
        // "auth_time claim is malformed or isn't of the expected type". So we add the
        // claim explicitly with ClaimValueTypes.Integer64 instead of SetClaim().
        identity.AddClaim(new Claim(
            Claims.AuthenticationTime,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64));

        // Authentication Method Reference (RFC 8176)
        identity.SetClaim("amr", "pwd");

        if (mfaVerified && !string.IsNullOrEmpty(mfaMethod))
        {
            // RFC 8176 mapping
            var mfaAmr = mfaMethod switch
            {
                "totp" => "otp",
                "sms" => "sms",
                "email" => "email",
                "webauthn" => "hwk",
                "recovery" => "rc",
                _ => "mfa"
            };
            identity.AddClaim(new Claim("amr", mfaAmr));
            // Standardised "mfa" marker (see RFC 8176 §2) so RPs can check a single claim instead of enumerating values.
            identity.AddClaim(new Claim("amr", "mfa"));
        }

        // OIDC Core §2 — Authentication Context Class Reference. Emit a single acr value
        // derived from the actual authentication strength:
        //   "0" — no authentication (long-lived session, currently unreachable here),
        //   "1" — single-factor / password-only (default for ROPC + cookie sessions),
        //   "2" — multi-factor verified (mfaVerified=true in SessionProps).
        // RPs that ask for acr_values via /connect/authorize get this back unconditionally;
        // enforcement of "this RP REQUIRES acr=2" is the RP's job (compare the claim) — the
        // OP intentionally does NOT reject below the requested level here, since OIDC §5.5.1.1
        // marks acr as a Voluntary Claim by default. The RP can opt into strict matching by
        // sending an `acr` claim in the `claims` parameter (out of scope; will reject if so).
        identity.SetClaim(Claims.AuthenticationContextReference, mfaVerified ? "2" : "1");

        // Claim destinations
        foreach (var claim in identity.Claims)
        {
            claim.SetDestinations(claim.Type switch
            {
                // Internal bigint user id (string-stringified). Emitted on BOTH the
                // access_token and the id_token so external projects can decode the
                // id_token client-side and cross-reference their own user table by
                // this id. Still namespaced with the "redb:" prefix per RFC 7519 §4.3
                // private-claim convention; doesn't shadow the public OIDC `sub` GUID.
                InternalUserIdClaim => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.Name or Claims.GivenName or Claims.FamilyName or Claims.Picture
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.Email or Claims.EmailVerified
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.PhoneNumber or Claims.PhoneNumberVerified
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.Address
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.AuthenticationTime or Claims.AuthenticationContextReference
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                _ => new[] { Destinations.AccessToken, Destinations.IdentityToken }
            });
        }

        return new ClaimsPrincipal(identity);
    }
}
