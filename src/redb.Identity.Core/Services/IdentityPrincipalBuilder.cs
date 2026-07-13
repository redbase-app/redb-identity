using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using redb.Core.Models.Contracts;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
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
    /// Internal marker listing the claim types the RP requested for <c>/connect/userinfo</c> via
    /// the <c>claims</c> parameter (OIDC Core §5.5), space-separated.
    /// <para>
    /// UserInfo is served from the access token, so by the time the request reaches
    /// <c>HandleUserInfoRequestContext</c> the original authorization request is long gone — all
    /// that survives is the principal. Without this marker the userinfo handler cannot tell
    /// "the RP asked for `name` individually" from "`name` happens to sit in the principal",
    /// and would have to either leak scope-gated claims to everyone or ignore the parameter.
    /// </para>
    /// <para>
    /// Access-token destination only, so it never reaches the id_token, and the userinfo handler
    /// strips it from its own output — it is our bookkeeping, not a claim about the user.
    /// </para>
    /// </summary>
    public const string RequestedUserInfoClaims = "redb:claims_userinfo";

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
        bool mfaVerified = false, string? mfaMethod = null,
        OidcClaimsRequest? claimsRequest = null)
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

        // Profile scope claims — the full OIDC Core §5.1 set. The conformance suite
        // (oidcc-scope-profile / oidcc-scope-all) compares userinfo against this exact list and
        // warns for each claim the OP omits, so emit every one we hold.
        //
        // Two are derived rather than stored: `preferred_username` falls back to the login, and
        // `updated_at` to the registration date when the profile was never edited. `updated_at` is
        // a JSON NUMBER (seconds since the epoch) per the spec — not a string.
        if (scopeList.Contains(Scopes.Profile))
        {
            if (!string.IsNullOrEmpty(oidcProps?.GivenName))
                identity.SetClaim(Claims.GivenName, oidcProps.GivenName);
            if (!string.IsNullOrEmpty(oidcProps?.FamilyName))
                identity.SetClaim(Claims.FamilyName, oidcProps.FamilyName);
            if (!string.IsNullOrEmpty(oidcProps?.MiddleName))
                identity.SetClaim(Claims.MiddleName, oidcProps.MiddleName);
            if (!string.IsNullOrEmpty(oidcProps?.Nickname))
                identity.SetClaim(Claims.Nickname, oidcProps.Nickname);
            if (!string.IsNullOrEmpty(oidcProps?.Profile))
                identity.SetClaim(Claims.Profile, oidcProps.Profile);
            if (!string.IsNullOrEmpty(oidcProps?.Picture))
                identity.SetClaim(Claims.Picture, oidcProps.Picture);
            if (!string.IsNullOrEmpty(oidcProps?.Website))
                identity.SetClaim(Claims.Website, oidcProps.Website);
            if (!string.IsNullOrEmpty(oidcProps?.Gender))
                identity.SetClaim(Claims.Gender, oidcProps.Gender);
            if (!string.IsNullOrEmpty(oidcProps?.Birthdate))
                identity.SetClaim(Claims.Birthdate, oidcProps.Birthdate);
            if (!string.IsNullOrEmpty(oidcProps?.ZoneInfo))
                identity.SetClaim(Claims.Zoneinfo, oidcProps.ZoneInfo);
            if (!string.IsNullOrEmpty(oidcProps?.Locale))
                identity.SetClaim(Claims.Locale, oidcProps.Locale);

            identity.SetClaim(Claims.PreferredUsername,
                !string.IsNullOrEmpty(oidcProps?.PreferredUsername) ? oidcProps.PreferredUsername : user.Login);

            var updatedAt = oidcProps?.UpdatedAt ?? user.DateRegister;
            identity.SetClaim(Claims.UpdatedAt, updatedAt.ToUnixTimeSeconds());
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

        // OIDC Core §5.5 — the `claims` request parameter. Scopes are a coarse instrument: an RP
        // that needs one claim (say `name`) would otherwise have to ask for the whole `profile`
        // scope and receive twelve. The `claims` parameter lets it name exactly what it needs, and
        // say where it wants it delivered — in the id_token, or from UserInfo.
        //
        // So this runs AFTER the scope-derived claims above and only ever ADDS: a claim the RP
        // named individually is emitted even when its scope was not requested, and a claim that is
        // already present just gains the extra destination the RP asked for. It never removes a
        // claim the scopes granted — the two mechanisms are additive, per §5.5.
        var requestedDestinations = ApplyClaimsRequest(identity, user, oidcProps, claimsRequest);

        // Claim destinations.
        //
        // OIDC Core §5.4: in the authorization-code flow the scope-derived identity claims
        // (profile / email / phone / address) are delivered from the UserInfo endpoint — NOT in
        // the id_token. Emitting them in the id_token anyway is what the OIDF conformance suite
        // flags as "may result in user data being exposed in unintended ways": the id_token is
        // routinely forwarded to third parties and logged as proof of the authentication event,
        // so any PII inside it travels further than the RP intended. Access-token destination is
        // what makes a claim visible at /connect/userinfo, which is exactly where these belong.
        //
        // The id_token keeps only what identifies the authentication event itself: sub, auth_time,
        // acr (plus sid/nonce/at_hash, attached by their own handlers).
        foreach (var claim in identity.Claims)
        {
            var scopeDestinations = claim.Type switch
            {
                // Internal bigint user id (stringified). Emitted on BOTH tokens so external
                // projects can decode the id_token client-side and cross-reference their own user
                // table by this id. Namespaced with the "redb:" prefix per RFC 7519 §4.3
                // private-claim convention; doesn't shadow the public OIDC `sub` GUID.
                InternalUserIdClaim => new[] { Destinations.AccessToken, Destinations.IdentityToken },

                // Identifies the authentication event → belongs in the id_token.
                Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                Claims.AuthenticationTime or Claims.AuthenticationContextReference
                    => new[] { Destinations.AccessToken, Destinations.IdentityToken },

                // Scope-derived user data → UserInfo only (access_token destination). Never the
                // id_token: the RP asked for "access to the user's email/profile", not for the PII
                // to be embedded in a token it forwards elsewhere.
                Claims.Name or Claims.GivenName or Claims.FamilyName or Claims.MiddleName
                    or Claims.Nickname or Claims.PreferredUsername or Claims.Profile
                    or Claims.Picture or Claims.Website or Claims.Gender or Claims.Birthdate
                    or Claims.Zoneinfo or Claims.Locale or Claims.UpdatedAt
                    => new[] { Destinations.AccessToken },
                Claims.Email or Claims.EmailVerified
                    => new[] { Destinations.AccessToken },
                Claims.PhoneNumber or Claims.PhoneNumberVerified
                    => new[] { Destinations.AccessToken },
                Claims.Address
                    => new[] { Destinations.AccessToken },

                _ => new[] { Destinations.AccessToken, Destinations.IdentityToken }
            };

            // §5.5 again: an RP that asked for `email` in the id_token gets the IdentityToken
            // destination added on top of the AccessToken one the `email` scope grants. Union, not
            // replace — otherwise naming a claim in `claims` would silently revoke the delivery
            // channel its scope already earned.
            if (requestedDestinations.TryGetValue(claim.Type, out var extra) && extra.Count > 0)
            {
                var union = new HashSet<string>(scopeDestinations, StringComparer.Ordinal);
                union.UnionWith(extra);
                claim.SetDestinations(union.ToArray());
            }
            else
            {
                claim.SetDestinations(scopeDestinations);
            }
        }

        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Emits the claims the RP named in the <c>claims</c> parameter (OIDC Core §5.5) and reports
    /// the extra destination each one earned. Returns claim-type → destinations to be unioned with
    /// the scope-derived destinations by the caller.
    /// </summary>
    /// <remarks>
    /// Three rules, all from §5.5.1:
    /// <list type="bullet">
    /// <item><description>A claim we do not hold a value for is omitted, Essential or not. "essential"
    /// tells us the RP <em>needs</em> it, not that we can invent it.</description></item>
    /// <item><description>A claim requested with <c>value</c> / <c>values</c> that our value does not
    /// match is omitted — the RP asked for a specific value; answering with a different one would be
    /// worse than answering with nothing.</description></item>
    /// <item><description>Requesting a claim never removes anything: we only add.</description></item>
    /// </list>
    /// <c>sub</c> is deliberately not handled here. A <c>claims</c> request that pins <c>sub</c> to a
    /// value is a statement about <em>which End-User must be signed in</em>, not a claim to emit, and
    /// §5.5.1 requires the request to fail when the session belongs to somebody else. That check
    /// belongs at the authorize endpoint, where we can still reject — see
    /// <c>AttachSessionPrincipalHandler</c>.
    /// </remarks>
    private static Dictionary<string, HashSet<string>> ApplyClaimsRequest(
        ClaimsIdentity identity, IRedbUser user, UserProps? oidcProps, OidcClaimsRequest? claimsRequest)
    {
        var destinations = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        if (claimsRequest is null || claimsRequest.IsEmpty)
            return destinations;

        var userInfoRequested = new List<string>();

        Apply(claimsRequest.IdToken, Destinations.IdentityToken, null);
        Apply(claimsRequest.UserInfo, Destinations.AccessToken, userInfoRequested);

        // Tell the userinfo handler which claims were individually requested — see
        // RequestedUserInfoClaims for why the principal is the only channel available there.
        if (userInfoRequested.Count > 0)
            identity.SetClaim(RequestedUserInfoClaims, string.Join(' ', userInfoRequested));

        return destinations;

        void Apply(
            IReadOnlyDictionary<string, OidcClaimsRequestEntry> entries,
            string destination,
            List<string>? emitted)
        {
            foreach (var (type, entry) in entries)
            {
                // `sub` is always emitted to both tokens anyway; its `value` constraint is enforced
                // at authorize, not here.
                if (type == Claims.Subject) continue;

                var existing = identity.FindFirst(type)?.Value;
                var value = existing ?? ResolveClaimValue(type, user, oidcProps);

                if (!entry.Accepts(value)) continue;

                if (existing is null)
                    SetTypedClaim(identity, type, value!);

                if (!destinations.TryGetValue(type, out var set))
                    destinations[type] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(destination);

                emitted?.Add(type);
            }
        }
    }

    /// <summary>
    /// Resolves a claim the scopes did not emit, straight from the user record and the OIDC profile
    /// extension. Returns null for anything we do not hold — including claims we simply do not
    /// implement (<c>address</c> is resolved, an arbitrary vendor claim is not), which the caller
    /// turns into "omit the claim".
    /// </summary>
    private static string? ResolveClaimValue(string type, IRedbUser user, UserProps? oidcProps)
    {
        var value = type switch
        {
            Claims.Name => user.Login,
            Claims.GivenName => oidcProps?.GivenName,
            Claims.FamilyName => oidcProps?.FamilyName,
            Claims.MiddleName => oidcProps?.MiddleName,
            Claims.Nickname => oidcProps?.Nickname,
            Claims.Profile => oidcProps?.Profile,
            Claims.Picture => oidcProps?.Picture,
            Claims.Website => oidcProps?.Website,
            Claims.Gender => oidcProps?.Gender,
            Claims.Birthdate => oidcProps?.Birthdate,
            Claims.Zoneinfo => oidcProps?.ZoneInfo,
            Claims.Locale => oidcProps?.Locale,
            Claims.PreferredUsername => oidcProps?.PreferredUsername ?? user.Login,
            Claims.UpdatedAt => (oidcProps?.UpdatedAt ?? user.DateRegister).ToUnixTimeSeconds()
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
            Claims.Email => user.Email,
            Claims.EmailVerified => (oidcProps?.EmailVerified ?? false) ? "true" : "false",
            Claims.PhoneNumber => user.Phone,
            Claims.PhoneNumberVerified => (oidcProps?.PhoneNumberVerified ?? false) ? "true" : "false",
            Claims.Address => oidcProps?.Address is { } address
                ? JsonSerializer.Serialize(address, AddressJsonOptions)
                : null,
            _ => oidcProps?.CustomClaims is { } custom && custom.TryGetValue(type, out var c) ? c : null
        };

        // A *_verified flag on its own is meaningless — and misleading, since "false" would read as
        // "we checked and it isn't verified" when the truth is we hold no email/phone at all.
        if (type == Claims.EmailVerified && string.IsNullOrEmpty(user.Email)) return null;
        if (type == Claims.PhoneNumberVerified && string.IsNullOrEmpty(user.Phone)) return null;

        return string.IsNullOrEmpty(value) ? null : value;
    }

    /// <summary>
    /// Adds a claim with the JSON type OIDC Core §5.1 requires for it: <c>updated_at</c> is a
    /// number, the <c>*_verified</c> flags are booleans, everything else a string. Getting this
    /// wrong is not cosmetic — an RP deserialising <c>"email_verified": "true"</c> into a bool
    /// fails, and the conformance suite flags it.
    /// </summary>
    private static void SetTypedClaim(ClaimsIdentity identity, string type, string value)
    {
        switch (type)
        {
            case Claims.EmailVerified or Claims.PhoneNumberVerified
                when bool.TryParse(value, out var flag):
                identity.SetClaim(type, flag);
                break;

            case Claims.UpdatedAt when long.TryParse(value, out var epoch):
                identity.SetClaim(type, epoch);
                break;

            default:
                identity.SetClaim(type, value);
                break;
        }
    }
}
