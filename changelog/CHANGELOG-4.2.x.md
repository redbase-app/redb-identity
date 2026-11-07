# redb.Identity changelog: 4.2.x

Releases of the 4.2 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.2.2] — 2026-10-04

### Security — the password grant logged the username at `Debug`; it logs it at `Trace`

Building the `ClaimsPrincipal` for the password grant (ROPC) wrote
`Issued ClaimsPrincipal for password grant: {Username}` at `Debug`. A default production configuration leaves
`Debug` off, but a deployment that keeps it on accumulates account identifiers next to the fact of a
successful password sign-in, and matching a person to a time then takes nothing but a log read. The line
moved to `Trace`; the message, its fields and its position are unchanged, so nothing else in the flow moves
with it.

## [4.2.0] — 2026-09-30

### Security — `/connect/logout` acts on the browser's own session; a `userId` in the request no longer chooses whom to sign out

The logout processor read `userId` from the request body (the GET route maps the query string the same
way) and, when no session cookie came with the request, signed that user out: every session revoked and a
back-channel logout token sent to every relying party holding a live token for them. `/connect/logout` is
the OIDC `end_session_endpoint`, reachable anonymously by design, so the value was the caller's word:
`POST /connect/logout` with `userId=1` and no cookie ended the administrator's browser sessions and told
the relying parties so, and user ids are sequential. The parameter had no legitimate caller — the two
facade routes are the endpoint's only clients, and an operator signing another user out goes through the
sessions management API behind the management gate. The processor now takes the user and the session from
the verified session ticket alone (the headers `ReadSessionCookie` writes; the facade strips those names
off incoming requests first). A request with no session completes with nothing ended — RP-Initiated
Logout 1.0 §2 still expects the redirect to `post_logout_redirect_uri` — instead of being refused;
externally that is what already happened, the signed-out page having overwritten the processor's error.
`LogoutSubjectBindingTests` pins it: an anonymous POST and GET naming the victim leave the session active,
the browser holding the cookie still ends its own, a bare `id_token_hint` completes and ends nothing.

In the same processor, the `id_token_hint` subject was compared with the numeric core user id, while `sub`
is the user's public subject GUID, so every hinted logout logged a mismatch and ignored the hint. It is
compared with the subject GUID now.

### Security — a logout without a valid `id_token_hint` asks the End-User first

The session cookie is `SameSite=Lax`, so a cross-site top-level navigation carries it: a link on any page
could send the browser to `/connect/logout` and end the visitor's OP session — the cookie proves whose
session it is, not that its owner wants it ended. A relying party proves intent with a valid
`id_token_hint` whose `sub` is the session's user, and such a request signs out at once, as before.
Without it the OP now answers with a confirmation page (GET and POST alike): its form carries a state
bound to the user and the session and valid for five minutes, and posting that state back is the
confirmation. A foreign page cannot read the state (same-origin policy) nor forge it (DataProtection), a
state issued for another session confirms nothing, and the page clears no cookie and performs no redirect
until the End-User confirms; the relying party's `post_logout_redirect_uri`, `state` and `client_id`
travel through the form so the redirect back still happens. Duende's logout prompt and Keycloak's
confirmation without `id_token_hint` behave the same way. The decision is made in the core
(`LogoutProcessor` with `LogoutConfirmationProtector`) and the HTTP facade only renders the page, so
another facade would render its own. A browser that used to sign out with one request without a hint
now sees one page first. `LogoutConfirmationTests` pins it: the page instead of the logout, the
confirmation, a forged or foreign state, and the relying party's parameters surviving the round trip.

### Security — signing a user out everywhere revoked their sessions and nothing else

`SessionService.LogoutAsync` is what a password change, a password reset, an operator's logout, a SCIM
deactivation and a user disable rely on to end every grant the user holds. It revoked the sessions and
then looked for the user's authorizations by the internal user id in `Key`; since V4 the OpenIddict
stores key authorizations and tokens by the user's public subject in `value_guid`, so the lookup found
nothing and every refresh token kept working — after a password reset, the tokens of whoever had the old
password kept refreshing. Tokens issued by the password grant have no authorization row at all and were
never in reach of that step. The method now resolves the public subject and revokes the user's
authorizations and their valid tokens by it, in batches; other subjects' tokens at the same application
are untouched. `FullLogoutRevokesGrantsTests` runs the real path — a refresh token from the authorization
code flow and one from the password grant, then the operator's logout — and both refreshes must fail;
they succeeded before. `SessionServiceTests` now seeds grants the way the stores write them.

### Fixed — the relying party's `state` comes back on the post-logout redirect

RP-Initiated Logout 1.0 §3: when the RP passed `state`, the OP returns it as a query parameter on the
redirect to `post_logout_redirect_uri`. It was dropped. It is preserved with the redirect URI and appended
to the `Location`, through the confirmation page as well.

### Fixed — back-channel logout for a session reaches the relying parties that used it, with the user's public subject

A browser session is opened at `/login`, before any relying party is involved, and it did not record
which relying parties later obtained tokens through it. A per-session logout therefore had nobody to
notify (Back-Channel Logout 1.0 §2.1 asks the OP to notify the RPs the End-User signed in to through the
session being ended), and the `logout_token` carried the internal user id as `sub`, while the id_token the
RP holds carries the public subject GUID, so an RP could not have matched it anyway. The session now
keeps the list of relying parties that obtained tokens through it (`SessionProps.ClientApplicationIds`,
appended at the authorization endpoint under a row lock, so two tabs cannot drop each other's entry), a
per-session logout notifies exactly those with the session's `sid`, a logout of every session notifies
each session's relying parties with its own `sid` and token holders outside any session (ROPC, device
flow) with `sub` alone, and `sub` is the public subject in every case. Sessions opened before this
release have no list and notify nobody, as before. `BackchannelLogoutOnSessionEndTests` runs the whole
path against a relying party endpoint on the same HTTP stack: sign in, authorize, RP-initiated logout with
`id_token_hint`, a `logout_token` whose `sub` and `sid` equal the id_token's; it times out without the
binding. `demo_backchannel_logout.ps1` follows the same browser path now.

### Changed — with configured credentials and the redb-backed signing-key store both present, `MintingKeySource` says which one mints

The option's documentation said the store's keys are appended after configured `SigningCredentials` /
`EncryptionCredentials`, so that an HSM-backed key stays primary; the post-configure inserted them first,
so the store minted. OpenIddict signs with the first compatible signing credential and encrypts with the
first encryption credential, while every entry validates and is published, so the order of two lists was
deciding who mints — and the pair is legitimate in both directions, as the state of a deployment moving
its keys onto an HSM or off one. That is the operator's decision, not a list order's: the new
`RedbIdentityOptions.MintingKeySource` (`Configured` or `Store`) is required when both sources are
present — registration refuses the pair without it — and refused when only one source is configured,
since it would decide nothing. The post-configure places the store's keys after or before the configured
ones accordingly, the active store key first among them as before. Deployments with the store alone (the
shipped configuration) are unaffected. `SigningKeysBootstrapTests` and `SigningKeyPostConfigureTests`
pin the refusals and both orders.

### Fixed — ephemeral keys and the redb-backed signing-key store refuse to be enabled together; the store always seeds an encryption key

`AllowEphemeralKeys=true` together with `UsePropsSigningKeyStore=true` registered an ephemeral key first
and left it in the credential lists beside the store's keys: in this replica's JWKS only, trusted for
validation, and the encryption key for every token until the store had one. Not exploitable — its private
half never leaves the process — but it is the per-process failure the store exists to remove, hidden
behind a persistent store. `AddRedbIdentityServer` now refuses the pair. `SigningKeyInitListener` seeded an
encryption key only while access-token encryption was on; OpenIddict encrypts authorization codes, refresh
tokens, device and user codes and its own state tokens whatever `DisableAccessTokenEncryption` says, and
refuses to build its options without an encryption credential, so a store holding a signing key and no
encryption key was a server that could not start. It seeds both kinds now, and the registration refuses a
configuration with no encryption credential whatever that flag says, naming the options in the message.
`SigningKeysBootstrapTests` and `SigningKeyInitListenerTests` pin both.

### Security — a retired signing key is offered to nobody, by construction rather than by registration order

The post-configure that feeds OpenIddict from the redb-backed signing-key store built two pools. Keys inside
their `NotBefore..NotAfter` window became the credentials OpenIddict mints with. A broader "validation pool"
— every persisted key past `NotBefore`, retired ones included — was written into
`TokenValidationParameters.IssuerSigningKeys`, so that, its comments said, tokens signed by retired keys
would keep validating "during the grace window". Retirement sets `NotAfter` to the moment of retirement,
so that pool kept a retired key for as long as its row existed: had a validator read that list, the one
reaction an operator has to a leaked key would have reached the JWKS and minting, and nothing else.

Checked against the real pipeline before anything was changed, and the list was never read: OpenIddict's
own post-configure runs after this one (this one is registered in `AddCore`, OpenIddict's in `AddServer`)
and rebuilds the validation parameters from the credentials — a token signed by a retired key was already
refused (`ID2090`) at introspection and by the validation stack the management API uses. What kept it
safe was the order two registrations happen to have; a refactor that moved one of them would have made the
stale pool live. The component no longer has one. It takes the store's working set only (`GetAllAsync`,
in-window keys), so a retired key appears in no list, and it writes the validation parameters as a
projection of the credential lists — the same two lines OpenIddict writes — so the result is the same
whichever post-configure runs last. That also ends the clobbering of credentials other configurers added
(the file's own rule was "never clear the list"; the assignment did): they stay, and they are trusted for
validation too.

Rotation is unchanged: the demoted key keeps its own `NotAfter` and validates until then, which is the
handover window relying parties need. Retirement now means what it says everywhere.

`SigningKeyPostConfigureTests` pins the component alone — a retired key in no list, parameters equal to
credentials, a host-added credential kept and trusted; three of four fail on the previous code.
`SigningKeyRetirementTests` runs the store-backed key path end to end for the first time in the suite:
mint, rotate (the old token still validates), retire (introspection and the validation stack both refuse
it).

### Security — an open redirect after sign-in through a control character in `returnUrl`

Every point where a `returnUrl` becomes a `Location` header — login, MFA (twice), federation, consent —
asks `LoginPageProcessors.IsValidReturnUrl` first, and the check refused absolute addresses, `//host` and
`/\host`. It did not refuse control characters. A browser removes ASCII tab and newline from a URL before
resolving it (WHATWG URL), so `returnUrl=%2F%09%2Fevil.example` — `/\t/evil.example` once decoded —
passed the check and landed the user on `//evil.example`, another host, right after they typed their
password here. The check now refuses any control character, as ASP.NET Core's `IsLocalUrl` does for the
same reason. `ReturnUrlOpenRedirectTests` pins it; the control-character cases fail without the fix.

### Fixed — a federation sign-in deleted the session cookie it had just issued

The federation callback answers with the new session cookie and with the expiry of the per-flow binding
cookie, and it joined the two into one `Set-Cookie` value with `", "`. A browser does not split
`Set-Cookie` on commas (RFC 6265 §3): it read the fold as one cookie — the session — whose attributes
ended with the binding cookie's `Max-Age=0`, and since the last `Max-Age` wins (§5.3) it deleted the
session as it arrived, while the binding cookie was never cleared. The HTTP consumer already writes an
array value as one header line per entry, and the MFA cookies already used that through a private helper
of their own. There is now one `IdentityCookieFormatter.AddSetCookie`: a second cookie turns the value into
an array, a single one stays the plain string every reader expects. The federation, session and MFA writers
all go through it, and the session writers no longer assign the header — no route pairs two of them today,
but a second cookie would have silently replaced the first, including the re-authentication marker.
`SetCookieFoldingTests` reads the headers the way a browser does.

### Fixed — a `Set-Cookie` the caller sent came back in the response

The routes answer on the request message, and the cookie writers add to whatever `Set-Cookie` is already
there — which, on a login, was the caller's own request header. The HTTP consumer refuses to echo a request
header only while it is the very object the client sent (it stopped matching by name so a client can no longer
suppress a header the route wrote, redb.Route 4.2.0), and the array built around the caller's value
is not that object, so both cookies went out. A browser cannot send `Set-Cookie` on a request, so this only
ever reached the caller itself. `Set-Cookie` is now one of the names stripped on ingress on every transport.
`InboundSetCookieTests` signs in through the real HTTP pipeline with the header planted and fails without the
fix. Since redb.Route 4.2.0 the HTTP consumer also drops `Set-Cookie`, with the other response-only
fields of RFC 9110, before the exchange is built; Identity keeps its own strip all the same — it covers gRPC
and SOAP as well, and the names Identity refuses to take from a caller are Identity's to declare.

### Fixed — three HTTP routes did not strip the reserved inbound headers first

The HTTP facade removes the caller-supplied names it trusts internally (`session_user_id`, `user_id`,
`ip_address`, …) as the first step of a route, documented as "every HTTP route". The management catch-all
(`http-management-api`) and the SCIM catch-all (`http-scim-api`) never did, and the SCIM discovery route
did it second. Nothing on those routes reads a reserved name today — their controllers build the inner
message from scratch — so this was a structural gap, not an exploit. All three strip first now, and
`HttpRouteReservedHeaderStripTests` fails if a route in the HTTP route builder does not.
