# redb.Identity changelog: 4.1.x

Releases of the 4.1 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.1.1] — 2026-09-25

### Changed — a WS-Trust refusal is the STS's answer, not a failure of the route

The SOAP facade threw its WS-Trust faults. The caller received the right fault either way, but every
throw also failed the exchange, so each correct refusal — a malformed RST, bad credentials, a scope the
caller may not have, a caller over the rate limit — counted against `soap-identity-sts` as a route error,
headed for a dead-letter channel, and showed the STS as a failing route to whoever supervises it. The demo
suite's three negative probes alone put it on a supervisor's "needs attention" list, and a real breakage
would have drowned in such noise.

`redb.Route.Soap` now lets a consumer route answer with a fault: put `redbSoap.faultCode` and
`redbSoap.faultString` on the reply and return normally, and the consumer sends the `soap:Fault` while the
exchange stays successful. The STS uses exactly that. A refusal is raised internally as `WsTrustRefusal`
and turned into the reply at the boundary of the two steps that can refuse (`MapRequest`, `MapResponse`);
the route stops there, so nothing after a refusal runs.

What stays a failure is our own breakage: Core gave no answer, is unavailable, timed out, or issued no
token. Those remain `soap:Server` faults thrown as `SoapFaultException`, and the error count and
dead-letter channel see them — which is what they exist for. Rate limiting is deliberately on the answer
side: it is the limiter working, the same way the HTTP facade's 429 is an answer. Its code is unchanged
(`soap:Server`, "wait, do not rewrite the request").

Nothing changes on the wire: same fault codes, same reasons, same HTTP status. The existing SOAP flow
tests pass unchanged. `SoapProtocolFlowTests` now also reads the route's own
`redb.route.exchanges.failed` counter, filtered to its fixture's endpoint: before this change a malformed
RST and a wrong secret counted as two failed exchanges, now as none.

**Deployment order:** this needs the `redb.Route.Soap` that carries the fault-as-reply form. On a host
whose shared `redb.Route.Soap` predates it, the headers are ignored and a refusal would leave as a
malformed success reply instead of a fault. Identity and Route ship together, as always; a host built from
an older Route must be rebuilt before this module is deployed to it.

### Fixed — a missing management route answers 404, and a crash in a controller answers 500

The management surface answered **400** to a path no controller action matches, and **400** again when an
action threw. On gRPC both arrived as `INVALID_ARGUMENT`. A missing route told the caller their request was
malformed; an exception in our own code told them it was their fault — which is how a disabled feature once
showed up as a 400 while the log held an unhandled exception.

The controller dispatcher had already said the right thing: it writes `NotFound` with 404, or
`InternalError` with 500, both into the body's `error` field and as the status. The facades then read the
`error` field, looked it up in `ManagementErrorCodes` — which knows the controllers' own codes
(`not_found`, `duplicate`, …) and nothing of the dispatcher's — and replaced the status with the table's
fallback. The table exists for exactly one case, a controller that returned an error document wrapped in a
200; it was reaching past it.

`ManagementErrorCodes.DecidedErrorStatus` now names the status already decided — from
`redbHttp.ResponseCode` or `status.code`, whichever the dispatcher wrote — and both facades leave such a
status alone, consulting the table only when nobody stated a code. That is the rule `IdentityVerdict` has
always stated for the rest of Identity: the status wins where there is one. A status Core sets through a
controller (a 503 during an outage, say) is kept by the same rule. Teaching the table the dispatcher's strings
would have made the symptom go away and tied Identity to another package's constants; it was not done.

`ManagementStatusPreservationTests` pins both transports, through the real HTTP pipeline as well as at the
mappers, and pins that controller error documents still map exactly as before. Without the fix the pipeline
test answers 400 and the gRPC one `INVALID_ARGUMENT` for a 500.


## [4.1.0] — 2026-09-21

> **This release carries security fixes.** An administrative scope is no longer granted without a role
> that carries it, and an anonymous client registration can no longer create a client that administers
> the server. The entries marked *Security!* below say what was possible before and what changed.

### Security! — an administrative scope now requires a role that carries it

OAuth's scope check asks one question: may this **client** request this scope? Nothing in it asks
whether the **person** signing in should hold it. The admin console legitimately asks for
`identity:manage`, so every account that could sign in to it received the master management scope, and
the management API — validating the token exactly as it should — admitted them. Reproduced end to end
on a running instance: an account created seconds earlier, with no roles and no groups, listed every
user and deleted one. Roles were already resolved at issuance (`AttachRoleRegistryClaims`) but only ever
*added* scopes; nothing ever withheld one.

`RestrictAdminScopesByRoleHandler` supplies the missing half. For user-bound grants it computes the
scopes the user's effective roles attach — direct assignments and those inherited through groups, via
`RoleService.GetEffectiveScopeNamesAsync`, which already existed — and removes every administrative
scope that set does not contain. Administrative means Identity's own surface: `identity:*` except the
self-service `identity:account`, plus `scim`. An operator's own scopes are untouched unless named in
`Identity:AdminScopeEntitlement`.

Three decisions worth stating plainly, because each could have gone the other way:

- **It removes, it never rejects.** A user who asks for more than their roles allow still signs in,
  without those scopes. Rejecting would turn a missing role into a failed login, and the console asks
  for `identity:manage` on behalf of everyone. Every removal is logged with the user and the scopes.
- **It fails closed.** If roles cannot be resolved the administrative scopes are dropped rather than
  issued on trust. That costs an administrator a refresh after a database hiccup; the opposite costs
  everyone their user list.
- **Refresh re-evaluates.** The handler runs on every sign-in, refresh included, so revoking a role
  takes effect on the next refresh instead of lasting as long as the grant.

`client_credentials` is deliberately untouched: it has no user to entitle, and the application's own
`scp:{scope}` permission remains the authoritative gate there.

Upgrades keep working: `SeedAdminRoleScopesListener` attaches the management scope to the system
`admin` role at startup **when that role carries no scopes at all** — the state every installation
predating this change is in, and the state that would otherwise lock the only administrator out of
their own console. A role whose scopes an operator has curated is never touched. `Identity:
AdminScopeEntitlement:Enabled=false` turns the gate off from configuration alone, so a deployment that
still manages to lock itself out can recover without a rebuild.

Pinned by `AdminScopeEntitlementTests` through the real token pipeline, asking the server what the
issued token carries rather than trusting the token response (RFC 6749 §5.1 makes its `scope` member
optional when nothing changed): no entitling role, no management scope; an entitling role, the scope is
there; `client_credentials` unchanged. With the gate switched off the first of those fails with
`{openid, identity:manage}` — the vulnerability, reproduced in a test.

Verified on a running Tsak worker, not only in the suite: a freshly registered account with no roles
received `openid` alone and got `403` from the user list, the role list and a delete; an account in the
`admin` role received `identity:manage` and administered normally. Self-service is unaffected — the
console requests `identity:account` as well, and that scope is exempt.

### Fixed — the shipped module entry point ran a shorter startup chain than the embeddable one

Identity has two entry points. `redb.Identity.Core/Module/InitRoute.cs` boots it inside a host process
and is what the test fixtures use; `redb.Identity.Core.Module/InitRoute.cs` is what Tsak discovers in
the `.tpkg`, and therefore what every deployment actually runs. Each keeps its own chain of lifecycle
listeners, so a listener added to the first and forgotten in the second is green in the whole suite and
absent in production.

Two listeners had drifted:

- `SeedAdminRoleScopesListener` — the upgrade path for the gate above. On the running worker the admin
  role stayed empty, so an administrator in the `admin` role was refused `identity:manage` just like
  anybody else. Found by deploying the gate and watching an administrator get locked out.
- `V4UniqueBackfillListener` — the V4-UNIQUE transition backfill, whose own documentation says it must
  run before the seed listeners. No Tsak deployment had ever run it; on the first boot after this change
  the worker reported `candidates=356 repaired=1 duplicates=0` and retired the pre-V4 indexes.

`ModuleListenerParityTests` now fails when a listener the embeddable path registers is missing from the
shipped one. The reverse stays allowed: the module entry point legitimately owns host-specific
listeners (child-container and bridge-scope disposal, the credential seeders from its own container).

`RoleScopeQueryIsolationTests` pins the neighbouring assumption the diagnosis had to rule out: a role is
the parent of both its users and its scopes, and reading the users as scope attachments would make an
empty role look curated.

### Security! — an anonymous registration cannot create a client that administers the server

Dynamic client registration (RFC 7591) has two modes: open, and protected behind an initial access
token. Open was what shipped, and the only limit on what a registration could ask for was
`DynamicRegistrationAllowedScopes` — a list that includes every granular administrative scope so the
demo suite can probe each admin surface. Anyone able to reach `POST /connect/register` could therefore
register a `client_credentials` client carrying `identity:users:write`, take a token, and delete users.
No role, no password, no operator involved. It was used exactly that way during this cycle's work, to
clean up probe accounts, which is how it came to the owner's attention.

The scope-entitlement gate above cannot help here: `client_credentials` has no user to entitle, so the
client's own permissions are the whole gate — and those permissions are precisely what registration was
handing out.

So the rule sits below deployment policy, in `DynamicRegistrationProcessor`: **while registration is
open, a scope this deployment counts as administrative is refused, whatever the allow-list says**. What
counts is `Identity:AdminScopeEntitlement`, the same definition the issuance gate uses, so an operator
who declares their own administrative scope is covered by both at once. Its `Enabled` switch is
deliberately not consulted — that switch exists to recover a locked-out administrator and must not
quietly reopen anonymous registration of administrative clients.

Registering administrative clients dynamically remains possible, through the mode RFC 7591 defines for
it: set `DynamicRegistrationInitialAccessToken`, and every registration then carries a credential the
deployment issued, with the allow-list governing as before. The shipped context sets one, for the same
reason it ships a seeded admin password and a dev pepper: the demo suite registers admin-scoped clients
and something has to authorise it. That value is as public as the file it lives in, and the context says
so — production rotates it, or sets it to null and trims the allow-list to the user-info scopes.

The demo suite presents that token on every `POST /connect/register`, and takes it from
`IDENTITY_DCR_TOKEN` when set — a host whose token differs from the shipped default runs the demos by
exporting that variable, and changes nothing in the scripts.

`AnonymousDcrAdminScopeTests` pins both directions, including that open registration still serves the
ordinary clients it exists for. Verified on a running worker as well.

### Fixed — a switched-off feature answers "no such endpoint" instead of failing

Registration, e-mail verification, e-mail change and WebAuthn bind their `direct-vm://` routes only when
enabled, while the facades mount their controllers regardless. A call to a disabled feature therefore
reached a producer with nothing behind it, and the resulting `InvalidOperationException` left the caller
with a generic failure and the log with an unhandled-exception stack trace — observed as
`POST /account/register` answering 400 with `No consumer registered for direct-vm endpoint
'identity-account-register'`.

`IdentityControllerBase.Forward` now asks the shared registry whether the route is bound and, when it is
not, answers the standard `not_found` document, which `ManagementErrorCodes` turns into 404 on every
transport. That is the answer the client SDK already reads back as `registration_disabled`, and it is
what the API documentation said all along.

The question goes to the registry rather than to a feature flag on purpose. The flag lives in Core's
options and each facade binds its own; copying it across the boundary would put the answer in two places
and let them disagree, while what is actually bound cannot disagree with itself.

### Security — what self-registration meant on 4.0.1, and why the shipped context keeps it on now

During this cycle `Registration.Enabled` was turned **off** in the context this repository ships, then
turned back **on**. Both moves belong in the record, because the reason was never registration itself.

On 4.0.1 the scopes a request receives are the ones the **client** is permitted to ask for, narrowed by
nothing that depends on the user. Roles only add scopes (`AttachRoleRegistryClaims`); the one mechanism
that could withhold one — `ScopeRequiredGroups` — is opt-in and unset by default. The admin console asks
for `identity:manage` at sign-in, so every account that could sign in to it held the master management
scope, and the server-side check passed for them exactly as for an administrator. Confirmed against a
running instance, reads and writes alike; the finding is the owner's. With that gap open, self-service
registration was the path from anonymous to full administrator in two requests, so it was closed.

**Operators running 4.0.1: keep self-registration off, and treat every account that can sign in to the
console as an administrator.** That advice stands for that release and is the reason this entry stays.

The gap is closed in this cycle by the entitlement gate above, and with it closed the shipped context
turns registration back on: this context is the showcase one, and an image where a visitor can create an
account and walk the sign-in, MFA and self-service flows is the point of shipping it. A self-registered
account now holds `openid`, `profile` and `identity:account`, and nothing that can administer. The code
default remains `false`, so a host that configures nothing still ships closed, and the context says in
so many words that production should set `false` unless public sign-up is a wanted feature.

One door the gate does not touch, stated plainly because a showcase invites probing: dynamic client
registration is still open in this context and `DynamicRegistrationAllowedScopes` still includes the
granular admin scopes, so any caller of `POST /connect/register` can mint a `client_credentials` client
that administers. `client_credentials` has no user to entitle — the client's own permissions are the
whole gate there, by design. An exposed instance needs `DynamicRegistrationInitialAccessToken` set or
that list trimmed to the user-info scopes.

### Fixed — Administration → Federation crashed, and the top bar showed a subject instead of a login

Two findings from a user of the 4.0.1 console.

`FederationList` passed `Icon="cluster"` to `UiEmptyState`, which has no such parameter — it takes an
`Illustration` slot. Blazor answers that with a runtime error, and the compiler cannot see it, so the
page died on every visit where no provider was registered yet: *"Object of type 'UiEmptyState' does not
have a property matching the name 'Icon'"*. The icon now goes through the slot. The page tests next
door only assert that a route exists and refuses anonymous callers, which is why a page that threw on
sight counted as covered; `AdminPagesRenderTests` renders it instead, and against the old markup it
reproduces the user's error verbatim.

The signed-in user was shown as an opaque subject. The OP keeps `preferred_username` and `name` out of
the id_token on purpose — their destination is the access token, so a relying party cannot forward the
user's PII in a token it passes on — and the BFF chose its name claim while only the id_token was in
hand, leaving `sub`. Userinfo arrives a moment later carrying the login, but the identity had already
been named, and `NameClaimType` is fixed at construction. Both sign-in paths now pick the name claim
*after* the userinfo merge (`PrincipalNaming`, shared by the backchannel client and the redirect flow),
in the order `preferred_username` → `name` → `email` → `sub`; the subject remains the fallback, because
a poor label is better than a blank one. The redirect flow also needed the userinfo claims to be
mapped onto the principal at all, which it was not doing.

### Changed — a module cannot ship its own version of a host assembly, and the packer now says so

`pack-tpkg.ps1` force-included `Microsoft.IdentityModel.*`: those DLLs went into the package even
though the host had them, on the reasoning that the host shipped an older, incompatible major. That
never worked and cannot work — `ModuleAssemblyLoadContext` asks the Default ALC before probing the
package, as it must or contract types would split, and since redb.Tsak 4.1.0 its `LoadedAssemblyTracker`
prefers the host copy too. The force-include shipped 1.26 MB the loader never looked at, and a
Troubleshooting note advising a cure that cures nothing. Removed:
`Core.Module` is 25 → 19 DLLs, `Http` 5 → 2.

What the force-include was reaching for — never running against a host assembly of the wrong version —
is now a gate instead of a copy. For every DLL skipped as host-provided the packer compares the
assembly version it would have shipped with the version the host will actually load, and a **major**
divergence stops the packaging with both versions, the host's path, and where each pin lives; a minor
one is a warning, because the host copy is what loads either way. Until now that divergence was silent:
the module compiled against one version, the host loaded another, and it surfaced far away as a
`FileNotFoundException` inside OpenIddict. The gate was checked by pointing it at an older
`Microsoft.IdentityModel.Tokens` (6.35.1 against our 8.16.0): packaging stops before the archive is
written, saying `module 8.16.0.0, host 6.35.1.0`.

This does not give a module version independence — nothing on the packaging side can. That would need
a shared context for a group of packages (Identity's core and its facades deliberately share
dependencies with each other, so per-package isolation cannot express it); recorded with the Tsak side
as F-13a and deliberately not built, since the versions are aligned today.

### Fixed — packages no longer carry shared-framework assemblies

`pack-tpkg.ps1` built its "the host provides this" exclusion set from the worker's `bin` and
`Libs\shared` only. While `build-shared` copied framework assemblies into that layer, names like
`Microsoft.Extensions.Options` were excluded by accident. Tsak stopped copying them on 2026-09-18, and
the next pack put ten `Microsoft.Extensions.*` 10.0.3 assemblies inside `redb.Identity.Contracts.tpkg`
(66 KB → 294 KB) — while the host resolves those same names from its own framework, 10.0.8.

Nothing broke at runtime: `ModuleAssemblyLoadContext` asks the Default ALC before probing the package,
so a packaged copy can never win a resolve. It was dead weight that `LoadedAssemblyTracker` byte-loaded
a second time into the non-collectible Default context (fixed on the redb.Tsak side in 4.1.0).

The exclusion set now also scans both shared frameworks — `Microsoft.NETCore.App` **and**
`Microsoft.AspNetCore.App`, because `Microsoft.Extensions.Configuration` / `.Options` / `.Logging` /
`.Diagnostics.HealthChecks` live in the ASP.NET one. The version is picked as the highest install of the
worker's own major, compared as a version and never as text (a string sort ranks `9.0.20` above
`10.0.8`); a missing framework throws instead of silently packing the assemblies. `Contracts.tpkg` is
back to two DLLs and 65 KB; the other four packages are unchanged, DLL for DLL, so nothing the modules
actually need was swept out with them.
