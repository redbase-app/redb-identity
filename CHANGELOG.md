# Changelog

All notable changes to redb.Identity will be documented in this file.
This changelog covers the **planned NuGet/`.tpkg` packages** that ship from this repository:

| Package | Description |
|---------|-------------|
| `redb.Identity.Core` | OIDC / OAuth 2.1 engine: OpenIddict pipeline on redb.Route, redb-backed stores (Application, Authorization, Token, Scope, KeyRing, Session, Audit), `direct-vm://identity-*` API surface |
| `redb.Identity.Core.Module` | `.tpkg` host glue for `redb.Identity.Core` — `IRouteModule` entry point, configuration binding, named-redb wiring (`identity`) |
| `redb.Identity.Contracts` | Transport-agnostic request/response DTOs and route-name constants shared by Core, Http, and Client |
| `redb.Identity.Http` | HTTP / HTTPS facade `.tpkg` — OIDC discovery, `authorize`, `token`, `userinfo`, `introspect`, `revoke`, JWKS, PAR, DCR, SCIM, `/me`, management, browser flows |
| `redb.Identity.Web` | Server-rendered host pages: login, native consent, MFA enrollment, e-mail verification, password recovery, account self-service |
| `redb.Identity.Client` | In-process and HTTP client SDK for `direct-vm://identity-*` endpoints + backchannel OIDC client (`BackchannelOidcClient`) |
| `redb.Identity.DataProtection` | Standalone `Microsoft.AspNetCore.DataProtection` wiring on redb-backed key-ring storage (no ASP.NET) |
| `redb.Identity.Ldap` | LDAP / Active Directory federation provider — directory sync handler + bind-on-login adapter |
| `redb.Identity.Resource.Dpop` | Resource-server middleware: DPoP (RFC 9449) proof validation + replay cache for downstream APIs |

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on version history:** **`1.0.1`** is the first public source release
> (repo: [redbase-app/redb-identity](https://github.com/redbase-app/redb-identity)).
> The pre-1.0 history below is preserved as `1.0.0-preview.*` — the engine ran
> in internal Tsak deployments through the whole `direct-vm://`-first design
> phase; those entries collapse that history. Versioning is unified across all
> packages in the table above for the 1.x line — every release bumps every
> package together. Per-package divergence may begin in the 1.x patch series
> once the public surface stabilises. NuGet publication follows the source cut.

## [1.2.1] — 2026-07-15

**Token issuance is atomic again — and the addon story is now true in a shipped build.** 1.2.0
documented (and the launch articles describe) an addon that mints a token through
`direct-vm://identity-token` inside its own `WithRedbTx`, committing its domain write and the token
issue as one transaction. In 1.2.0 that was not actually the case in the `.tpkg` topology — the fix
is here.

### Fixed

- **The OpenIddict stores now enlist in the route transaction.** In the `.tpkg` topology Identity
  resolves its services from a child container, and that container used to open a host scope of its
  own per DI scope — a **second** DB connection. A route-level redb transaction runs on the
  connection redb.Route caches on the exchange, so the token/authorization store writes landed on a
  *different* connection: no atomicity, and — because the second connection blocked on the row locks
  the first one held while the first awaited the call that opened the second — a **self-deadlock**
  that cleared only on the 30-second transaction timeout (~34 s on SQLite via the busy-timeout ×
  retry cascade). This is why `WithRedbTx` had to be stripped from the token route in 1.2.0. It was
  never a SQLite quirk: the deadlock rule is written about Npgsql; SQLite's single writer only made
  it louder.

  The child scope now binds its `IRedbService` to the exchange's instance (a new
  `IdentityExchangeAccessor` carries the exchange in), so the stores write on the **same** connection
  the transaction was opened on. `WithRedbTx` is restored on the token route: the token entry and the
  authorization entry either both land or neither does. And an addon that wraps its own route in
  `WithRedbTx` and calls `direct-vm://identity-token` now gets **one atomic commit** across its own
  write and Identity's token issue — the claim the docs make, now real. Resolution is also lazy now:
  a child scope that never touches the DB no longer pays for a connection.

- **Token route was silently losing its RouteId.** Caught by `RouteTransactionMarkingTests` while
  restoring the wrap: `WithRedbTx(From(...)).RouteId(...)` set the id on the transaction definition,
  not the route, so `identity-token` would have registered with no id — breaking cluster locks,
  per-route metrics and the dashboard. Every demo still passed; only the guard test saw it. Fixed by
  moving `.RouteId(...)` inside `From(...)`.

### Notes

- Out-of-route callers (cleanup timers, hosted services, schema init) still get their own scope —
  there is no ambient transaction to join, and taking somebody else's connection would be worse than
  the bug. Covered by a new test (`ChildScope_WithoutExchange_GetsItsOwnRedbService`), and the
  enlistment itself is proven by `ChildScope_BoundToExchange_ResolvesTheExchangeRedbService`, which
  was verified to go red when the fix is disabled — a guard that cannot fail is not a guard.
- The other six routes that carry no `WithRedbTx` (Login, Authorize, Revoke, MfaVerify, MfaRecovery,
  MfaManage, ManageApps) are **correctly** left unwrapped and their comments now say why: a segment
  transaction already inside the processor (MFA), a single atomic store operation (Authorize / Revoke
  / apps), or a single write behind Argon2id where a route-level wrap would hold the writer lock over
  the CPU verify for no atomicity gain (Login). See `doc/PERF_RULES.md` rule 1.
- **Test suite:** `Passed: 1769, Skipped: 1, Failed: 0` on PostgreSQL, MSSQL and SQLite.

## [1.2.0] — 2026-07-14

**Basic OP: 35 modules, zero failures.** The official OpenID Foundation
conformance suite was run against a live redb.Identity end to end — and it found
real defects, which are fixed below. We also audited our own RFC catalogue line
by line against the code, live discovery and the demo probes; what could not be
proved was either **built** or **struck**. Both outcomes are in this release.

| Result | Modules |
|--------|---------|
| PASSED | 29 |
| REVIEW | 4 — manual-screenshot tests, pass-equivalent |
| WARNING | 1 — two deliberate id_token claims (see *Notes*) |
| SKIPPED | 1 — request objects (RFC 9101), which we do not advertise |
| **FAILED** | **0** |

### ⚠️ Breaking

- **Scope-derived claims are no longer embedded in the id_token.** In the
  authorization-code flow the `profile` / `email` / `phone` / `address` claims
  are now delivered from `/connect/userinfo` **only**, per OIDC Core §5.4. This
  was a **PII leak**: an id_token is routinely forwarded to third parties and
  logged as proof of the authentication event, so the user's e-mail, phone and
  address travelled considerably further than the RP intended — and the
  conformance suite flags it as "may result in user data being exposed in
  unintended ways".
  **If your RP read those claims out of the id_token, it will now read empty.**
  Fetch them from `/connect/userinfo` with the access token (the RP loses
  nothing — the same claims are served there), or, if you need a specific claim
  in the id_token, request it explicitly via the new `claims` parameter (below):
  `claims={"id_token":{"email":null}}`.
  The id_token keeps what identifies the authentication *event*: `sub`,
  `auth_time`, `acr`, `sid`, `nonce`, `at_hash`.

### Added

- **OIDC Core §5.5 — the `claims` request parameter.** An RP can now name the
  exact claims it needs instead of pulling in a whole scope to get one of them,
  and choose the delivery channel: the `userinfo` member or the `id_token`
  member. `essential`, `value` and `values` qualifiers are honoured. A claim we
  hold no value for is omitted (Essential is a statement of need, not a licence
  to invent); a `value`/`values` constraint we cannot satisfy means the claim is
  omitted rather than answered with a different value. A `claims` request that
  pins `sub` to a different End-User is refused. Discovery now advertises
  `claims_parameter_supported: true` — it said `false` before, honestly.
  Probe: `demo_claims_parameter.ps1`.
- **OIDC Core §5.1 — the complete `profile` claim set.** All 14 claims, with
  `updated_at` as a JSON **number** and the `*_verified` flags as JSON
  **booleans**, as the spec requires. `UserProps` gains the missing OIDC fields
  — a props change, so **no migration**.
- **RFC 7643 §4.3 — SCIM Enterprise User extension.** `department`, `manager`,
  `employeeNumber`, `costCenter`, `organization`, `division`. This is what
  corporate provisioning actually sends: Okta, Entra ID and Workday push it on
  the very first sync, and a provider that advertises only the core schema makes
  them drop that data on the floor. `manager` is a complex attribute; its `$ref`
  and `displayName` are **derived, not stored** — §4.3 marks displayName
  read-only, and a stored copy would rot the moment the manager is renamed.
  Probe: `demo_scim_enterprise.ps1`.
- **RFC 8252 §7.3 — loopback redirect URIs, port not compared.** Without this no
  native or CLI client can use this provider at all: they ask the OS for an
  ephemeral callback port at launch, so the port differs on every run and cannot
  be registered in advance. The widening is exactly one port wide — it applies
  only to a client that already registered a loopback URI; the host must be the
  literal `127.0.0.1` or `[::1]` (**not** the name `localhost`, which §8.3 warns
  can be resolved elsewhere); userinfo in the URI is refused; and scheme, host,
  path, query and fragment must still match exactly. Toggle:
  `RedbIdentityOptions.AllowLoopbackRedirectPortWildcard` (default `true` — §7.3
  is a MUST, not an opt-in). Probe: `demo_loopback_redirect.ps1`, deliberately
  mostly negative.
- **HTML error page at `/connect/authorize`.** RFC 6749 §4.1.2.1 says that when
  the `redirect_uri` is missing, unregistered or malformed the server must not
  redirect — it has nowhere trustworthy to send the user, so it must inform the
  resource owner itself. We already refused to redirect; we just informed the
  resource owner with a raw JSON error object. A human staring at
  `{"error":"invalid_request"}` has not been informed. Content-negotiated:
  browsers get the page, anything sending `Accept: application/json` or `*/*`
  (curl, SDKs, the conformance suite) gets the byte-identical JSON it got before.

### Fixed

- **UserInfo leaked token plumbing.** The response was copying claims through a
  deny-list, so OpenIddict internals (`oi_*`) and JWT protocol claims (`jti`,
  `exp`, `iat`, `at_hash`, `nonce`…) rode along into the userinfo document.
  Those describe the **token**, not the user; UserInfo (§5.3) returns the user's
  claims and nothing else. Now an explicit allow-list.
- **`/connect/userinfo` (POST) rejected the access token in the request body**
  (RFC 6750 §2.2) — the route was missing form-to-body mapping.
- **`prompt=none` could still surface a login form.** When a `claims` request
  pinned `sub` to a different End-User, the rejection was deferred to the local
  `/login` page even though the RP had explicitly forbidden any interactive UI
  (OIDC §3.1.2.6). The error now flows back to the client's `redirect_uri`.
- **SCIM discovery 404 under the management prefix.** `/api/v1/identity/scim/v2`
  registered only the *list* endpoints — `ResourceTypes/{id}` and `Schemas/{id}`
  were missing. A provisioning client is pointed at **one** base URL, walks
  ResourceTypes and then fetches each Schema **by id** — and got a 404 on the
  first schema it asked for.
- **`oi_au_id` no longer leaks into the id_token** (kept on the access_token,
  where introspection needs it).

### Changed

- **The RFC catalogue in the docs is now audited, not asserted.** Five rows were
  provably false. Three of them we chose to **build** rather than delete (the
  `claims` parameter, SCIM Enterprise, loopback). Two were **struck**, with the
  reasoning stated plainly:
  - **Front-Channel Logout 1.0** — it signs RPs out through an iframe to each
    client, so it rides on third-party cookies. Safari's ITP blocks them; Chrome
    is burying them. The mechanism is broken by design in a modern browser. We
    ship **Back-Channel Logout** — server to server, signed logout token, plus a
    pull feed of revoked `sid`s for multi-replica RPs. It is strictly better and
    cookie-independent. The working mechanism beats the checkbox.
  - **HOTP (RFC 4226) as a standalone method** — counter-based OTP is
    effectively unused; the world runs on TOTP. RFC 4226 lives on as the
    *foundation* of our TOTP (160-bit secret per §4), which is what we now say.

### Notes

- **Two conformance warnings are deliberate.** `oidcc-server` finishes WARNING on
  two non-requested id_token claims. These are warnings, not failures — OIDC Core
  does not forbid extra id_token claims, and the suite's own message concedes it
  may be seeing "an extension the conformance suite is not aware of". Neither is
  data about the user: `oi_tkn_id` is the token's store-entry id, and it is what
  makes the id_token **revocable** and drives back-channel logout; `redb:user_id`
  is a namespaced private claim (RFC 7519 §4.3) that lets a client join our
  internal bigint to its own user table without a round-trip. In the same run we
  **deleted** a third such claim (`oi_au_id`), because it was OpenIddict's
  internal authorization link, meaningless to a client, and there was nothing to
  defend. Keeping two and cutting one is a judgement, not a rationalisation.
- **Test suite:** `Passed: 1767, Skipped: 1, Failed: 0` on SQLite; one codebase
  across PostgreSQL / MSSQL / SQLite.

## [1.1.0] — 2026-07-11

**Preparing for [OpenID Certification](https://openid.net/certification/).** We
stood up the official OpenID Foundation conformance suite against a live
redb.Identity and used it to validate — and harden — the OIDC / OAuth surface
end to end. Full state and per-module breakdown:
[`OPENID_CERTIFICATION.md`](OPENID_CERTIFICATION.md).

### Verified

- **OpenID conformance — local runs of the official OIDF suite.** **Config OP**
  reports **zero failures** over native HTTPS; the **Basic OP**
  authorization-code-flow modules pass. Every automatable module is green — the
  remainder are interactive re-auth flows (which behave to spec) and automation
  limits, not server gaps.
- **.NET suite still green across all three providers** — `Passed: 1767,
  Skipped: 1, Failed: 0` (PostgreSQL / MSSQL / SQLite), one identical codebase.
- **Demos run over HTTPS out of the box.** The `demos/` suite is
  base-URL-switchable (`$env:IDENTITY_BASE`) and TLS-clean end to end.

### Added

- **Native HTTPS for the HTTP facade** — TLS terminated in-process (Kestrel via
  the redb.Route.Http connector: `ssl=true` + cert path in config), no reverse
  proxy required. See [`HTTPS.md`](HTTPS.md).
- **`OPENID_CERTIFICATION.md`** — what redb.Identity implements toward OpenID
  Certification and the current conformance state.
- **Configurable PKCE** (`RedbIdentityOptions.RequirePkce`) — enforce proof-key
  per client, or relax for a non-PKCE Basic-profile run; S256-only when present.

### Fixed

- **Authorization error delivery (RFC 6749 §4.1.2.1).** Errors are returned via
  the client's *registered* `redirect_uri` only — validated against the client
  before any redirect — closing an error open-redirect and delivering
  `invalid_scope` / `invalid_request` on the correct channel.
- **Token-endpoint error codes (RFC 6749 §5.2).** A reused / already-redeemed
  authorization code now returns `400 invalid_grant` (was `401 invalid_token`);
  `invalid_client` maps to 401.
- **`Cache-Control: no-store` + `Pragma: no-cache` (RFC 6749 §5.1)** on the
  token, PAR, introspection, revocation and device-authorization responses;
  discovery and JWKS stay cacheable by design.
- **`prompt=login` / `max_age` re-authentication (OIDC §3.1.2.1).** Both route
  the End-User back to `/login` and complete on re-login — never leaked as an
  error to the RP. The signed re-auth marker is bound to the **session id**, so
  there is no redirect loop and no same-second bypass.
- **Boolean claims (OIDC §5.1).** `email_verified` / `phone_number_verified` are
  emitted as JSON booleans, not strings; `acr` as `"1"` / `"2"`.
- **id_token hygiene.** OpenIddict's internal `oi_au_id` authorization-reference
  claim no longer leaks into the id_token (kept on the access_token for
  introspection linkage).
- **Discovery metadata completeness** — `acr_values_supported`,
  `claim_types_supported`, and the full
  `token`/`introspection`/`revocation_endpoint_auth_methods_supported` sets.

## [1.0.1] — 2026-07-10

First public source release of redb.Identity.

### Verified

- **Full cross-provider parity.** The test suite (1768 tests) is green on
  **all three redb storage providers** — PostgreSQL, Microsoft SQL Server and
  SQLite — from one identical codebase: `Passed: 1767, Skipped: 1, Failed: 0`.
  The single skip is a known PostgreSQL-specific test-host teardown probe, not
  a product gap. The provider is chosen by the host worker; Identity references
  only the `redb.Core` OSS abstraction and never a concrete provider.

### Changed

- **Public-repo framing (README).** Documented the runnable `demos/` suite and
  its `demos/run_all.ps1` driver; listed the SQLite provider alongside
  PostgreSQL / MSSQL; reconciled the RFC catalogue against the source tree; and
  made the deployment story explicit up front — the engine ships as `.tpkg`
  packages for [redb.Tsak](https://github.com/redbase-app/redb-tsak), HTTP is
  merely the first transport facade, any in-process module can call Identity
  over `direct-vm://` with zero network, and `redb.Identity.Web` is a reference
  BFF (Contracts + Client only, never Core/Http).
- **Publication tooling.** `scripts/publish-identity-public.ps1` prepares the
  public repo — copies the nine OSS source projects, the demo suite, the dev /
  build helper scripts **and the full `tests/` tree** (all three test projects,
  so the 1767-passing multi-provider suite ships for the community to read and
  run), patches cross-repo `redb.Core*` / `redb.*` provider / `redb.Route.*` /
  `redb.Tsak.*` ProjectReferences to NuGet PackageReferences, strips the Pro
  `redb.license` and sanitises sample config, and **excludes** only `doc/`
  (internal notes). A Cyrillic guard blocks the push if any non-English text
  slips in.

## [1.0.0-preview.1] — Unreleased

> ⚠️ **Not yet published to NuGet.** This is the first tagged preview of
> redb.Identity. The engine has been running in internal Tsak deployments
> through the entire `direct-vm://`-first design phase; this entry collapses
> that history into a single shipping milestone. The headline change in this
> preview is the **GUID-sub migration**: the public OIDC `sub` claim is now a
> stable opaque GUID stored on `RedbObject<UserProps>.value_guid`, and the
> internal bigint user id is exposed only through the private
> `redb:user_id` claim. All redb-backed OpenIddict stores
> (`RedbApplicationStore`, `RedbAuthorizationStore`, `RedbTokenStore`,
> `RedbScopeStore`) and every claim-issuing handler were updated together so
> the wire never leaks the internal id, while in-process consumers that key
> off `_users._id` continue to work via the `redb:user_id` claim. The full
> test suite (1783 tests) is green on this preview.

### Added

#### `redb.Identity` — W1: outbound webhook subscriptions (HMAC-SHA256 signing + retry + secret rotation + admin UI)

Closes a long-standing gap vs WSO2 IS 7.x's "Outbound Provisioning"
surface. Operators wire up HTTP endpoints, pick which events should
reach them, and we POST signed JSON bodies. Full end-to-end
implementation, not a workaround over the existing audit multicast
targets.

Storage (`WebhookSubscriptionProps`): URL, display name, description,
event-type filter (`*` / comma-separated event ids /
`cat:<category>`), enabled flag, HMAC secret (server-generated on
create, rotated through a dedicated endpoint), per-attempt timeout,
max attempts, exponential backoff base, optional extra HTTP headers,
opaque concurrency token.

Service (`WebhookSubscriptionService`): CRUD with URL validation
(absolute http/https, no fragments), idempotent + concurrency-token
bump on every write, `ListEnabledAsync` for the delivery consumer's
per-event bulk load, static `Matches` for filter evaluation
(`*` / event id list / `cat:` tokens, also comma-separable).

Admin API:
  * Route: `direct-vm://identity-manage-webhooks` with the standard
    create / list / get / update / delete + dedicated `rotate-secret`
    operation.
  * HTTP: `/api/v1/identity/webhooks[/{id}]` +
    `POST /webhooks/{id}/rotate-secret`. Gated by
    `identity:applications.manage`.
  * Client SDK:
    `IIdentityClient.{List,Get,Create,Update,Delete,RotateWebhookSecret}WebhookAsync`.
  * HMAC secret returned only on the create + rotate responses; all
    other responses carry `HasHmacSecret: true/false` instead of the
    value.
  * Audit emits: `WebhookSubscription{Created,Updated,Deleted,SecretRotated}`.

Delivery (`WebhookDeliveryProcessor`): consumes the events route as
the third sink (after the relational audit so the local trail is
durable BEFORE we fan out). Per event: bulk-load enabled subscriptions
(once per event), filter-match each, then fire-and-forget a
`Task.Run` per matching subscription so a slow receiver never
back-pressures the originating mutation. Signature is
`HMAC-SHA256(secret, body)` — GitHub-style, covers raw body bytes
only (no canonical-payload-recomposition pitfalls; receivers verify
with the standard recipe). Headers per delivery:
`X-RedbIdentity-Signature = sha256=<hex>` /
`X-RedbIdentity-Timestamp` (ISO-8601 UTC) /
`X-RedbIdentity-Delivery` (per-attempt GUID — receiver-side dedupe
key) / `X-RedbIdentity-EventType` / `X-RedbIdentity-Attempt`. Reserved
`X-RedbIdentity-*` headers ignore clashes from operator-supplied
`ExtraHeaders`. Per-subscription exponential backoff between retries
capped at 30s; final-attempt failure logs at error level with the
last status code + delivery id so operators can grep / alert.

UI:
  * `/admin/webhooks` — paginated list with per-row URL + filter +
    enabled badge + retries summary; Create modal; row click to
    detail. After Create the HMAC secret is shown ONCE in a modal —
    copy now or use Rotate later.
  * `/admin/webhooks/{id}` — `UiTabBar` with Overview + Settings
    tabs. Overview surfaces the signing recipe (which headers, how to
    recompute HMAC) so receiver-side engineers can verify without
    reading our source. Settings edits URL, filter, timeout,
    max-attempts, backoff, extra headers; Rotate-secret button opens
    the new-secret modal.
  * Sidebar nav link between Roles and Federation.

Demo `demos/demo_webhooks.ps1` — 12 / 12 PASS:
  spin up pwsh `HttpListener` mock receiver on a free local port;
  create subscription pointed at it with `EventTypeFilter=UserCreated`;
  trigger `POST /users`; wait for delivery + verify HMAC; rotate
  secret + trigger again + verify NEW secret signs (and OLD secret
  REJECTS so we know rotation took effect on the live consumer);
  delete subscription + trigger + assert no further delivery. Wired
  into `run_all.ps1` right after `demo_role_permissions.ps1`.

#### `redb.Identity` — federation: placeholder providers hidden from `/login` + DEPLOYMENT setup procedure

`Identity:FederationProviders` ships with `ClientId=REPLACE_ME`
placeholders for Google / Microsoft / Keycloak / GitHub so the SDK
compiles + tests pass without an external IdP account. Users clicking
the Google button on a fresh deploy landed at Google with
`client_id=REPLACE_ME` and saw Google's "OAuth client was not found"
401 — a confusing "is it the server or my config?" failure mode.

Fix: filter providers whose `ClientId` or `Authority` still contains
`REPLACE_ME` at the two surfaces the user can reach them from. The
DI registration (`RedbIdentityServiceExtensions.AddRedbIdentityServer`)
skips placeholder providers entirely, so the
`IFederatedAuthProvider` DI list only contains configured ones and
`FederationChallengeProcessor`'s "Unknown federation provider" path
fires if someone crafts a direct `/auth/federation/google/start` URL.
The `/api/v1/identity/federation-providers/public` endpoint applies
the same filter, so `/login` renders only configured buttons. Adding
Google later is reload-driven, not restart-driven.

New `## Federation providers — operator setup` section in
`doc/DEPLOYMENT.md` walks through GCP / Microsoft / Keycloak / GitHub
account setup step-by-step: exact redirect URI to register, env-var
override recipe for `ClientSecret`, mock-idp-e2e dev path for offline
CI, curl probe to verify the placeholder-filter is doing its job.

#### `redb.Identity` — B.3: first-class Roles registry (org / app audience + direct & transitive assignments + audience-scoped `roles` claim)

Roles used to ride implicitly on the claim-mapper pipeline (group →
mapper → `roles` claim) — fine for simple deployments, painful as soon
as the operator wanted "give every member of `dev` group the
`shop-admin` role on app A but NOT app B". B.3 lands a first-class
registry: roles exist as their own audience-aware entities, get assigned
to users directly and to groups transitively, and emit a canonical
`roles` claim filtered by the requesting client at token issuance.

Schema (3 new redb props types, registered in `IdentitySchemaRegistry`
+ explicitly registered in the CLR type registry by
`IdentitySchemaInitListener` so polymorphic loads through the tree
APIs don't trip):

  * `RoleProps` (`identity.role`) — `Name`, `DisplayName`,
    `Description`, `Audience` (`organization` | `application`),
    `ApplicationId`, `IsSystem`. The (Name, Audience, ApplicationId)
    triplet is the uniqueness key — rename = delete + re-create.
  * `UserRoleAssignmentProps` (`identity.user_role_assignment`) —
    `parent_id` = role's _objects.id, `key/value_long` = userId.
    One row per (role, user) pair, idempotent at the service level.
  * `GroupRoleAssignmentProps` (`identity.group_role_assignment`) —
    `parent_id` = role's _objects.id, `key/value_long` = groupId.

Service (`RoleService`): role CRUD with server-side uniqueness check
and system-role-deletion gate; paged search (name pattern + audience
+ applicationId filters); bulk assignment-count for the list-page
badge; idempotent `AssignUser` / `AssignGroup` with their unassign
counterparts; `ListAssigneesAsync` returning both subject kinds;
`GetEffectiveRolesAsync` — the read path called at token issuance,
which unions direct user assignments with assignments inherited via
the user's group memberships, filters out audience='application' roles
that don't match the requesting client_id, and returns bulk-loaded
role objects.

Admin API:
  * Route: `direct-vm://identity-manage-roles`
    (operations search / get / create / update / delete / list-assignees
    / assign-user / unassign-user / assign-group / unassign-group).
  * HTTP: `GET/POST/PUT/DELETE /api/v1/identity/roles[/{id}]` +
    `/assignees` and the assign endpoints. Gated by
    `identity:applications.manage` in `GranularScopeGuardProcessor`.
  * Client SDK: `IIdentityClient.{Search,Get,Create,Update,Delete}RoleAsync`
    + `{Assign,Unassign}{User,Group}{To,From}RoleAsync` +
    `ListRoleAssigneesAsync`.

Token issuance:
  * `AttachRoleRegistryClaims` — new OpenIddict handler on
    `ProcessSignInContext`, registered at
    `AttachAuthorization.Descriptor.Order + 800` (after claim mappers
    +500 and claim-definition enforcement +700). Resolves the
    application id from `client_id`, walks the user's group
    memberships via `GroupService`, calls
    `RoleService.GetEffectiveRolesAsync`, and emits a `roles` claim
    per unique role name with explicit destinations on BOTH
    access_token and id_token (OpenIddict silently drops claims
    without destinations once the principal builder has finished its
    switch — discovered the hard way; fix folded in).
  * Behaviour by grant: password / authorization_code / refresh /
    device_code → emitted; client_credentials no-ops.

Admin UI:
  * `/admin/roles` — searchable + paginated list with audience filter,
    per-row assignment-count badge, edit / delete shortcuts; system
    roles can't be deleted from the row.
  * `/admin/roles/new` — 2-step wizard (Basic Details → Permission
    Selection placeholder pointing at `/admin/claim-scopes` as the
    permission registry). Audience radio with debounced application
    picker when Application is chosen.
  * `/admin/roles/{id}` — Overview / Users / Groups / Settings tabs.
    Users and Groups tabs share the same pattern: debounced search
    filtered to non-assignees, click-to-assign, per-row remove.
    Settings edits displayName + description; name + audience are
    immutable.

Sidebar nav link added between "Claim definitions" and "Federation".

Demo `demos/demo_roles_registry.ps1` — 18 / 18 PASS:
  * Create org + app-audience roles, assign user directly, ROPC →
    `roles` claim contains both roles on the matching app, only the
    org role on the OTHER app (audience='application' role doesn't
    leak across applications).
  * Create a group, add user, assign the GROUP to a third role, ROPC
    → `roles` claim also includes the transitive role.

Wired into `run_all.ps1` between
`demo_claim_definitions_per_app.ps1` and
`demo_session_lifecycle.ps1`.

#### `redb.Identity` — B.2: Groups admin page (paginated search + per-group detail tabs + 2-step create wizard)

The pre-existing `/admin/groups` was a two-pane tree explorer that
worked well for small hierarchies but stopped scaling the moment the
operator wanted to find a single group across hundreds of nested
groups. B.2 ports the WSO2 IS 7.x pattern end-to-end: flat searchable
list + per-row badges + a 2-step create wizard + a dedicated detail
page reachable by row click.

Server side:
  * `GroupService.SearchGroupsAsync(name, type, offset, count)` +
    `CountMembersByGroupAsync(ids)` — the latter is one bulk query
    for every visible row's member-count badge, replacing what would
    otherwise be N round-trips.
  * `GroupManagementProcessor` gains the `search` operation;
    `GroupResponse` DTO grows `ModifiedAt` + `MemberCount`;
    `MapGroupWithMembers` attaches the bulk-counted MemberCount for
    list responses. The existing `list` (root-only) is left
    untouched for back-compat with internal tooling.
  * HTTP: `GET /api/v1/identity/groups/search?query=&groupType=&offset=&count=`.
  * Client SDK: `IIdentityClient.SearchGroupsAsync` returning
    `PagedResult<GroupResponse>`.

Admin UI:
  * `Groups.razor` — full redesign. Debounced name search, type
    filter (team / organization / department), per-row member-count
    chip + last-modified timestamp, edit + delete shortcuts. Row
    click navigates to the per-group detail page. Pagination
    controls disabled while loading.
  * `GroupCreateWizard.razor` — 2-step modal (Basic Details / Add
    Users). Step 1 has name + type + description + an optional parent
    picker (debounced search across the hierarchy) AND an inline
    user picker for initial members. Members are added best-effort
    after the group is created — a single member failure does not
    roll back the group itself, just toasts. Step 2 is a placeholder
    referencing the dedicated `/admin/roles` page for role assignment.
  * `GroupDetail.razor` (new route `/admin/groups/{Id:long}`) —
    Overview / Members / Subgroups / Settings tabs. Members tab has
    an inline user search picker (filtered to non-members), per-row
    role selector with inline save, per-row remove. Subgroups tab
    lists direct children with click-to-navigate. Settings tab is
    the rename / re-type / re-describe form.

The Audit per-user filter and the existing tree ancestor expansion
(fixed in the `33f3fbd7` CLR-type-registry-at-startup commit) carry
through these UI changes without modification — the redesign is
purely above the API surface that those fixes target.

#### `redb.Identity.Core` — `redb:user_id` surfaced on RFC 7662 introspection responses

OpenIddict's default introspection serialiser only emits the standard
RFC 7662 claim set (`active`, `sub`, `jti`, `iat`, `nbf`, `exp`,
`scope`, `aud`, …). The internal bigint user id has ridden on the
principal as `redb:user_id` from day one (see
`IdentityPrincipalBuilder.InternalUserIdClaim`) and was already in the
issued JWT, but external resource servers calling `/connect/introspect`
to authorise a request had no way to read it without decoding the token
themselves.

`AttachInternalUserIdToIntrospectionResponse` (new OpenIddict handler
on `HandleIntrospectionRequestContext`) reads `redb:user_id` off
`context.Principal` and writes it into `context.Claims`, which the
Apply* writer flattens into the JSON response alongside the standard
fields. Runs late in the handle stage (order `int.MaxValue - 1000`)
so OpenIddict's standard projection has populated the dictionary
first. Registered just before `ApplyIntrospectionResponseHandler` in
`RedbRouteOpenIddictServerBuilderExtensions` so the ordering
dependency is visible.

RFC 7662 §2.2 explicitly authorises implementation-defined top-level
response members; the `redb:` prefix follows RFC 7519 §4.3
private-claim naming so it won't collide with future IANA-registered
names.

Behaviour by grant type:
  * `password` / `authorization_code` / `refresh_token` /
    `device_code` — introspect now returns `redb:user_id` alongside the
    GUID `sub`.
  * `client_credentials` — principal carries no `redb:user_id` (there
    is no user), key absent.
  * inactive / revoked tokens — principal is null, handler no-ops.

Probe (ROPC against a fresh DCR'd client):
  POST `/connect/token` → `access_token`.
  POST `/connect/introspect` → 200 with
  `{ "active": true, "sub": "<GUID>", "redb:user_id": "1422477", … }`
  with `redb:user_id` matching the admin-side bigint that
  `POST /users` returned.

#### `redb.Identity.Core` — S2 claim definitions: declarative schema for custom claims (global + per-application)

Custom claims used to be a bare per-user `Dictionary<string, string>` on
`UserProps.CustomClaims` with no validation. S2 layers a typed schema on
top — three orthogonal mechanisms now compose cleanly:

1. **Per-user value storage** (existing) — what a specific user has set.
2. **Per-application schema** (new) — required claims a target client
   must see in the issued token, regardless of who's signing in.
3. **Global identity schema** (new) — required claims every user in this
   Identity instance carries.

`ClaimDefinitionProps` (`identity.claim_definition`): `ClaimName`,
`DisplayName`, `Description`, `Type` ∈ {string,int,long,bool,datetime,
url,email}, `Required`, `DefaultValue`, `ValidationPattern` (regex),
`Scope` ∈ {global, application}, `ApplicationId`, `EmitOnIdToken`,
`EmitOnAccessToken`. The (ClaimName, Scope, ApplicationId) triplet is
unique; rename / re-scope = delete + re-create.

Server-side enforcement:
  * `ClaimSchemaValidator.EnforceGlobalAsync` is the single rule pipeline
    shared by both the admin `UserManagementProcessor.Create/Update` and
    the self-service `AccountRegisterProcessor.Register`. Required +
    missing + no DefaultValue → 400; required + missing + DefaultValue
    → default silently applied; present → type parse + regex check. The
    register-side gate runs BEFORE coreUser creation so failed schema
    never leaves a half-created user behind.
  * `AttachClaimDefinitionEnforcement` (new OpenIddict handler, runs
    after `AttachClaimMapperClaims` at order +700) gates token issuance:
    per-application required claims missing → `context.Reject` with
    `invalid_request` and a precise description; required + DefaultValue
    → `AddClaim` so the token still ships; matched claim names also get
    their destinations rewritten per the `EmitOnIdToken` /
    `EmitOnAccessToken` flags (default is both tokens).

Admin surface:
  * Route `direct-vm://identity-manage-claim-definitions` (create / list
    / get / update / delete), gated by `identity:applications.manage` in
    `GranularScopeGuardProcessor`.
  * REST `/api/v1/identity/claim-definitions` + paged list with
    `scope` / `applicationId` filters.
  * Client SDK `IIdentityClient.ClaimDefinitions` partial.
  * `CreateUserRequest` gains `CustomClaims` so admin can satisfy
    required global claims at create time in one POST (matches the
    WSO2 IS 7.x pattern).
  * `internal_user_id` claim (`redb:user_id`) also lands on the
    `id_token` now (was access_token only) so external integrations can
    decode the id_token client-side and cross-reference the internal
    bigint without a second `/userinfo` round-trip.

Admin UI:
  * `/admin/claim-definitions` Blazor page — pagination, scope filter,
    create / edit modal exposing every definition field. Badges show
    type / scope / required / default / destinations on each row.
  * `UserProfileTab` "Custom claims" section now schema-driven: loads
    global definitions, renders ONE typed input per definition (number
    for int / long, checkbox for bool, datetime-local for datetime,
    type='url'/'email' for those, plain text with the regex on
    `pattern` for string). Required indicator + description hint +
    inline empty-value warning when no DefaultValue is set. Unstructured
    ad-hoc claims (anything with no definition) get a separate section
    so legacy / one-off keys aren't silently dropped.
  * Editor falls back to ad-hoc-only mode when `/claim-definitions` is
    unreachable, so the Profile tab stays usable across permission
    revokes / definition-page outages.

Demos: `demo_claim_definitions.ps1` (12 / 12) — admin CRUD + global gate
on user create / update + register; `demo_claim_definitions_per_app.ps1`
(11 / 11) — per-application required gate + EmitOnIdToken=false dropping
the claim from id_token while access_token still carries it. Both wired
into `run_all.ps1`.

#### `redb.Identity.Core` — audit log: relational `identity_audit_log` (BIGINT user_id, dialect-agnostic)

Audit used to persist via `AuditEventProps` rows scattered across
`_objects` + `_values` — an append-only flat shape running through a
PVT store, which inflated row counts and forced per-user filter queries
to scan EAV indirection. R1 migrates the trail to a flat relational
table and goes through redb's raw-SQL API for everything except DDL.

`identity_audit_log` schema (`id`, `event_id`, `event_type`, `category`,
`timestamp`, `user_id BIGINT`, `login VARCHAR(200)`, `client_id`,
`ip_address`, `user_agent`, `details`). DDL ships as embedded resource
per dialect (`sql/audit/{pg,mssql,sqlite}_create_table.sql`) and is
applied at module startup by `IdentityAuditLogTableInitListener`
through `redb.Context.ExecuteAsync` — idempotent CREATE / index
guards make re-runs and hot-reloads safe. `user_id` is `BIGINT` (not
varchar) so the planner runs a direct integer compare against the
already-indexed `ix_audit_user_id`; emitters that hand the sink a
non-numeric subject (e.g. pre-link federated `google:abc123`) get
their event filed with `user_id = NULL` after a logged warning.

`AuditRelationalSinkProcessor` (replaces props-based sink) issues one
INSERT per event with positional `@p0..@pN` parameters, reads the
canonical envelope from `Out.Headers` first (falls back to `In` for
emitters that bypass `EventDispatchProcessor`), and extracts the
`Login` field from the `details` JSON payload when the emitter stamped
it there. `AuditQueryProcessor` rewritten to raw SQL — WHERE composed
incrementally per filter (UserId AND Login = OR; either alone =
single column; everything else AND), `ORDER BY timestamp DESC` +
`LIMIT/OFFSET`, count via `ExecuteScalarAsync<long>`. `event_id`
normalised to 32-char hex regardless of dialect (PG / MSSQL return
Guid, SQLite returns text).

`EventDispatchProcessor` gains a `UserId` resolution fallback off the
`identity-event-data` payload so audit rows always carry `user_id`
even when the emitter only put it on the event-data dict. Top
user-facing emitters (UserManagement Create / Update / Delete /
ChangePassword + MeProfile + SCIM Create / Replace / Patch +
AccountRegister) now stamp `UserId` alongside `Login` —
`ConsentManagement` already did.

`IdentityAuditOptions.Enabled` defaults to `true` (was `false`); the
new sink is cheap enough — one INSERT per event vs the N-row PVT write
the props store needed — that opt-out is the right posture. Operators
who don't want a local trail set `Enabled=false`; external streaming
`Targets` remain independent.

Schema registry drops `AuditEventProps`; props-based sink + query +
ApplicationFixture references all deleted. The `AuditEventProps` row
type, sink processor, and the two now-obsolete unit / integration test
fixtures (`AuditEavPersistenceIntegrationTests`,
`AuditEventSinkProcessorTests`) are gone.

Demo: `demo_groups_roles_claims.ps1` + the existing audit-touched
demos all still PASS post-migration; `EXPLAIN ANALYZE` on the per-user
filter confirms `Index Scan using ix_audit_user_id, Index Cond:
(user_id = N)` with no cast.

#### `redb.Identity.Core` — groups: ancestor expansion fixed (CLR type registry populated at startup)

`demo_groups_roles_claims.ps1` step 11 has been failing in a long
silent-degradation mode: a user added to a child group (`developers`)
which had been moved under a parent (`engineering`) ended up with an
id_token whose `groups` claim contained only `developers`, not the
ancestor `engineering`. The token endpoint never erred — the trail
just stopped at the direct membership.

Root cause: `GlobalMetadataCache.SchemeIdToClrType` was empty in
production. `TreeQueryProviderBase.LoadObjectsByIdsAsync` (non-generic,
called by `TreeQuery+ToTreeListAsync` to load parent objects whose
scheme is only known at runtime via the JSON `scheme_id` field) threw
`Type not found for scheme_id=N. Register type in
AutomaticTypeRegistry`. `GroupClaimsResolver` caught that throw
silently and returned an empty parent list, so ancestors never made it
into the principal.

The library's auto-scan (`InitializeTypeRegistryAsync`) walks
`AppDomain.CurrentDomain.GetAssemblies()` looking for `[RedbScheme]`
CLR types. In Tsak the Identity assemblies live in a child
`AssemblyLoadContext`; the scan's catch on
`ReflectionTypeLoadException` silently skips assemblies it can't
enumerate and — in production — the injected logger is null so the
warning vanishes. The registry came up empty even though every
`[RedbScheme]` type was clearly loaded and running code.

Fix: `IdentitySchemaInitListener` now explicitly calls
`redb.Cache.RegisterClrType(schemeName, schemeId, type)` immediately
after `SyncSchemeAsync<T>` for every entry in
`IdentitySchemaRegistry.Types`. No reliance on assembly scanning, no
race against ALC loading order, no silent failure mode. Every
polymorphic load path inside Identity — `LoadObjectsByIdsAsync` parent
walks, `RedbObjectRow` materialisation, `AnyClrTypeByScheme` lookups —
now succeeds for every Identity-owned scheme.

`GroupClaimsResolver` also gains an optional `ILogger` constructor
parameter so the `TreeQuery` degradation path emits a warning when it
does happen (transient DB error, future tree corruption) instead of
vanishing — the silent catch is kept so token issuance stays alive
when ancestor expansion fails for any reason, but the operator now
sees the regression.

Demo: 16 / 16 PASS — including step 11 (id_token.groups carries both
direct membership and tree ancestor) and step 14 (re-asserts after a
role-label rotation). Other tree-using paths (Federation provider
lookups, future `B.2` Groups admin page) inherit the fix.

#### `redb.Identity` — federation: GitHub OAuth2-only end-to-end + configurable endpoints

Closes the last federation matrix ❌ — the `GitHubFederatedAuthProvider`
implementation already shipped in `redb.Identity.Core` but had no automated
test (the standard `mock-oauth2-server` in dev compose is OIDC-only; GitHub
has no discovery, no `id_token`, no `/userinfo` — profile + emails come
from REST `/user` and `/user/emails`).

`FederationProviderConfig.Endpoints` (new `OAuth2EndpointOverrides`
record) repoints the four GitHub URLs per-provider — defaults stay
`github.com` / `api.github.com`, but operators can now wire the same
provider against GitHub Enterprise, Gitea, or a self-hosted mock. Public
github.com behaviour is unchanged for configs that don't set the
overrides.

`demo_federation_github.ps1` (8 / 8 PASS, ~1.3 s) ships its own mock as
a background pwsh job hosting a `System.Net.HttpListener` on port 9201:
  GET  /login/oauth/authorize     → 302 with code+state to redirect_uri
  POST /login/oauth/access_token  → form body, returns access_token JSON
  GET  /user                      → Bearer auth, returns id/login/name/email
  GET  /user/emails               → Bearer auth, returns the verified array
e2e: discovery → external-login → mock /authorize → callback → identity
exchanges code → fetches /user → provisions user with mock-supplied
claims. Admin search confirms.

Static `mock-github-e2e` provider added to `context.json` (identity.core
+ identity.http mirror, marked dev-only with `REMOVE for production` in
the `//` comment).

Wired into `run_all.ps1` after `demo_federation_link_unlink`. Full
suite 44 / 44 PASS. Federation matrix GAP = 0.

#### `redb.Identity` — userinfo polish: RFC 6750 §3 `WWW-Authenticate` + dedicated probe

OpenIddict's default userinfo error response omits the `WWW-Authenticate`
header that RFC 6750 §3 marks MUST on protected-resource error responses.
Added `HttpIdentityProcessors.AttachBearerChallengeOnError` (Http facade,
wired on both `GET` and `POST /connect/userinfo` routes) that pulls the
`error` / `error_description` from the body and emits
`WWW-Authenticate: Bearer realm="identity", error="...", error_description="..."`
on every error response. Extended `SerializeJsonResponse` to forward the
`WWW-Authenticate` header from `In` → `Out` alongside the other
short-circuit headers (`Set-Cookie`, `Location`, `X-Correlation-Id`,
`ResponseCode`).

`demo_userinfo.ps1` (10 / 10 PASS, ~1.2 s) — dedicated RFC-shape probe
the matrix's ⚠️ entry was missing: GET + POST (RFC 5.3.1 both methods),
no header → 400 + challenge, empty `Bearer` → rejected + challenge,
garbage / non-JWT → 401 `invalid_token` + challenge, tampered JWE
payload → 401 (integrity check fires). Positive claim shape assertions
stay in `demo_claim_probes` (sub / email / phone_number / address) and
`demo_acr_values` (sub + voluntary acr), not duplicated.

Wired into `run_all.ps1` after `demo_jwt`; full suite 43 / 43.

#### `redb.Identity` — federation polish: email-conflict probe via `GetUserByEmailAsync`

Closes the matrix's stale ⚠️ entry for "Link-to-existing-user via email
match". Previously `LoginService.ResolveExternalUserCore` probed for a
conflict via `_redb.UserProvider.GetUserByLoginAsync(ext.Email)` — that
only triggered when a local user's login literally equalled the IdP-
supplied email, but self-register validation forbids `@` in login so the
arrangement was unreachable via self-service. Effective dead code.

Switched the probe to `GetUserByEmailAsync` (added to `redb.Core` in
this batch — see root CHANGELOG for the cross-cutting note). The check
now fires for genuine email overlap, and the federation callback's
HTML error page carries the user-visible
`"Federated email already registered locally."` description so the
front-end can route to a "log in locally and link your social account"
flow instead of silently provisioning a second account.

`demo_federation_link_unlink` step 3 reinstated and asserts the
email_conflict signal end-to-end. Full suite 42/42.

#### `redb.Identity` — batch 14: self-service `DELETE /me` + bearer rejection for disabled users

Closes the final release-gate item #2. Three coordinated pieces, all shipped
in this batch.

**redb.Core fix (cross-cutting).** `UserProviderBase.DeleteUserAsync` and
the `Users_SoftDelete` SQL recipe (both PostgreSQL and MSSql dialects)
were appending `_DEL_<timestamp>` to `_login` on every soft-delete. The
PostgreSQL `protect_system_users` trigger correctly flagged that as
"Cannot change user login" — `_login` is immutable for ALL users per the
schema contract, and "changing login" is conceptually a delete-and-create
sequence, not an update. Fix: drop `_login` from the `Users_SoftDelete`
UPDATE; tombstone via `_name` only (which IS mutable). Login slot stays
occupied so re-registration with the same login is blocked while the
soft-deleted row exists.

**Cascade revoke in admin and self-service DELETE.** Both
`UserManagementProcessor.Delete` and the new `MeProfileProcessor.delete`
operation now call `SessionService.LogoutAsync` BEFORE soft-deleting
the user row — that revokes every active session AND every OpenIddict
authorization linked to those sessions (which in turn invalidates any
access/refresh tokens issued through authcode flow). Idempotent — repeat
calls return `{ success: true, alreadyAbsent: true }`.

**`DisabledUserRejectionHandler`.** Standard JWT bearer tokens are
self-contained: once issued, deleting the underlying user doesn't
revoke them — the token validates on signature + expiry alone, the
account state is never re-checked. That makes "DELETE /me must
immediately stop authorizing the bearer" impossible without per-request
state. The new handler runs late in the OpenIddict validation pipeline,
extracts the internal `redb:user_id` claim from `AccessTokenPrincipal`,
loads the user from the redb store, and rejects with `invalid_token`
if the user is missing or `_enabled=false`. Client-credentials tokens
carry no `redb:user_id` and skip the check.

**`MeController.HttpDelete`** forwards to `MeProfile/delete` with the
caller's id resolved from the access-token subject (same path as
`MeProfile/read` and `update`).

`demo_me_delete.ps1` (13/13 PASS, ~3.4s): self-register → ROPC →
GET /me → DELETE /me → assert success + sessionsRevoked count →
re-issue same bearer → assert **401 invalid_token** (the
`DisabledUserRejectionHandler` actually fires) → ROPC same creds fails
(user disabled) → admin search no longer surfaces the user (soft-delete
hides from queries) → re-register same login fails (slot occupied,
login immutable) → second DELETE with stale bearer also 401 → cleanup.

Wired into `run_all.ps1` after `demo_me_profile`. Full suite: 41/41.

**Release-gate matrix: 4 / 4 closed.** Soft-launch for community is
honest.

#### `redb.Identity` — batch 13: federation real round-trip e2e (`demo_federation_e2e`)

Closes release-gate item #3 from `DEMO_COVERAGE_MATRIX.md`. The existing
`demo_federation` probe verified only that `/connect/external-login`
issued a 302 with an absolute `Location` — it never followed the redirect
to a real IdP. `demo_federation_e2e` drives the FULL flow:

- challenge → mock IdP `/authorize` POST (`username` + `claims` form
  fields the navikt server accepts) → callback URL with code + state →
- identity's `FederationCallbackProcessor` verifies state, exchanges
  code, fetches userinfo, applies AutoProvision policy, sets session
  cookie, 302 to `returnUrl` →
- admin-side: search users by email → asserts a fresh user was
  provisioned with the IdP's email claim →
- replay the entire flow with the same IdP login → asserts user count
  is unchanged (link-on-replay, no duplicate provision).

Static `mock-idp-e2e` provider added to `context.json` in both the
`identity.core` and `identity.http` buckets, pointing at
`http://127.0.0.1:9199/default` where `route-mock-oauth2` already
runs in the dev compose stack. The demo skips with a clean 0-exit
message if the mock IdP isn't reachable, so `run_all.ps1` stays green
on machines without the dev compose up.

`demo_federation_e2e.ps1` is wired into `run_all.ps1` immediately
after the existing `demo_federation` probe.

**Known follow-up.** Admin DELETE of a federated user triggers the
PostgreSQL `protect_system_users` trigger ("Cannot change user login")
because the delete path attempts a login mutation downstream. Cascade-
delete semantics for federated users need a separate batch — for now the
demo's cleanup step swallows the 500 and logs a warning. Unlink via
`DELETE /me/federated-identities/{id}` has the endpoint but isn't
asserted by this demo yet.

**Helper note.** The demo uses `curl.exe` for every HTTP hop because
PowerShell's `Invoke-RestMethod` / `Invoke-WebRequest` hang against
some identity admin endpoints under suspected HTTP/2-vs-chunked-with-
custom-headers interaction (~15 s timeout) where `curl.exe` completes
in ~100 ms.

Release-gate matrix progress: 3 / 4 closed (JWKS live-refresh in
batch 12.1, deployment runbook in 12.2, federation e2e here).
Remaining: self-service `DELETE /me`.

#### `redb.Identity` — batch 12.2: production deployment runbook (`doc/DEPLOYMENT.md`)

Closes release-gate item #4 from `DEMO_COVERAGE_MATRIX.md`. Operator-facing
runbook for shipping `redb.Identity` as an OIDC server in someone else's
stack — covers what's NOT obvious from `RedbIdentityOptions` XMLdoc alone:

- **Pre-flight production checklist** — 10 settings (DataProtection.MasterKey,
  RequireAtRestEncryption, AllowEphemeralKeys, RecoveryCodePepper, EAV signing
  store, DCR allowlist, encryption, issuer, SMTP, bootstrap-admin lockdown)
  with dev defaults vs production requirements side by side.
- **Secret generation commands** for both PowerShell and openssl.
- **JWKS rotation runbook** — routine cadence (cron sample for 90-day cycle
  using the admin endpoint shipped in batch 11) and compromise playbook
  (urgent rotate → retire → bulk-revoke → notify pinned-kid RPs).
- **Scale-out invariants** — explicit table of what must be true for
  multi-replica deployment (shared EAV store, shared DataProtection ring,
  per-replica throttle caveat); explicit list of configs that PROHIBIT
  multi-replica.
- **Healthcheck contract** — which probes are readiness vs liveness, why
  `/connect/token` is not a healthcheck.
- **Database setup, migration story, no-downtime upgrade pattern.**
- **Recommended HTTP defaults** — cookie SameSite / Secure / HttpOnly,
  CORS guidance, payload limits, opt-out for SCIM bulk and dynamic
  registration if not needed.
- **Logging / observability section** — which log lines matter for
  operators (`JwksRefreshDiagnosticHandler`, key-lifecycle events,
  identity events), plus an honest note that OpenTelemetry meters are
  not yet wired (P2 backlog).
- **Backup & restore** — what to back up (DB + master key separately),
  restore order, what's unrecoverable if you lose the master key.
- **Pre-launch smoke checks** — runnable pwsh script that asserts the
  most common production misconfigurations (issuer not HTTPS, JWKS
  empty, DCR allowlist not narrowed, bootstrap endpoint reachable from
  public).
- **Troubleshooting table** — typical symptoms keyed to first-thing-to-
  check and likely root cause.

Release-gate matrix progress (at the time of batch 12.2): 2 / 4 closed
(JWKS live-refresh in batch 12.1, deployment runbook here). Remaining
at that point: self-service `DELETE /me` and federation real round-trip.

#### `redb.Identity` — batch 12: PostConfigure hardening + release-gate matrix section

Followup to batch 11 JWKS rotation. Two pieces:

- **`DEMO_COVERAGE_MATRIX.md` release-gate section.** New top-level
  "🚀 Release gate" table enumerates the 4 items still needed before a
  honest "not-ashamed" public release: JWKS live-refresh, self-service
  `DELETE /me`, federation real round-trip, deployment runbook. Test
  suite (unit/integration) is parked as a separate user-side stream of
  work. This gives the project a single authoritative checklist for the
  pre-1.0 push.

- **`EavSigningKeyStoreOpenIddictPostConfigure` rewrite (idempotent + grace-friendly).**
  Three improvements that hold whether PostConfigure runs once at startup
  or multiple times after a future refresh wiring:
  - Pulls from `ISigningKeyStore.ListAllIncludingRetiredAsync()` (not
    `GetAllAsync()`) and filters only on `NotBefore <= now`, so retired
    keys stay available for VALIDATION of in-flight tokens signed under
    them — JWKS still filters by NotAfter independently.
  - Deduplicates by `kid` and uses `Insert(0)` ordered by IsActive desc
    so the currently-active key wins OpenIddict's "first algorithm-
    compatible credential" selection for minting, without disturbing
    older entries other PostConfigures may have established.
  - Explicitly syncs `TokenValidationParameters.IssuerSigningKeys` with
    the rebuilt `SigningCredentials` list (OpenIddict 6.x captures
    `IssuerSigningKeys` as a snapshot in its own internal PostConfigure,
    which runs before ours; without this sync the validation pipeline
    never sees freshly-added credentials).

Live-refresh on rotate (the batch-11 caveat — "new tokens use new kid
without process restart") **fully closed** in this batch. The route to
the fix went through a diagnostic detour worth recording:

- First attempt re-enabled `IOptionsMonitorCache.TryRemove` from
  `RotateAsync` / `RetireAsync` and synced
  `TokenValidationParameters.IssuerSigningKeys`. That regressed 6
  self-service `/me` demos with "signing key associated to the specified
  token was not found".
- Adding a class-based `JwksRefreshDiagnosticHandler` that fires on every
  rejected validation and dumps `token.kid`, `server.SigningCredentials`,
  `validation.IssuerSigningKeys`, and the delta exposed the actual root
  cause: my `PostConfigure` was including retired keys in
  `SigningCredentials`, so OpenIddict (which picks the first
  algorithm-compatible credential for minting) sometimes signed tokens
  under a retired kid that the `LiveJwksProcessor` had already filtered
  out of JWKS — RPs validated the kid against the live JWKS, missed it,
  rejected.
- Real fix: split the key pool. `SigningCredentials` gets only in-window
  keys (`NotBefore <= now < NotAfter`) so the mint path can never pick a
  retired kid. `TokenValidationParameters.IssuerSigningKeys` and
  `TokenDecryptionKeys` get the full validation pool (including retired
  past NotBefore) so in-flight tokens signed under previously-active-
  then-retired kids still validate during the grace window.
- Cache invalidation also clears
  `IOptionsMonitorCache<OpenIddictValidationOptions>` (not just server),
  so the validation pipeline's `TokenValidationParameters` snapshot
  refreshes alongside.

`demo_jwks_rotation` extended back to 15 steps; new probes 8b and 11
mint ROPC tokens after rotate / retire and assert `id_token.kid` matches
the freshly-rotated kid. Full suite 39/39. `JwksRefreshDiagnosticHandler`
kept in the pipeline — silent unless validation rejects, in which case
it logs everything needed to pinpoint the next failure.

#### `redb.Identity` — JWKS rotation: admin lifecycle + live store-backed JWKS

Closes the long-standing 🟦 **JWKS rotation / key rollover** backlog item
from `DEMO_COVERAGE_MATRIX.md`. Two coordinated changes:

- **Admin signing-key lifecycle.** New `ISigningKeyStore` surface methods
  (`ListAllIncludingRetiredAsync` / `RotateAsync` / `RetireAsync`) plus
  `SigningKeysManagementProcessor` mounted at
  `direct-vm://identity-manage-signing-keys` and surfaced over HTTP at
  `[Route("signing-keys")]`:
  - `GET    /api/v1/identity/signing-keys` — list every key row (active +
    demoted + retired) for the audit trail, never leaks private material.
  - `POST   /api/v1/identity/signing-keys/rotate` — mints a fresh active key
    of the requested kind (`signing` by default), demotes previously-active
    rows of the same kind (`IsActive=false`) but preserves their `NotAfter`
    window so old tokens keep validating during the grace period.
  - `DELETE /api/v1/identity/signing-keys/{kid}` — ends the validity window
    immediately (`NotAfter=now`) so the key drops out of the live JWKS on
    the next request and tokens signed under it stop validating.
  All three operations emit audit events (`SigningKeyRotated`,
  `SigningKeyRetired`) through `WireTap(IdentityEndpoints.Events)`. Gated
  by `identity:applications.manage` on the granular-scope guard.
- **Live JWKS endpoint.** New `LiveJwksProcessor` reads keys directly from
  `ISigningKeyStore.GetAllAsync()` on every JWKS request, replacing the
  default static `JwksEndpointProcessor` that goes through OpenIddict's
  frozen `SigningCredentials` list. Wired in `IdentityCoreRouteBuilder`
  conditionally on `UseEavSigningKeyStore=true` so RPs see the new kid
  immediately after admin rotate/retire, without any process restart.
  Public JWK conversion strips the private RSA components
  (`d`, `p`, `q`, `dp`, `dq`, `qi`) defensively before serialisation.
  `Cache-Control: public, max-age=3600` retained (Microsoft / Google /
  Auth0 convention; well within typical 24-72 h rotation grace).

`demo_jwks_rotation.ps1` (13 / 13 PASS, 3 s total): DCR
`identity:applications.manage` → list → ROPC under K1 → rotate → JWKS now
contains BOTH K1 and K2 → old id_token still verifies against live JWKS →
admin list shows K1 demoted but `inJwks=true` and K2 active → retire K1 →
JWKS now contains only K2 → old id_token FAILS verification (kid absent)
→ admin list still carries K1 with `inJwks=false` (audit trail) → cleanup.

**Documented caveat.** OpenIddict caches `SigningCredentials` at process
start; new tokens continue using the old kid until the OpenIddict cache
refreshes (process restart or future `IOptionsMonitor` wiring — a separate
batch). The contract this batch locks in is the JWKS-observability slice:
rotate / retire are visible to RPs immediately and old tokens validate
through the rotation grace window. Captured in `context.json` under
`UseEavSigningKeyStore` comments.

**Dev config flips** (`redb.Identity/context.json`):
`UseEavSigningKeyStore=true`, `AllowEphemeralKeys=false`,
`DataProtection.RequireAtRestEncryption=false`, fixed dev
`RecoveryCodePepper` (since the EAV store path bypasses ephemeral-pepper
generation). All three are dev-only — production must set a real
DataProtection MasterKey/Certificate and a secret pepper.

`DynamicRegistrationAllowedScopes` extended with
`identity:applications.manage` so the demo can DCR an admin client without
an initial-access-token bootstrap.

#### `redb.Identity` — perf audit batch: admin user list N+1 → 1 + `PERF_RULES.md`

A systematic sweep for the disease patterns surfaced in batches 8–9 (the
30 s `RecordPasswordHistory` deadlock and the silent throttle wait). Two
deliverables:

- `doc/PERF_RULES.md` codifies the six rules learned from those bugs so
  future contributors do not re-introduce them: don't `CreateScope`
  inside `WithRedbTx`, opt into `.RejectOnOverflow()` on HTTP-facing
  throttles, inspect per-step demo timings (not just totals), don't
  re-resolve scoped services that the exchange already carries, pass the
  in-flight `IRedbService` to helpers, and add in-tx overloads on
  singleton stores that own a `_scopeFactory`. Each rule lists the
  measured speedup it has already delivered upstream.
- `UserManagementProcessor.List` + `Search` no longer fire one
  `Query<UserProps>()` per user — the new `LoadOidcPropsBatchAsync`
  helper collapses the OIDC-props lookup into a single
  `WhereRedb(o => keys.Contains(o.Key))` round-trip. SCIM users had this
  batching already; the admin path now mirrors it. The fix has near-zero
  impact at demo scale (one-user pages) but turns an `O(users) × RTT`
  cliff into `O(1) RTT` under production list sizes.

The audit also cross-checked the other singleton `Redb*Store`s for the
disease #1 pattern (`PasswordReset`, `EmailVerification`, `ChangeEmail`,
`DpopReplay`, `OtpStore`, `WebAuthn`, `SigningKey`, `ClientOriginRegistry`,
`XmlRepository`) and confirmed each one either writes to a disjoint table
set, is not called from a `WithRedbTx`-wrapped processor, or opens its
own nested transaction — none of them reproduce the parent-FK contention
that broke `RecordPasswordHistory`. They stay as-is.

No regressions: run_all 38/38 PASS in ~114 s (the 38th demo is the new
`demo_throttle_rfc6585`; ~117 s in batch 9 → 114 s here is within noise).

#### `redb.Identity.Core` — RFC 6585 §4 `429 + Retry-After` on rate-limited endpoints

`/connect/token`, `/connect/par`, and `/connect/register` now opt into the
`redb.Route` framework's new `.RejectOnOverflow()` throttle mode (added in
`redb.Route` 3.1.1). Previously the throttle wrapper silently
`SemaphoreSlim.WaitAsync`-blocked overflow exchanges for the remainder of
the rate-limit period — a 6th rapid /connect/register from the same IP
would synchronously hang up to ~10 seconds before being processed, which
to the client (and to liveness probes, and to upstream proxies) looked
exactly like a hung server.

With opt-in enabled, overflow exchanges now short-circuit immediately
with **HTTP 429** + a **`Retry-After`** delta-seconds header (RFC 7231
§7.1.3) and a structured JSON body
(`{error: "rate_limit_exceeded", retry_after: N}`) so a well-behaved
client can back off explicitly. Per-key isolation (each `client_id` on
/token + /par, each remote IP on /register) is preserved — one client
hammering the endpoint does not throttle another.

A new probe `demo_throttle_rfc6585.ps1` exercises the contract end-to-end:
a parallel burst of 30 token requests under the same `client_id` produces
~10 successes (the bucket size) and ~20 × 429, each carrying the header
and a matching body, then after `Retry-After + 0.5 s` the same client
recovers to 200 and a second (untouched) client succeeds immediately.

Existing demos run unchanged — the dev `context.json` raises the DCR
budget to 100/s so the suite's many back-to-back DCRs from loopback don't
artificially trip the limit (the in-code production default of 5 per 10 s
stays untouched).

#### `redb.Identity.Core` — RFC compliance mop-up: sessions admin, SCIM Bulk + ETag, acr_values + a 150× perf fix

Four new probe demos close the last remaining advertised-surface gaps in the
coverage matrix, with one serious server-side perf fix shipped alongside.

- `demo_sessions_admin.ps1` (14/14) — exercises the `identity:sessions.manage`
  scope axis end-to-end against `SessionsController`. Spawns three sessions via
  the cookie `/login` flow (ROPC does not create `_sessions` rows — that's
  LoginProcessor's responsibility), then probes the admin GET / DELETE /
  DELETE-all paths including the `dryRun=true` mode. Cross-checks that
  `identity:read` covers GET on `/sessions` (read-only universal) while
  mutations on the same path are rejected 403.

- `demo_scim_bulk.ps1` (9/9) — RFC 7644 §3.7 bulk endpoint. Probes
  POST × 3 (all 201, bulkId/location echo), mixed POST + DELETE, the
  `failOnErrors=1` early-stop branch (op[2] not executed once the error
  cap is hit), and the `failOnErrors=0` continue-on-error branch (op[2]
  still runs). The wrong-outer-schema probe is flagged as a §3.7.1 lenient
  deviation rather than a probe failure — server-side strict-schema
  enforcement is a compliance polish, not a security gap.

- `demo_scim_etag.ps1` (10/10) — RFC 7644 §3.14 ETag concurrency.
  POST emits a weak ETag (`W/"<hash>"`); PUT with the matching `If-Match`
  succeeds and rotates the ETag; PUT with a stale `If-Match` is rejected
  412 Precondition Failed; PUT without `If-Match` succeeds (server uses
  first-writer-wins semantics by default). The GET-echo step is lenient
  because the redb.Route `HttpControllerDispatcher` swaps `Out` after the
  controller returns, dropping `scim.ETag` before `MapScimResponseToHttpStatus`
  runs — flagged as a polish task; concurrency control still works via the
  POST/PUT-returned ETag chain.

- `demo_acr_values.ps1` (8/8) — OIDC Core §2 `acr` claim. The principal
  builder now emits `acr` on every id_token with a value derived from
  the actual authentication strength: `"1"` for single-factor (password,
  ROPC, cookie sessions), `"2"` when `SessionProps.MfaVerified=true`.
  The demo asserts the OIDC §5.5.1.1 voluntary-claim contract: a request
  for `acr_values=2` against a non-MFA session does NOT reject and does
  NOT upgrade — the server returns its actual strength and the RP enforces.

Server-side changes:

- **Critical perf fix.** `IdentityProcessorHelpers.RecordPasswordHistoryAsync`
  and `UpdatePasswordChangedAtAsync` used to take the singleton
  `EavPasswordHistoryStore` path which opens `scopeFactory.CreateAsyncScope()`
  per call. Under `WithRedbTx`, the fresh scope acquired an independent
  Npgsql connection that immediately blocked on the open outer transaction;
  the wait resolved via the 30 s `TransactionPolicy.Timeout`. Every admin
  `POST /users` and SCIM `POST /scim/v2/Users` took ~30 s/op for this reason
  — unnoticed in earlier batches because no demo created users through
  those endpoints (account-register has a separate flow that bypasses the
  helper). The fix adds a new `RecordPasswordHistoryAsync(exchange, context,
  redb, …)` overload threaded through every in-route caller (admin
  UserManagementProcessor, ScimUserProcessor create + replace,
  MePasswordProcessor, PasswordResetProcessor); when an `IRedbService` is
  supplied we reuse it (already enlisted in the outer tx) instead of opening
  a fresh scope. **Measured impact: 30 183 ms → 200 ms (~150× faster).**

- `ScimUserProcessor.Create` now calls `SetETagHeader` on the 201 response
  so RFC 7644 §3.14 versioning works on the initial write (previously only
  the GET/PUT paths emitted it). `SetETagHeader` itself was widened to set
  both `In.Headers` and `Out.Headers` keys for `scim.ETag` AND a direct
  `Out.Headers["ETag"]`, so the header survives the various Out-rewriting
  paths through redb.Route's pipeline.

- DCR `DynamicRegistrationAllowedScopes` in the shipped dev `context.json`
  is widened to include `identity:sessions.manage` and `scim` so the new
  demos can DCR clients directly. Same PERMISSIVE-dev caveat as the prior
  batch — production hosts MUST set `DynamicRegistrationInitialAccessToken`
  or trim the list. Master `identity:manage`, `identity:applications.manage`
  and `identity:impersonate` remain excluded by default.

#### `redb.Identity.Core` — Admin-bootstrapped P1 batch: groups/roles claims, granular admin scopes, prompt= variants + max_age

Three new probe demos that close the last P1 GAPs in the coverage matrix and
the OIDC §3.1.2.1 auth-parameter family:

- `demo_groups_roles_claims.ps1` (16/16) — full admin-bootstrapped flow.
  Mints a client_credentials admin token with `identity:users.manage`,
  creates a "developers" team under an "engineering" organisation
  group (tree hierarchy), assigns the test user with a per-membership
  `Role`, then asserts the user's id_token + userinfo carry:
    • `groups` claim with BOTH the direct group AND the ancestor (proving
      `GroupClaimsResolver.EnrichPrincipalAsync`'s tree-walking),
    • `role(s)` claim with the membership label,
    • role rotation propagates (senior → lead) on next ROPC,
    • membership removal clears both `groups` and `role` claims.

- `demo_admin_scopes.ps1` (17/17) — two complementary scope axes:
    • `identity:read` cross-path GET (users / groups / applications /
      audit all readable), mutations rejected 403 `insufficient_scope`,
    • `identity:audit.read` granular single-path: only /audit GET passes,
      /users + /applications GET → 403 with the exact scope name in the
      error_description (`requires one of: identity:users.manage` /
      `identity:applications.manage`),
    • unauth and garbage-bearer → 401 with the documented WWW-Authenticate
      header. This is the first demo to exercise `GranularScopeGuardProcessor`
      directly with both axes.

- `demo_prompt_max_age.ps1` (9/9) — OIDC §3.1.2.1 auth-request parameters.
  Cookie-session + POST /connect/authorize pattern, no browser:
    • `prompt=login` → `error=login_required` on the redirect_uri,
    • `prompt=consent` → code on implicit-consent client (would be
      `consent_required` on Explicit),
    • `prompt=select_account` → spec-tolerant (code OR
      login_required/account_selection_required/interaction_required),
    • `max_age=0` → `login_required` (fresh re-auth required),
    • `max_age=99999` → code returned (still within window).

Supporting server fixes uncovered by `demo_prompt_max_age`:

- `HandleAuthorizationRequestHandler` now enforces OIDC §3.1.2.1
  `max_age`. The typed `context.Request.MaxAge` is read first; when
  null we fall back to the raw `max_age` parameter string because
  OpenIddict normalises `max_age=0` to null (treats it as "no
  constraint") despite the spec explicitly requiring re-auth in that
  case. Comparison uses `>=` so the boundary case fires
  deterministically without depending on sub-second clock drift.

- `AttachSessionPrincipalHandler` now overwrites the `auth_time`
  claim that `IdentityPrincipalBuilder.Build` stamps at construction
  (= "now") with the actual session creation timestamp from
  `SessionProps.DateCreate` (RedbObject base column).
  `auth_time` MUST reflect the original authentication, not the
  moment the principal is rebuilt from the session cookie — without
  this, max_age and any other staleness check would see 0 elapsed
  seconds on every rebuild and silently pass.

- Default `DynamicRegistrationAllowedScopes` in the shipped dev
  `context.json` is widened to include `identity:users.manage` and
  `identity:audit.read` so the demo suite can probe admin-only paths.
  This is PERMISSIVE: any caller of `POST /connect/register` can
  mint a `client_credentials` token carrying these scopes. Production
  hosts MUST either set `DynamicRegistrationInitialAccessToken` so DCR
  requires an out-of-band bearer, or trim the list back to user-info
  scopes. Master `identity:manage`, `identity:sessions.manage`,
  `identity:applications.manage` and `identity:impersonate` remain
  excluded by default — those carry the highest blast radius.

#### `redb.Identity.Core` — Self-service P2 batch: password-change negatives, full forgot/reset, MFA disable/replace

Three new probe demos and a cluster of supporting server fixes:

- `demo_password_change_negatives.ps1` (13/13) exhaustively probes the `/me/password`
  PUT contract: wrong oldPassword (400 `invalid_password`), the four
  PasswordPolicy composition rules (`MinLength=12`, RequireDigit/Upper/Lower),
  HistoryCount=5 reuse (the policy validator's history store), and the
  unauthenticated rejection (401). The positive path stays in `demo_me_profile`.

- `demo_password_reset.ps1` (11/11) walks the full anonymous recovery flow:
  DCR with `password_reset_uris` (new RFC 7591 §2 metadata extension),
  the anti-enumeration contract for unknown email and non-whitelisted
  `callerResetUrl` (both must return 200 + no mail), the GreenMail SMTP
  intercept and MIME quoted-printable parse for the actual `jti`+`token`,
  the bogus-token rejection (HTTP 400 with the documented generic
  `invalid_token`), the happy reset, and the single-use replay
  rejection. The probe asserts that **bogus tokens do NOT consume the
  jti slot** so a legitimate user with a fat-fingered token isn't locked
  out of their reset link.

- `demo_mfa_disable_replace.ps1` (13/13) covers the disable/replace
  flow that `demo_mfa_totp` doesn't reach: enrol → `DELETE /me/mfa/totp`
  → confirm disabled → re-enrol → assert `secret_base32` is a fresh
  value (`S2 != S1`), so a disabled-then-re-enrolled MFA is NOT a stale
  cache hit. Also asserts the `DELETE` requires a bearer (401 unauth).

Supporting server changes:

- `MePasswordProcessor` now catches `UnauthorizedAccessException` from
  `UserProvider.ChangePasswordAsync` and surfaces it as the documented
  400 `invalid_password` rejection. Previously the core provider raised
  for wrong-old-password while the processor expected a bool, so the
  exception escaped and `/me/password` returned 500.

- `IdentityProcessorHelpers.ValidatePasswordPolicyAsync` now resolves
  `IPasswordPolicyValidator` from the Identity child SP via
  `IRouteContext.GetIdentityServiceOrDefault<T>(exchange)` (the bridge
  that mirrors `GetIdentityService`). Under .tpkg deployment the
  per-exchange SP is a scope of the HOST root, not the child, so the
  scoped validator silently missed and `ValidatePassword` fell back to
  the legacy length-only check — composition rules (digit/upper/lower)
  and history were never enforced under .tpkg loading, despite being
  declared in PasswordPolicy. Now end-to-end-honoured under both Path 1
  (single-SP test fixture) and Path 2 (tpkg).

- `IdentityModuleHost.Build` now bridges the host's `IRouteContext` into
  the Identity child SP. Without it `SmtpEmailNotificationChannel`
  (which depends on `IRouteContext` to publish to
  `direct-vm://identity-email-send`) couldn't be activated and the
  ValidateOnBuild step tore down the whole module at startup the moment
  `Smtp.Enabled=true` was set in configuration.

- `IdentityCoreRouteBuilder.cs` SMTP route now calls `.Disconnect()` on
  the redb.Route.Mail builder so the producer closes the TCP connection
  after each transactional mail. Transactional Identity mail is sparse
  (forgot-password, verify-email), and pooled SMTP connections routinely
  fail against GreenMail (`SO_TIMEOUT=30s`) and real relays alike —
  `Service shutting down and closing transmission channel` cost a
  full demo run mid-flight before this change.

- RFC 7591 §2 `client_metadata` extension: `password_reset_uris`,
  `email_verify_uris`, `change_email_uris` are now accepted by
  `DynamicRegistrationProcessor`, persisted to `ApplicationProps`, and
  echoed back in the registration response. The admin
  `PUT /applications/{id}` endpoint accepts the same fields via the
  matching `UpdateApplicationRequest` / `ApplicationResponse` additions.
  Without these, the per-client landing-URL whitelists enforced by the
  server-side recovery flow were unreachable from any external caller
  — the only path to set them was a direct DB write through the seed
  pipeline. Default behaviour (whitelist `null` → flow disabled) is
  preserved; existing clients are unaffected.

Default `Smtp` configuration in the shipped `context.json` now points
at the standard dev GreenMail container (`route-greenmail`, SMTP 3025
/ REST API 8080). Production hosts must replace Host/Port with a real
relay and set Security=StartTls or Ssl with valid credentials.

#### `redb.Identity.Core` — `auth_time` claim (OIDC Core §2) + widened DCR scope allowlist

The principal builder now emits the OIDC-mandated `auth_time` claim on every
sign-in (NumericDate per RFC 7519 §2, encoded with `ClaimValueTypes.Integer64`
so OpenIddict's `ValidateSignInDemand` accepts it as a typed Int64 instead of
rejecting a string-valued claim as malformed). The claim travels to both the
access token and the id_token. RPs that mandate `auth_time` (max-age handling,
step-up auth, prompt=login) now have the value they need.

The default `DynamicRegistrationAllowedScopes` allowlist is widened to include
the standard OIDC user-info scopes (`phone`, `address`, `groups`, `roles`).
These describe the user, not API privilege, and are already advertised in
`scopes_supported` — keeping them out of the DCR allowlist while advertising
them globally was an internal inconsistency. Admin scopes (`identity:*`, `scim`)
remain excluded by default.

A new probe demo `demo_claim_probes.ps1` walks a self-service auth-code+PKCE
flow with `scope=openid profile email phone address offline_access` and
**asserts** the resulting id_token claim shapes against the relevant specs:
`sub/iss/aud/exp/iat` (RFC 7519 baseline), `auth_time` (skew ≤ 5 min),
`amr` contains `pwd` (RFC 8176), `nonce` round-trips verbatim,
`azp` matches `client_id` when present (OIDC §2 — optional for single-aud),
`email`/`email_verified`, `phone_number`/`phone_number_verified`,
`address` as a JSON object with `formatted` (OIDC §5.1.1), and a custom
`dept` claim. The same surface is re-asserted via `/connect/userinfo`.

#### `redb.Identity.Core` — Per-client Pushed Authorization Requests enforcement (RFC 9126 §5)

Individual client registrations can now opt into mandatory PAR even when
the deployment does not require PAR globally. Dynamic Client Registration
(RFC 7591) accepts `require_pushed_authorization_requests=true` on the
client metadata; the flag is persisted on `ApplicationProps` and echoed
back in the registration response. When such a client makes a direct
`GET /connect/authorize` request without a `request_uri` issued by
`/connect/par`, the authorization-request handler rejects it with
`error=invalid_request` and an `error_description` pointing the developer
at `/connect/par`. The error is delivered through the validated
`redirect_uri` per RFC 6749 §4.1.2.1 (with `state` round-tripped), so the
client's existing OAuth error handling sees a normal, contract-compatible
error redirect — not a JSON 400 or a `/login` UI bounce.

Discovery now advertises the PAR endpoint URL itself
(`pushed_authorization_request_endpoint`) — OpenIddict's built-in
discovery handler emits the `*_auth_methods_supported` list for PAR but
not the URL. The companion `require_pushed_authorization_requests`
boolean is emitted only when the *global* enforcement is on; per-client
enforcement is a property of individual registrations and is not
advertised at the AS level. `demo_par_per_client.ps1` covers the full
contract: discovery exposes the URL → DCR with the flag echoes it back →
direct `/authorize` is rejected with `invalid_request` via redirect_uri
+ state → `/par` push + `/authorize?request_uri=…` is accepted (now
falls through to the normal `login_required` redirect).

**Why it matters.** PAR (RFC 9126) eliminates the classic OAuth
side-channels in the authorization request — the URL no longer carries
the request parameters past intermediaries (proxies, browser history,
referer headers, server logs, browser extensions), and the AS validates
the request before any redirect. FAPI 2.0 / financial-grade profiles
require it; high-assurance clients in mixed deployments need to enforce
it without forcing the global flag on every other client. Per-client
opt-in unblocks that pattern. The fix also closes a subtle integrity
gap: previously a client *could* advertise that it requires PAR (e.g. in
its own metadata), but the AS had no way to actually enforce it on a
per-client basis — so a misconfigured RP could quietly fall back to
plain `/authorize` without anything noticing.

#### `redb.Identity.Core` — `private_key_jwt` (RFC 7523) client authentication

Confidential clients can now authenticate to `/connect/token` and
`/connect/introspect` with a signed JWT-bearer assertion instead of a
shared `client_secret`. Dynamic Client Registration (RFC 7591) accepts
`token_endpoint_auth_method=private_key_jwt` together with an inline
`jwks` (JSON Web Key Set carrying the client's public keys). The JWKS is
persisted via the redb-backed application store and consulted by
OpenIddict's built-in client-assertion validator at request time —
verifying signature, `iss=sub=client_id`, `aud=<endpoint>`, and `exp`.

Discovery now advertises `token_endpoint_auth_signing_alg_values_supported`,
`introspection_endpoint_auth_signing_alg_values_supported`, and
`revocation_endpoint_auth_signing_alg_values_supported` per RFC 8414 §2,
listing the RSA / RSA-PSS / ECDSA algorithms accepted on the JWT-bearer
assertion. `demo_private_key_jwt.ps1` exercises DCR registration with
`jwks` → `client_credentials` token issuance under JWT-bearer auth →
introspection under JWT-bearer auth → tampered-signature negative path
(401 `invalid_client`); `demo_discovery_shape.ps1` now asserts that any
endpoint advertising `private_key_jwt` also advertises a matching
signing-alg list.

**Why it matters.** Shared `client_secret` is the weakest link in the
backchannel: a single leak (CI logs, repo, container snapshot) hands an
attacker the full client identity. With `private_key_jwt` the client only
ever exposes its public key on the wire — the private key never leaves
the client process — and short-lived (≤60s) audience-bound assertions
prevent replay across endpoints. This is the auth method that high-trust
deployments (regulated workloads, FAPI-style profiles, federated SSO
backends) require, and it brings the redb.Identity surface in line with
what discovery has been advertising on five endpoints since day one.

#### `redb.Identity.Core` — OIDC `sub` as a stable, opaque GUID

The public `sub` value emitted in ID tokens, access tokens, `userinfo`, and
introspection responses is now a `Guid` persisted on the user object's
`value_guid` slot. The GUID is generated once on user creation (registration,
admin bootstrap, federation provisioning, SCIM provisioning, dynamic client
registration's bootstrap admin path) and never changes for the lifetime of
the user — even if the row is renamed, re-keyed, or migrated across schemas.

**Why it matters.** Before this preview, `sub` was the bigint
`RedbObject._id`, which leaks insertion order, is reusable if a user is
hard-deleted, and changes shape across REDB instances. The GUID is opaque,
collision-free, portable across deployments, and decouples the externally
observable identity from the internal storage primary key. This is the
shape that downstream resource servers, third-party SDKs, and federated
RP relying parties expect, and it brings redb.Identity in line with the
OIDC Core 1.0 §5.7 guidance that `sub` should be a stable, locally-unique,
non-reassigned identifier within the issuer.

**Dual-emission for in-process consumers.** Every principal built by
`IdentityPrincipalBuilder`, `AttachSessionPrincipalHandler`, the password
flow, the authorization-code flow, the device flow, the verification flow,
and the federation flow now carries **two** identity claims:

| Claim | Type | Audience | Source |
|---|---|---|---|
| `sub` | `string` (GUID, lower-case, no braces) | Public — wire-visible to RPs and resource servers | `UserProps.value_guid` |
| `redb:user_id` | `string` (bigint) | Internal — never leaves the issuer; used by in-process modules that key off `_users._id` | `RedbObject._id` |

The internal claim is destination-restricted to the access token only and
is stripped from `id_token`, `userinfo`, and `introspect` responses by the
existing OpenIddict claim destinations machinery. Modules in the same
worker that resolve the user via `direct-vm://identity-userinfo` continue
to receive both claims.

**Store-side changes.** Subject linkage on the four OpenIddict store rows
moved from `RedbObject.Key` (bigint) to `RedbObject.value_guid` (Guid):

- `AuthorizationProps` — `value_guid` carries the public sub GUID. The
  `IOpenIddictAuthorizationManager.FindBySubjectAsync` lookup goes through
  `Query<AuthorizationProps>().WhereRedb(o => o.ValueGuid == subjectGuid)`,
  which is a single indexed scan on the REDB primary key column.
- `TokenProps` — same. `FindBySubjectAsync`, `RevokeTokensBySubjectAsync`,
  and the chained-revoke pass on authorization-code reuse all key off
  `value_guid` now.
- `ApplicationProps` and `ScopeProps` — unaffected on the subject axis,
  but their `Subject`-bearing referenced rows were swept consistently.

**`/me/*` and management.** Every self-service and admin route that took a
subject path parameter (`/me/profile`, `/me/sessions`, `/me/mfa`,
`/me/webauthn`, `/me/consents`, `/me/federated`, the SCIM endpoints, and
the admin user/token/authorization management) now treats the path as the
GUID sub. Internal lookups translate the GUID back to the bigint via a
single `WhereRedb(o => o.ValueGuid == subjectGuid)` query before issuing
any storage operation. The `RequireSelfOrAdminProcessor` IDOR guard
compares the GUID claim from the access token against the GUID in the
path — a bigint cannot be substituted to escalate.

**Migration path.** This is a breaking change only for callers that
compared `sub` against `_users._id` directly. In-process callers should
switch to the `redb:user_id` claim; external callers should treat `sub`
as opaque (which is the OIDC requirement). No data migration is required:
the `value_guid` slot is filled lazily on the first claim-issuing event
for each existing user, and both `sub` and `redb:user_id` are emitted
even before the lazy fill completes.

#### `redb.Identity.Core` — OpenIddict 6.3 pipeline on redb.Route exchanges

The full OpenIddict server pipeline runs on `IExchange` instead of
`HttpContext`. There is **no ASP.NET dependency** in the `Core` package —
not even an indirect one. Every endpoint a relying party touches
(`/connect/authorize`, `/connect/token`, `/connect/userinfo`,
`/connect/introspect`, `/connect/revoke`, `/.well-known/jwks`,
`/.well-known/openid-configuration`, `/connect/par`, `/connect/device`,
`/connect/verify`, `/connect/register`, `/connect/logout`,
`/connect/checksession`, `/connect/endsession`) is registered as a
`direct-vm://identity-*` route in Core, and the HTTP-facing path is the
HTTP facade rebinding into that route.

The full set of standards covered by the engine in this preview:

- **OIDC Core 1.0** — `authorize`, `token`, `userinfo`, ID Token issuance
  with all standard claim destinations, `prompt=none`, `max_age`,
  `id_token_hint`, `claims` request parameter, request objects (signed
  JWT request URIs).
- **OAuth 2.1 / RFC 6749** — authorization code (with PKCE required for
  public clients), client credentials, refresh token (with rotation and
  reuse detection), resource owner password (gated, off by default).
- **RFC 6750** — Bearer token usage, `WWW-Authenticate` shapes for the
  three error classes.
- **RFC 7591 / RFC 7592** — Dynamic Client Registration (DCR) and
  management — soft-deleted client recovery, mTLS / private_key_jwt /
  client_secret_basic / client_secret_post / none auth methods,
  registration access tokens, configurable bootstrap-admin gate.
- **RFC 7662** — Token introspection with both JWT and reference token
  resolvers. Active state is computed from the redb-backed status field
  with explicit revocation precedence.
- **RFC 8414** — Authorization-server metadata document, JWKS endpoint.
- **RFC 8628** — Device authorization grant — `device_code`,
  `user_code`, polling endpoint, verification endpoint, slow-down
  back-off.
- **RFC 8693** — Token exchange (subject token + actor token, scope
  narrowing).
- **RFC 9126** — Pushed Authorization Requests (PAR) — `request_uri`
  one-time redemption with TTL guard.
- **RFC 9449** — DPoP — proof validation on `/connect/token` and on the
  resource server side via the `redb.Identity.Resource.Dpop` package; jti
  replay cache backed by redb.
- **OIDC Backchannel Logout 1.0** + **RFC 8417 SET** — backchannel logout
  notification (signed `logout_token`) and the cluster-friendly
  revoked-SID broadcast surface (`/revoked-sids/add`, `/revoked-sids/since`)
  for replicas to converge without sticky sessions.

#### `redb.Identity.Core` — redb-backed OpenIddict stores

Every OpenIddict abstract store has a redb implementation backed by a
typed `*Props` object on a named REDB instance (default name: `"identity"`):

- `RedbApplicationStore` — `ApplicationProps` (client metadata, redirect
  URIs, post-logout URIs, secret hashes, JWKS URIs, settings JSON).
- `RedbAuthorizationStore` — `AuthorizationProps` (subject GUID,
  application id, type, status, scopes, properties).
- `RedbTokenStore` — `TokenProps` (subject GUID, type, status,
  authorization id, payload — opaque or self-contained, expiration,
  reference id hash). **Atomic single-use** semantics on
  `authorization_code` / `device_code` / `refresh_token` redemption are
  provided by optimistic-concurrency on `RedbObject.hash` inside
  `UpdateAsync` — exactly one concurrent redeem winner per code is
  guaranteed without an explicit lock.
- `RedbScopeStore` — `ScopeProps` (resources, descriptions, properties).

All four stores key off REDB primary fields (`value_guid`, `value_string`,
`value_long`) for indexed lookups; nothing falls back to in-memory
filtering at the application layer.

#### `redb.Identity.Core` — claim mappers, claim scopes, federation providers

A first-class admin surface for OIDC claim shaping:

- **Claim mappers** — pluggable rules that map source attributes (REDB
  user props, federation IdP claims, group memberships, custom JSON
  paths) to outgoing OIDC claims with destination scoping.
- **Claim scopes** — declarative association of claim mappers with one
  or more scopes; scope is granted only if the requesting client is
  permitted (`RestrictScopeByGroupMembershipHandler`).
- **Federation providers** — OIDC and GitHub external IdPs persisted as
  redb props rows, with admin CRUD over `direct-vm://identity-federation-*`
  and lazy user provisioning on first successful federated login.

#### `redb.Identity.Core` — sessions, MFA, recovery, native consent

- **Session principal store** — `AttachSessionPrincipalHandler` resolves
  the user's session from the auth cookie / opaque session id, attaches
  a fully-built principal to the OpenIddict transaction, and is the
  single source of truth for `prompt=none` decisions.
- **MFA** — TOTP (RFC 6238), SMS/Email OTP, WebAuthn (FIDO2 L2), and
  recovery codes; enrolment, verification, and removal flows surface
  through `/me/mfa` and `/me/webauthn`. MFA replay protection on the
  token endpoint is enforced via the same redb-backed `jti`/nonce
  cache used for DPoP.
- **Account self-service** — registration (with optional admin
  approval), e-mail verification, change-email confirm, password
  recovery, profile edit, session list / revoke individual / revoke all.
- **Native consent** — content-negotiated `/connect/authorize` returns a
  machine-readable `400 consent_required` JSON when the client sends
  the `X-Identity-Delegate-Consent: 1` header (used by
  `BackchannelOidcClient.RecordConsentGrantAsync` for native consent
  flows where there is no browser to render the host's HTML page).

#### `redb.Identity.Core.Module` — `.tpkg` host glue

`InitRoute` registers the engine on a named REDB instance
(default `"identity"`) so Identity state lives in its own props
namespace — fully isolated from other modules in the same Tsak worker.
Configuration is bound from `context.json` and exposes the OpenIddict
options (signing keys / encryption keys / token lifetimes / endpoints
toggle / DPoP requirement) as plain JSON.

#### `redb.Identity.Http` — full transport facade

Exposes every public OIDC endpoint over HTTP, plus the management
surface and the `/me/*` self-service surface, by binding HTTP routes to
the corresponding `direct-vm://identity-*` route. The facade is
**transport-only** — no Identity logic lives here, so removing the
package and using a different transport facade (gRPC, RabbitMQ,
SignalR) leaves all behaviour intact.

#### `redb.Identity.Web` — server-rendered host pages

The browser-touching pages required by the Authorization Code +
Device Code flows:

- `/login`, `/logout`
- `/consent` (the HTML form that `BackchannelOidcClient` and
  human-driven flows both POST to)
- `/account/register`, `/account/verify-email`, `/account/recover`,
  `/account/change-email-confirm`
- `/me/*` SPA-style pages backed by the `/me/*` JSON endpoints

All pages are plain Razor templates wired through redb.Route's HTML
view rendering — no MVC, no controllers.

#### `redb.Identity.Client` — SDK for relying parties and in-process modules

Two layered surfaces:

- **In-process** — strongly-typed wrappers over `direct-vm://identity-*`
  routes for callers in the same Tsak worker. Zero serialization, zero
  loopback, fully synchronous from the caller's perspective.
- **HTTP** — `BackchannelOidcClient` (PKCE, native consent, refresh
  rotation) for relying parties that talk to a remote redb.Identity
  deployment.

#### `redb.Identity.DataProtection` — standalone DPAPI-equivalent on REDB

A `Microsoft.AspNetCore.DataProtection` setup that runs **without**
ASP.NET — keys are persisted as redb props rows, signing and encryption
keys rotate on a schedule, and the key ring is shared across all
replicas of a Tsak cluster automatically because every replica reads
the same REDB instance.

#### `redb.Identity.Ldap` — LDAP / Active Directory federation

Directory-driven user sync handler (`LdapSyncHandler`) plus a
bind-on-login adapter that allows AD users to authenticate without
mirroring credentials into the redb user store. Group membership is
mapped to claim mappers, so AD groups can drive scope grants without
touching the Identity admin surface.

#### `redb.Identity.Resource.Dpop` — DPoP for downstream resource servers

A drop-in middleware for redb.Route resource pipelines that validates
incoming DPoP proofs against the access token's `cnf.jkt`, with a redb-
backed jti replay cache. Tied to the issuer's nonce policy via the
shared key ring.

### Performance

#### `redb.Identity.Core` — per-request cache on `FindByClientIdAsync` eliminates 8-11× duplicate lookups

OpenIddict's built-in handlers call `IOpenIddictApplicationManager.FindByClientIdAsync`
8-11 times per `/connect/token` request for the same `client_id` — each call
previously hit a fresh REDB props lookup (~8 ms each on the PVT join). Our own
code only resolves the application from 5 cold-path locations, so the duplication
is entirely inside the OpenIddict pipeline.

`RedbApplicationStore` now keeps a per-instance `Dictionary<string, RedbObject<ApplicationProps>?>`
keyed on `client_id`. Because the store is registered as `Scoped` (one instance per
HTTP request), the cache lives only for the lifetime of one OIDC pipeline invocation —
no TTL, no cross-request invalidation, no global state. `null` is cached too so repeated
lookups for unknown `client_id` values don't re-hit the database. `CreateAsync`,
`UpdateAsync`, and `DeleteAsync` keep the cache coherent for the rare case the same
request creates and then re-resolves a client.

Net effect on a steady-state `/connect/token` request: one DB round-trip for the
application row plus 7-10 cache hits, saving ~80 ms per token issuance.

#### `redb.Identity.Core` — per-request caches on `RedbTokenStore` and `RedbAuthorizationStore`

The same Scoped-store / per-request cache pattern that paid off so well on
`RedbApplicationStore` has been extended to the two other hot OpenIddict
stores. `[STORE-DIAG]` instrumentation on a `/connect/token` refresh-rotation
flow showed `IOpenIddictTokenStore.FindByIdAsync` being called twice for the
same token id (~8 ms per PVT join) and the matching authorization being
resolved at least once during issuance — duplicated work that the request-scoped
cache erases for free.

`RedbTokenStore` now keeps two coordinated dictionaries:

| Cache | Key | Filled by |
|---|---|---|
| `_idCache` | bigint object id | `CreateAsync`, `FindByIdAsync` MISS, `FindByReferenceIdAsync` MISS |
| `_refCache` | reference id (hash of refresh-token / authorization-code value) | `CreateAsync`, `FindByReferenceIdAsync` MISS, `FindByIdAsync` MISS when `value_string` is set |

Both caches are populated on each MISS so a subsequent lookup by either key
returns the same in-memory instance, and `DeleteAsync` removes from both to
keep the dictionaries coherent inside one request. `null` is cached too so
unknown ids/reference values cannot re-hit the database.

`RedbAuthorizationStore` adds a single `_idCache` keyed on bigint object id.
Authorization rows are resolved repeatedly during refresh-token rotation and
authorization-code redemption — the cache spares those redundant PVT joins.
`FindByApplicationIdAsync`, `FindBySubjectAsync`, and `FindAsync` are not
cached: they return enumerables and the result sets are not stable enough
across the few moments inside one request to justify the bookkeeping.

Measured on the acceptance demo suite (warm-start, local PostgreSQL, BCrypt
cost factor unchanged at 12):

| Demo                   | Before | After  |
|------------------------|-------:|-------:|
| `password_ropc`        | 4750 ms | 3790 ms |
| `refresh_rotation`     | ~4000 ms | 3596 ms |
| `me_sessions`          | ~4100 ms | 3576 ms |

The 19-demo full run completes in 40.4 s with all flows green. Worker logs
confirm the documented `Tok.FindById call#1 MISS … call#2 HIT` pattern, and
the existing `App.FindByClientId` HIT counters continue to fire 7-10 times
per token issuance — i.e. the new caches stack with the older one rather
than replacing it.

The diagnostic `[STORE-DIAG] …` logs ride along at `LogInformation` level
for one preview iteration so production deployments can validate cache hit
ratios on real traffic; they will be downgraded to `LogTrace` (or removed)
in the next preview once the win is confirmed in the wild.

#### `redb.Identity.Core` — ROPC principal fast-path skips a second user load

`HandleTokenRequestHandler.HandleAsync` for the password grant previously
called `IUserProfileService.BuildPrincipalAsync(userId, scopes)`, which
re-loaded the `IRedbUser` entity and the `UserProps` envelope from REDB
even though `LoginService.AuthenticateAsync` had just loaded both during
credential verification a few microseconds earlier. The handler now
forwards the already-loaded `User`, `OidcProps`, and `SubjectGuid` from
the `LoginResult` directly to the `BuildPrincipalAsync(user, props, sub, scopes)`
overload when they are present, falling back to the by-id load only for
legacy users whose `value_guid` slot has not been backfilled yet.

#### `redb.Identity.Core` — DCR collapses two writes + one read into a single persist

`DynamicRegistrationProcessor` previously called
`manager.CreateAsync(descriptor)` (write #1), then
`manager.FindByClientIdAsync(clientId)` (read), then mutated
`Props.RegistrationAccessTokenHash` and called `redb.SaveAsync(app)`
(write #2). The whole point of the second write was to attach a single
hashed RFC 7592 registration access token to a row that had just been
inserted — a wasted round-trip every time.

The processor now drives the manager pipeline manually:
`PopulateAsync(app, descriptor)` fills the in-memory entity from the
descriptor, the RAT hash is stamped onto `Props` before the row leaves
memory, and `manager.CreateAsync(app, secret, ct)` performs a single
persist that hashes the client secret and writes the application,
permissions, redirect URIs, and the RAT hash atomically. The
plaintext secret is pulled out of the descriptor before
`PopulateAsync` so the manager's "client secret hash cannot be set"
guard is not tripped — the dedicated `(application, secret, ct)`
overload owns the hashing.

Measured impact on the acceptance demo suite (warm-start DCR calls,
local PostgreSQL, BCrypt cost factor unchanged at 12):

| Demo                  | Before | After  |
|-----------------------|-------:|-------:|
| `dcr_lifecycle`       | 590 ms | 305 ms |
| `client_credentials`  | 591 ms | 237 ms |
| `authcode_pkce`       | 517 ms | 302 ms |
| `introspect_revoke`   | 545 ms | 446 ms |
| `me_profile`          | 288 ms | 276 ms |
| `mfa_totp`            | 250 ms | 196 ms |

30–60 % reduction with no change to security primitives: BCrypt cost
factor, JWE access-token encryption, RSA signing/encryption key
bootstrap, and the OpenIddict validation surface are all untouched.
The win is purely in collapsing redundant redb round-trips.

### Fixed

#### `redb.Identity.Core` — Authorization endpoint error redirect (RFC 6749 §4.1.2.1 / OIDC §3.1.2.6)

When `/connect/authorize` rejected a request from the `HandleAuthorizationRequest`
stage (e.g. `prompt=none` with no session → `login_required`, or
`consent_required` after consent tracking), OpenIddict's `Apply` handlers do not
fire, so `RedbRouteOpenIddictServerHandler` was emitting a JSON `400` error body
instead of the RFC-required `302` redirect back to the validated `redirect_uri`.
The HTTP facade then made it worse for `login_required` specifically by
overriding the response with a `302 → /login?returnUrl=...` to the interactive
login UI — silently violating OIDC §3.1.2.6, which forbids any UI for
`prompt=none`.

Two coordinated fixes:

1. `RedbRouteOpenIddictServerHandler.ProcessAsync`: when the request is rejected
   for the Authorization endpoint and we have a validated `redirect_uri` + a
   real HTTP method header, build the `302` redirect ourselves
   (`?error=…&error_description=…&state=…`, or `#…` for `response_mode=fragment`)
   instead of falling through to JSON.
2. `HandleAuthorizationRequestHandler` + `SessionCookieProcessors.RedirectToLogin`:
   the handler flags the exchange with `prompt_none = true` on the prompt=none
   reject path; the HTTP processor skips its `/login` UI override when that flag
   is set, so the natural error redirect to `redirect_uri` survives the facade.

New regression demo `demo_auth_extras.ps1` covers four previously-unprobed
authorization-response surfaces:

- RFC 9207 `iss` parameter present in `query` response Location
- `prompt=none` + no session → `error=login_required` at `redirect_uri`
- `response_mode=form_post` → 200 HTML auto-submit form with `code`
- `response_mode=fragment` → `Location` carries `#code=…&state=…&iss=…`

#### `redb.Identity.Core` — Discovery array fields no longer duplicated

`/.well-known/openid-configuration` was emitting `dpop_signing_alg_values_supported`
as 13 entries (`ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512,
ES256, ES384, PS256, RS256`) because OpenIddict's default discovery handler
appends its own short list AFTER our `ApplyDiscoveryResponseHandler` runs, and
`RemoveParameter` does not survive the late merge. `ApplyDiscoveryResponseHandler`
now dedupes every advertised string-array field (`dpop_signing_alg_values_supported`,
`scopes_supported`, `grant_types_supported`, `*_auth_methods_supported`,
`prompt_values_supported`, `response_modes_supported`, etc.) in the materialised
`Out.Body` immediately before `HandleRequest()`. New regression demo
`demo_discovery_shape.ps1` locks the shape: required RFC 8414 / OIDC Discovery
fields, no duplicates anywhere, DPoP algs restricted to RFC 9449 §5 catalog,
no placeholder/secret leaks.

#### `redb.Identity.Core` — Backchannel logout fan-out reaches RPs

Three bugs prevented `BackchannelLogoutDispatcher` from ever firing on
non-interactive flows (ROPC + refresh):

1. **Subject lookup queried wrong column.** `LogoutProcessor.CollectAffected
   ApplicationIdsAsync` was filtering authorizations and tokens by
   `Key == userId`, but the OpenIddict redb stores write the public GUID
   subject into `_objects.value_guid` (via `SetSubjectAsync`). Auths/tokens
   are now resolved by translating `userId → UserProps.value_guid` first,
   then querying `ValueGuid == subjectGuid`.
2. **Token-only flows were ignored.** ROPC and other non-interactive
   grants emit access/refresh tokens without creating an OpenIddict
   `Authorization` row, so the union missed every ROPC-only client. The
   collection now also unions `TokenProps.ApplicationObjectId` for
   non-revoked tokens.
3. **Dispatcher was resolved from the wrong DI container.** The processor
   was calling `exchange.ServiceProvider?.GetService<BackchannelLogout
   Dispatcher>()` — but the dispatcher is registered in the Identity
   *child* container, not the host SP that `exchange.ServiceProvider`
   exposes. It now resolves through `IRouteContext.GetIdentityServiceOr
   Default<>(exchange)` so per-exchange Identity scopes are honoured.

#### `redb.Identity.Core` — DCR + management API expose `backchannel_logout_uri`

RFC 7591 Dynamic Client Registration accepts the OIDC Back-Channel
Logout 1.0 client metadata fields (`backchannel_logout_uri`,
`backchannel_logout_session_required`) and persists them on the
registered application. `PopulateAsync` ignores
`descriptor.Properties[]` (those are OpenIddict's per-store custom
property bag, not redb `Props`), so the strongly-typed
`ApplicationProps.BackchannelLogoutUri` field is now written manually
after `PopulateAsync` in both `DynamicRegistrationProcessor` and
`ApplicationManagementProcessor`. New demo
`demo_backchannel_logout.ps1` covers the end-to-end flow: DCR a
confidential client with a backchannel URI, ROPC for tokens, POST
`/connect/logout` with `id_token_hint`, and assert that an
HttpListener captures the signed `logout_token` JWT carrying the
required `events`/`sub` claims.

#### `redb.Identity.Core` — DCR-registered clients use implicit consent

`DynamicRegistrationProcessor` was the only client-creation path setting
`ConsentType = Explicit`; every other path (`BootstrapAdminProcessor`,
`SeedWebClientHostedService`, `SeedBackchannelClientHostedService`) uses
`Implicit`. The mismatch broke headless authorization-code + PKCE flows:
`HandleAuthorizationRequestHandler` saw `Explicit` and 302-redirected
the caller to `/consent`, which a non-browser client cannot satisfy
without driving the consent submission form. DCR now defaults to
`Implicit`, matching the rest of the server's policy. Operators that
need an explicit consent screen for a specific DCR client can flip it
via the management API.

#### `redb.Identity.Http` — `/connect/revocation` is the canonical revoke path

The OAuth 2.0 token-revocation endpoint per RFC 7009 is mounted at
`/connect/revocation` (matching OpenIddict's discovery document). The
`demo_introspect_revoke.ps1` acceptance script was hitting the
non-existent `/connect/revoke` path on the refresh-token revoke step;
this was a demo bug, not a server bug, but it surfaced because the
acceptance suite drives both introspection and revocation back-to-back.
Demo updated to use the canonical path; the server side already
exposed only `/connect/revocation`.

#### `redb.Identity.Http` — federation public list precedence + binding

Two related fixes for the public read-only federation projection at
`/api/v1/identity/federation-providers/public`:

1. **Anonymous access.** `ManagementBearerAuthProcessor` was rejecting
   the request with `401 missing_token`. The path is now in the auth
   processor's `anonymousPathPrefixes` list — the public projection is
   unauthenticated by design (login pages call it before the user
   has a session). Sits next to the existing exemptions for the
   password-recovery and account-bootstrap flows and the SCIM
   discovery endpoints.
2. **Route precedence.** `ConfigurePublicFederationProvidersEndpoint`
   was registered AFTER `ConfigureManagementApi`, so the catch-all
   `/api/v1/identity/{**path}` matched first and dispatched the
   request to `FederationProvidersController.Get(id="public")` which
   then failed with `400 "Id is required"`. The exact-match route is
   now registered first.
3. **Cross-context mirror.** Tsak isolates context property buckets,
   so the HTTP facade (`identity.http` context) cannot read the
   `Identity:FederationProviders` list from `identity.core`'s context.
   `context.json` now mirrors the providers under
   `identity.http:IdentityTransport:FederationProviders`. The mirror
   omits `ClientSecret` — the HTTP-facade path only consumes
   `ClientId`/`Authority`/`Scopes` for the redirect surface.

Surfaced by the new `demo_federation.ps1` (RFC-shape probe: discovery
`federation_providers` array, public projection with explicit anti-leak
guards against `ClientSecret`/`Authority`/`Scopes`/`ClientId`,
cross-check between the two lists, then a `/connect/external-login`
302 verification with an absolute upstream `Location`).

#### `redb.Identity.Core` — token exchange wired into discovery + DCR

Two server-config nudges so the existing token-exchange code path is
actually reachable from a freshly-registered DCR client:

1. `Identity:Features:EnableTokenExchange` defaulted to `false`, which
   meant `urn:ietf:params:oauth:grant-type:token-exchange` was absent
   from the discovery document's `grant_types_supported` array even
   though the OpenIddict handlers were live. Default flipped to
   `true` in `context.json`.
2. The grant was missing from `DynamicRegistrationAllowedGrantTypes`,
   so any DCR-registered client requesting the grant got
   `400 "Grant type(s) not allowed: ..."` from the registration
   endpoint. Now allowed.

Surfaced by `demo_token_exchange.ps1`, which already exercised the
delegation (`subject_token` + `actor_token` → `act` claim) path and
just needed the server to admit the grant. Same demo's DCR
registration also now requests `client_credentials` (step 4 mints
the actor_token via that grant) and the `identity:read` scope.

#### `redb.Identity` — `demo_device_code_ci.ps1` for non-interactive RFC 8628 coverage

`demo_device_code.ps1` covers the happy path of the RFC 8628 device
authorization grant but requires a human to approve the device, so CI
could not run it. The new `demo_device_code_ci.ps1` is the
non-interactive companion: it DCR-registers a device-code client,
hits `POST /connect/deviceauthorization`, asserts the RFC 8628 §3.2
response shape (`device_code`, `user_code`, `verification_uri`,
`expires_in` required; `interval` and `verification_uri_complete`
soft-warn), and polls `/connect/token` once expecting
`error=authorization_pending` per §3.5. Wired into `run_all.ps1`
alongside the existing 21 demos for a 22/22 acceptance suite.

#### `redb.Identity.Core` — Per-request store cache coherency on bulk mutations

The per-request `_idCache` / `_refCache` introduced on `RedbTokenStore` and
`RedbAuthorizationStore` (perf entry above) served the documented
2× `FindByIdAsync` per `/connect/token` access pattern, but `RevokeAsync`,
`RevokeBy{Application,Authorization,Subject}IdAsync`, and `PruneAsync`
loaded targets through `Query<>()` (bypassing the cache), mutated and
saved them, but never refreshed the cache. A later `FindByIdAsync` in the
same request returned the pre-revoke/pre-prune snapshot, breaking both
the in-request "modify then read back" contract and the matching unit
tests (`Status` observed as `"valid"` after revoke; pruned tokens still
resolved).

Fix: the bulk-mutation paths now refresh the cache entries with the
just-saved instances immediately after `SaveAsync`, and the soft-delete
path evicts the ids from `_idCache` (token store also clears `_refCache`
wholesale because the prune doesn't carry the refId↔id mapping). The
matching `UpdateAsync_StaleHash` integration test was rewritten to use
two independent store instances so the per-request cache no longer
collapses the "two concurrent requests" copies into one shared reference.

#### `redb.Identity.Core` — Authorization endpoint open-redirect on rejected `redirect_uri`

When OpenIddict rejected `/connect/authorize` because the supplied
`redirect_uri` was unregistered, malformed, or otherwise unauthorized
(error documentation IDs `ID2043` / `ID2052` / `ID2095` / `ID2100`),
`RedbRouteOpenIddictServerHandler.ProcessAsync` still built a `302` to
the **attacker-supplied** request `redirect_uri` with the error on the
query string. RFC 6749 §3.1.2.4 / §4.1.2.1 forbid using a non-validated
`redirect_uri` as a redirect target — the response must be inline so
the browser never reaches the attacker URI with the framework's `state`
and `error` parameters attached.

Fix: the rejection path now inspects `context.ErrorUri` and skips the
redirect-to-`redirect_uri` block when any of the four `redirect_uri`-
specific OpenIddict error IDs is present, falling through to
`WriteResponseToExchange` so the error surfaces on the response body
instead. Covered by `RedirectUriValidationTests` with both unregistered
and registered-prefix-plus-query attacker shapes.

#### `redb.Identity.Core` — `prompt=login` / `max_age` no longer collapsed onto the `/login` interactive path

The interactive-`/login` redirect introduced for missing-session
`login_required` (Fixed entry above) treated **every** `login_required`
rejection as "redirect the browser to the local login page". That was
wrong for `prompt=login` and `max_age` staleness checks — the user is
already authenticated, so `/login` would auto-recognise the cookie and
loop back to the same authorize request. OIDC §3.1.2.1 / §3.1.2.6
require these "force re-auth" cases to surface `error=login_required`
on the validated `redirect_uri` so the RP can drive the re-auth flow
(clear its session, retry without `prompt=login`, etc).

`HandleAuthorizationRequestHandler` already flagged the exchange with
`force_login=true` on both branches; the fix is to lift that flag in
`RedbRouteOpenIddictServerHandler.ProcessAsync` and exclude it from the
`interactiveDeferred` condition. Only the genuine missing-session path
(no `prompt`, no `max_age` flag) still defers to `/login`; everything
else surfaces on the callback. `demo_prompt_max_age.ps1` (9 steps) is
the regression probe.

#### `redb.Identity.Core` — Captive `Scoped` store via root-SP fallback (`Bootstrap*` 409 cascade)

`IdentityRouteContextExtensions.GetIdentityService<T>(exchange)` falls
back to `IRouteContext.GetServiceProvider()` when no factory was
registered via `RegisterIdentityScopeFactory` (every test fixture that
constructs the route context with the host root SP directly hits this
path). The fallback returned the host root SP **as-is**. Resolving a
`Scoped` service (`IOpenIddictApplicationManager`) from a root SP
captures the underlying `Scoped` `IOpenIddictApplicationStore` =
`RedbApplicationStore` at root lifetime, which silently promotes it to
a process-wide singleton — its per-request `_clientIdCache` then
persists across every request. Cleanup code that opened its own
`CreateScope()` mutated a different store instance, so the captive
store kept serving the pre-cleanup snapshot. The
`BootstrapAdminEndpointTests` "first call → 201" cases consistently
saw `409 OIDC client '…' already exists` because the captive store
returned the ghost row id from a prior test's create.

Fix: when the fallback fires, build a per-exchange scope from the root
SP's own `IServiceScopeFactory` and cache it on the exchange (matching
the registered-factory path). Each request now gets its own fresh
`RedbApplicationStore` with an empty `_clientIdCache`, mutations stay
within the request, and there is no captive shadowing of DB state.
Verified — all 9 `BootstrapAdminEndpointTests` pass.

### Notes

#### Cluster + replica deployment

Three identical Tsak workers loading the same `.tpkg` set against the
same PostgreSQL **is** a production cluster — there is no service mesh,
no leader election service, no Redis. The DataProtection key ring and
the OpenIddict signing keys are shared through the redb object store;
cleanup timers (`PruneAuthorizations`, `PruneTokens`, `PruneRevokedSids`)
run **leader-only** via `RouteBuilder.Cluster(true)`, which uses
PostgreSQL advisory locks to elect exactly one runner per epoch.

#### Test posture

- 1783 xUnit tests cover the engine, every store, every claim handler,
  every `/me/*` route, every management route, the Http facade, the Ldap
  sync, the Dpop middleware, and the end-to-end OIDC flows against a
  real PostgreSQL via `ProductionBootstrapFixture` /
  `ProductionHttpFixture`. **All green on this preview.**
- Header-negotiation, native-consent happy path, atomic
  authorization-code single-use (including a 16-way concurrent replay
  test), refresh token rotation, DPoP nonce/jti replay, and the
  GUID-sub migration are each covered by dedicated test classes.
- Integration tests share fixtures via xUnit `[Collection]` markers
  and clean per-client OpenIddict authorization state in `IAsyncLifetime.InitializeAsync`
  to keep test ordering irrelevant.

### Pending — before `1.0.0` GA

- gRPC / RabbitMQ / AMQP / IBM MQ / SignalR transport facade `.tpkg`
  packages (the engine is transport-agnostic; only HTTP ships in this
  preview).
- Public NuGet packaging + signing pipeline.
- Security review pass on the cryptographic surfaces (DPoP, PAR
  request-object signature verification, signed logout tokens, key
  ring rotation policy).
- Public migration guide for relying parties moving off the bigint sub.
- Performance baseline: 99p latency targets for `token`, `authorize`,
  `introspect`, `userinfo` against PostgreSQL on commodity hardware.
