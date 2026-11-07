# redb.Identity changelog: 4.0.x

Releases of the 4.0 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.0.1] — 2026-09-18
### Security — the management surface no longer trusts a transport

The core management routes — `direct-vm://identity-manage-*`, `identity-manage-mfa`, `identity-me-*`,
`identity-scim-*`, `identity-revoked-sids` — never see a bearer token themselves. Each facade (HTTP,
gRPC, SOAP) validates it on the `identity-auth-management` hop, which leaves `identity:management-scopes`
and its siblings on the exchange, and forwards. The core routes carried no gate of their own: the
design assumed that whoever reaches `direct-vm` is one of our facades. `RequireSelfOrAdminProcessor`
(the B8 IDOR rule on `identity-manage-mfa`) wrote that assumption down and acted on it — an exchange
without a management context was admitted as an "internal trusted caller", on the reasoning that
`direct-vm` is not network-reachable.

That reasoning does not hold in a Tsak worker: the `direct-vm` registry is one per process and shared
by every module loaded into it. Any module could send to `identity-manage-users` and administer users,
or to `identity-manage-mfa` and reset anyone's MFA, with no token and no context — the routes ran the
business processor and answered. Nothing in the route DSL said so; the trust was inferred from the
absence of a property.

Every route on that surface now starts with `RequireManagementContextProcessor`: no
`identity:management-scopes` on the exchange, no idempotency lookup, no transaction, no business
processor — a generic 403 `not_authorized` (the same Problem Details every gate on the surface answers
with, so nothing about the target leaks) and a warning on the security log naming the route and the
operation. `RequireSelfOrAdminProcessor` refuses the same exchange too, so the rule holds even on a
route without the gate. There is deliberately no in-process bypass and no option to declare one: an
in-process module that needs the management surface obtains a context the way the facades do — a token
with the scopes it needs, validated on `identity-auth-management`. Trust is a property of the exchange,
established by that hop, never of the transport. `direct-vm` is a transport like the others.

The facades are unaffected: their exchanges already carry the context, and `Exchange.CreateChild`
copies it into the child exchanges the management controllers and SCIM bulk create. Tests that send to
the core routes directly now say which caller they play (`ManagementCaller.Admin` by default on the
fixtures — the fixture stands in for a facade that validated a bearer — and `ManagementCaller.None` to
probe the gate). `ManagementSurfaceGateTests` sends to every constant of the guarded surface without a
context and expects the 403; run against the previous code, the management routes answered 500 (the
business processor had already run and choked on the empty body), the self-service routes 401 from
their own caller check, `identity-manage-roles` and `identity-revoked-sids` answered as if nothing were
wrong, and `RequireSelfOrAdminProcessor` let the exchange through. All of that is now the one 403.

### Changed — the test gate runs all three test projects

The Identity gate used to be `redb.Identity.Tests` alone. The solution carries two more test projects,
`redb.Identity.Client.Tests` (the SDK) and `redb.Identity.Web.Tests` (the BFF), and nothing ran them:
that is how `RevokedSidsPollHostedServiceTests` stayed red from July, `DevTlsContractTests` from May,
and `UsersClientTests.SearchUsers_GETs_with_query` from June — the last one stale since the
non-paginated search moved onto the paginated endpoint (page size 200, `PagedResult` on the wire);
the test still stubbed a bare array and the old URL. Brought to the current contract.

`scripts/test-gate.ps1 -Provider sqlite|postgres|mssql` now runs the three projects and prints one
summary; the matrix is the three invocations in parallel, as before. Client and Web tests touch no
storage and add about three seconds. Documented commands updated; the BFF tests are now part of the
gate.

### Changed — Web component tests on bUnit 2

`redb.Identity.Web.Tests` pulled `AngleSharp` 1.2.0 through `bunit` 1.40.0, and every build flagged it
with `NU1902` for CVE-2026-54570 (mXSS in the HTML5 parser, patched in 1.5.0). Pinning a patched
AngleSharp directly does not work — 1.5.0 and 1.8.1 were both tried — because bunit 1.40 is compiled
against the 1.2 API and fails at runtime with `MissingMethodException` (`IHtmlCollection.get_Item`).

The test project now uses bunit 2.11.3, which depends on AngleSharp 1.8.1; the warning is gone without
any pin. The migration touched one file, `Phase3ComponentTests` (seven tests): the base class is
`BunitContext`, components render through `Render<T>()`, and the interaction helpers take
`IRenderedComponent<TComponent>` in place of the removed `IRenderedFragment`. Queries and event
dispatch (`FindAll`, `Change`, `Input`, `Click`, `Markup`) carried over unchanged, and every assertion
is the same — the tests that check the exact request a form sends (`Owner == "application:5"`,
blank optionals as `null`) pass only if the events really reach the components. Test-only change;
`redb.Identity.Web.Tests` 54/54.

### Changed — Identity.Web on the ASP.NET packages of its own framework

`redb.Identity.Web` targets `net10.0` but pinned `Microsoft.AspNetCore.Authentication.OpenIdConnect`,
`…Authentication.JwtBearer` and `…Components.Authorization` at 9.0.0 — packages of the previous major
on a 10.0 application. Nothing failed, but those three were the whole reason the BFF resolved
`Microsoft.IdentityModel` 8.0.1 while the rest of Identity and the Tsak worker run 8.16.0.
The two authentication packages now follow the TFM (`Microsoft.AspNetCore.Mvc.Testing`
in `redb.Identity.Web.Tests` likewise); `Components.Authorization` is not raised but dropped — the SDK
reports it framework-provided (`NU1510`), so the reference only ever added a version to argue about.
The two IdentityModel roots the handlers actually use —
`Microsoft.IdentityModel.Protocols.OpenIdConnect` and `System.IdentityModel.Tokens.Jwt` — are pinned
at 8.16.0 the way `redb.Identity.Http` pins its own. One IdentityModel version across Identity. The BFF
is a separate process, so this is hygiene rather than a runtime fix — but the code that validates the
OP's tokens in the BFF now runs on the same library revision as the OP that issues them.

The patch is 10.0.9, not the current 10.0.12, and that is a choice: from 10.0.10 the authentication
packages require `Microsoft.IdentityModel` ≥ 8.19.2, so on 10.0.12 a pin at 8.16.0 is a downgrade
(`NU1605`) and the ecosystem would split again — Web on 8.19.2, everything else on 8.16.0. 10.0.9 is
the newest patch that still ships against 8.0.1, where 8.16.0 is an upgrade. Checked before choosing:
the IdentityModel notes for 8.17–8.19.2 and the ASP.NET Core 10.0.10–10.0.12 releases carry no CVE for
the authentication handlers; Microsoft's bump was a routine dependency refresh. The pin has a shelf
life — the next ASP.NET patch Web takes will demand ≥ 8.19.2 — and moving the whole ecosystem to
8.19.2 is the planned follow-up, host first, then Identity.

`Microsoft.AspNetCore.DataProtection` 9.0.4 in Core, Http and DataProtection stays: on `net10.0` it
resolves to the shared framework's assembly — nothing of that version is copied into the module bin or
the `.tpkg` — so the pin only steers the `net8.0` / `net9.0` targets of the libraries and no
9.0.4 assembly reaches the worker.

Running `redb.Identity.Web.Tests` for this change found `RevokedSidsPollHostedServiceTests` red since
2026-07-12, when a change made the poll exit before its bootstrap call when no
`Identity:BackchannelClient:ClientSecret` is configured — intentional: the poll is a cluster feature
behind a service-account secret — but the tests built their options without one, so the service never
called and the first test has failed on every run since. The second test could not fail at all: with
no poll there was no exception to swallow, and every assertion still held. Nobody noticed because
these tests are not part of the gate. The tests now configure the secret, wait for the poll to have
been attempted (bounded at five seconds, in place of a fixed 50 ms that only ever worked by timing),
and the swallow test asserts the poll actually ran. A third test pins the intentional behaviour:
without the secret the service makes no call at all.

The same run showed `DevTlsContractTests` red: `appsettings.Development.json` carried
`"RequireHttpsMetadata": false`, which the contract test forbids in committed configuration because it
switches off the https requirement for the OIDC discovery document. The flag was a leftover of the
`http://localhost:5002` dev loop; a later change moved the dev authority to `https://host.docker.internal`
and made the `false` unnecessary — the certificate side of that loop is handled by
`AcceptAnyBackchannelCert`, a separate and explicitly dev-only switch, not by this flag. The
development config now says `true`; the dev loop is unchanged.

The shipped `appsettings.json` had the same `false`, and that one is not a dev
convenience — it is the default of every deployment, overriding the code default of `true` for anyone
who does not set the key themselves. It now says `true`, and `DevTlsContractTests` gained a test on the
shipped file so the two configs cannot drift apart again. A deployment that really
talks to an `http://` authority sets `false` explicitly for itself; the default no longer does it for
everyone.

### Security — a DPoP proof can no longer be consumed twice at once

`RedbDpopReplayStore` decided replays by lookup-then-insert, and nothing on the row was unique.
Two presentations of the same proof racing past the lookup both inserted and both were told
"reserved" — RFC 9449 §11.1 asks for at most once, and the store delivered it only when the
presentations were far enough apart. The move to `ExecuteAtomicAsync` changed nothing
here, and the class comment promising that "the database row uniqueness constraint prevents both
inserts" described a constraint that did not exist.

The reservation now carries `ValueUnique = SHA-256(jkt|jti)` — the derivation the idempotency record
already uses, because `jti` is client-chosen and unbounded while `ValueUnique`
is capped at 440 characters. The index decides: the loser of a race gets
`RedbUniqueViolationException` and is refused as a replay. The lookup stays as the fast path, so an
already-consumed proof is refused without a failing statement, and an expired reservation is
refreshed in place rather than inserted a second time — a second insert would hit the key and
misreport a stale row as a replay. The core runs the insert under a savepoint, so a violation inside
the transacted token route leaves the route's transaction intact. Rows written before the key existed
carry none; the lookup still finds them and the cleanup timer removes them within one TTL.

Pinned by `DpopReplayStoreAtomicityTests` on all three providers: sixteen simultaneous presentations
reserve exactly once and leave exactly one row, the plain second presentation is refused, and an
expired reservation is taken again without a duplicate row. Run first against the old store, the same
tests showed how wide the gap was: all sixteen presentations were accepted, not one or two — under
concurrency the lookup protected nothing — and the expired path left two rows behind.

### Changed — the deletion helper's dead `batchSize` is gone

`IdentityDeletionHelper.DeleteAsync` kept an `int batchSize` on all four overloads after the helper
stopped handing the batch to the background service; it was accepted and ignored.
Removed, together with the seven call sites that passed one. Purge batching is the background
service's own concern; the cleanup processors keep their page sizes for the `Take(...)` that selects
what to delete.

Comments in two stores and two other places that still described the route transaction as
`BeginRedbTransaction` were brought up to date. The `CS0618` warnings about that method in the
Identity solution build come from `redb.Route.Core/Xml/RedbXmlContributions.cs`, which is compiled
as a project reference — Identity itself no longer refers to it.

### Fixed — audit tests no longer race the provider matrix

The full gate starts the sqlite, postgres and mssql suites as three processes against one machine
and one set of brokers, staggered by seconds rather than isolated. Two audit suites were written as
if they owned the box, and they only stayed green while the timing held.

`AuditIbmMqIntegrationTests` published to the same `DEV.QUEUE.3` from all three processes and then
took whichever message arrived first. Both halves of that race show up in the full-run logs: a run
receives a sibling's message (`Expected eventType to be "TestWmqFields", but "TestWmqDirect"`), and
the sibling, whose message was eaten, waits out its 15-second timeout. The per-test drain cannot help
— it runs before the sibling publishes — and the eventType cannot tell the processes apart, because
all three publish the same types. Each provider now gets a queue of its own (`DEV.QUEUE.1/2/3`,
pre-created by the developer image), and within a process the receive accepts only its own eventType,
so a late message from the previous test is skipped rather than mistaken for this test's event.
Skipped messages are reported on stderr instead of vanishing quietly.

`AuditCompletenessFullCycleTests` waited a flat two seconds and then queried the audit catalog once.
The query helper looked like a retry loop but was not one for this purpose: it polled only while the
response was unsuccessful and returned an empty list the moment the endpoint answered 200 with no
rows — which is the normal first answer, since the row is written by a WireTap branch that finishes
after the response the caller already has. Under three concurrent suites two seconds stopped being
enough. The helper now polls until the row appears, on the same ceiling, and reports how long it
waited: on success, the attempt and elapsed time when the row was late; on failure, that nothing
arrived after ten attempts. A future failure therefore says whether audit is slow or absent instead
of leaving that to be guessed.

Neither change touches the product, and neither weakens an assertion: with the emission broken, both
suites still fail. That was checked the other way round as well — with the eventType filter removed
and foreign messages arriving during the receive window, the MQ test fails exactly as the gate logs
show it failing.

### Fixed — a database outage no longer retries forever

The `DbException` handler declared `MaximumRedeliveries(3)` next to
`RetryWhile(e => !IsUniqueViolation(...))`, and those two do not add up the way the pairing suggests:
`RetryWhile` does not narrow the ceiling, it **replaces** it. `OnExceptionProcessor` evaluates the
predicate *instead of* the attempt count, inside a loop with no outer bound. A predicate that only asks
"is this not a unique violation?" answers yes to every ordinary connection error, so a real outage was
retried without end — and because the delay doubles each round (200 ms, 400, 800…), the route stopped
answering altogether rather than returning the 503 it was supposed to return.

The predicate now carries the bound itself: it retries while the error is not a unique violation **and**
`CamelRedeliveryCounter` is below the limit. Both the ceiling and the predicate read one constant, so
they cannot drift apart. `MaximumRedeliveries` stays as the documented policy and as the bound that
applies if the predicate is ever removed.

The defect was invisible until redb.Route started passing the full handler configuration through (redb.Route
4.0.1): before it, `RetryWhile` never reached the processor and the count
check ran. So Route did not break this — it stopped hiding it. Pinned all along by
`ErrorHandlingPipelineTests.TransientDbErrors_AreRetried_ButABoundedNumberOfTimes`, which is exactly the
test that hung on all three providers.

### Changed — SQL audit targets take `:#name` parameters

The `sql:` connector now writes parameters the Camel way, `:#name`, and no longer reads `@name` as one:
`@` reaches the database untouched, because it collides with T-SQL and MySQL variables (redb.Route
4.0.1). There is no transition period — an audit target still carrying the old syntax stops
writing rows and fails with a database error instead.

Operators with a `sql:` audit target must update its `Uri`: `VALUES(@event_id, …)` becomes
`VALUES(:#event_id, …)`. The `param.*` bindings are untouched and casts still work (`:#details::jsonb`).
Identity's own relational audit sink does not go through the connector, so only operator-configured
`sql:` targets are affected; the suite's target and the sample in the test `appsettings.json` were
updated here.

### Changed — route transactions now ride the ambient scope

`WithRedbTx` used to pair `.Transacted(TransactionPolicy.Suppress)` with `BeginRedbTransaction(name)`:
the wrapper supplied the commit/rollback boundary while the redb transaction was opened explicitly,
because the core rejected an explicit transaction whenever an ambient scope was active. redb
4.0.1 inverted that — redb enlists into the ambient `TransactionScope` through its
`AmbientConnectionRegistry` — and `BeginRedbTransaction` is now `[Obsolete]`. Identity's wrapper is
plain `.Transacted(...)`, and the scope owns commit and rollback.

This changes what a processor may do inside a transacted route: `redb.Context.BeginTransactionAsync()`
throws there, and the core points at `ExecuteAtomicAsync`, which joins the ambient transaction instead.
`RedbDpopReplayStore` is the one place where that actually bit — DPoP replay reservation runs on the
token route, which is transacted — and it now uses `ExecuteAtomicAsync`. Its old mid-logic
`RollbackAsync` was wrong under an ambient scope for a second reason: a replayed proof must fail the
request, not undo everything the route did before it.

The scope timeout is stated explicitly (2 minutes) rather than inherited: this scope spans Argon2id
plus the whole OpenIddict pipeline on the token route, and the framework default of 30 seconds sits
uncomfortably close to that under load.

Eleven other call sites still open their own transaction (`MfaVerifyProcessor`, `MfaRecoveryProcessor`,
both WebAuthn processors and six token stores). None of them sits on a transacted route today, so none
of them breaks — but any route that gains `WithRedbTx` later will break them at runtime with a green
build. They are listed here rather than migrated silently.

Worth knowing about the test suite: no fixture configures `RedbInstanceName`, and without it
`WithRedbTx` returns the route unwrapped. Route transactions are therefore inert under test and live
only in a real deployment, where `context.json` sets the name — so this change was verified against a
running instance, not by the suite.

### Fixed — a deletion inside a route transaction no longer runs on a second connection

Every Identity deletion goes through `IdentityDeletionHelper`, and it handed the mark to
`IBackgroundDeletionService.DeleteAsync`. That method opens a DI scope of its own — a second
connection — and marks there. Under a route-level transaction (`WithRedbTx`, live whenever
`RedbInstanceName` is configured, which is every Tsak-hosted deployment) the two connections fight
over the same rows: on SQLite the mark waits on the writer lock the route holds and dies on the busy
timeout, about 35 seconds later; on PostgreSQL and MSSQL it either blocks on rows the route has
already written, or commits on its own — so a route that failed after the delete rolled back
everything **except** the deletion. Reached through manage-scopes, manage-users, manage-tokens,
manage-groups, manage-claim-mappers, manage-claim-scopes, manage-federation-providers, scim-users
and scim-groups.

The mark now runs on the caller's `IRedbService` and joins whatever transaction it is in
(`SoftDeleteAsync` goes through the core's `ExecuteAtomicAsync`). Nothing is handed to the
background service and nothing needs to be: it polls for trash containers and finds the one written
above by itself — its `EnqueuePurge` has been a no-op ever since the polling loop replaced the
channel, and the `batchSize` it was passed never reached the mark either. When no background service
is registered the warning stays: objects are marked and hidden from queries, but no physical purge
will run.

Pinned by `DeletionHelperTransactionTests` on all three providers: the mark rolls back with the
caller's transaction, commits with it, and still works with no ambient transaction at all. Proven
red on the unfixed code — 35 s per test on SQLite (the writer-lock timeout), a surviving trash row on
PostgreSQL. The cleanup tests that asserted the old path were rewritten rather than deleted, and
their `DidNotReceive` assertions moved onto `SoftDeleteAsync`: the background service is now never
called, so an assertion on it would have passed even if an object had been deleted.

Requires redb 4.0.1 or later (the trash-lock fix); the PostgreSQL and MSSQL modules it carries are
applied at startup.

### Changed — Microsoft.IdentityModel 8.16.0

`redb.Identity.Core` pins `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.16.0 (was 8.4.0), and
`redb.Identity.Http` references `Microsoft.IdentityModel.Abstractions`, `Logging` and `Tokens` 8.16.0 directly
(OpenIddict.Abstractions 6.3.0 alone resolves 8.4.0). `Microsoft.Data.SqlClient` 7.0.3, which `redb.MSSql`
ships, needs 8.16.0, and the Tsak worker pins it, so the Identity packages and the host they run in ship one
version. No code change.

## [4.0.0] — 2026-09-12

### Security — reserved header strip extended to the gRPC and SOAP facades

The 2026-09-09 fix removed the internal-only header names a caller must never supply on every HTTP
route. The gRPC connector copies caller metadata and envelope headers into the exchange the same
way, and the WS-Trust listener is HTTP underneath — neither facade stripped anything, and both reach
the audited `Token` / `Introspect` / `Revoke` routes, so a gRPC or SOAP caller could still sign the
audit log with another user's id, a fabricated address and agent, or a foreign `client_id` by sending
them as metadata or request headers. (The session names were harmless there only because those
transports never reach the authorize, logout or consent routes.) The list now lives once in
`IdentityReservedInboundHeaders` (Contracts) and every facade strips it as its first step.
`operation` is HTTP-only: on the gRPC envelope route the caller names the operation by design.

Audited in the same pass and found sound: `/me/*` and the management API carry the caller's
identity in exchange properties (`identity:management-*`), which no transport fills from the wire;
SCIM filters are parsed into a typed criteria object with whitelisted attributes and operators.

### Fixed — audit attribution: client_id for form-authenticated clients, timestamps on SQLite

`MapHttpToIdentityHeaders` documented two sources for the `client_id` / `client_secret` headers —
Basic authentication and the form body — but implemented only the first. Token issuance never
noticed (OpenIddict reads client credentials from the body itself), the audit envelope did:
`EventDispatchProcessor` attributes events by the `client_id` header, so every client authenticating
with form credentials — public PKCE clients included — was audited with `client_id` NULL. The form
step now exists (Basic wins when both are present; the body is parsed, not replaced).

The SQLite audit table declared `timestamp TEXT` and expected an RFC 3339 string, while the redb
SQLite provider encodes every `DateTimeOffset` parameter as a Julian day number: the number landed
in the TEXT column as text, the query layer failed to parse it back (every row read as
`0001-01-01`), and `from`/`to` filters compared text to a number. The column is `REAL` now, matching
the provider's `_date_*` convention. No migration is shipped: SQLite has no conditional DDL and the
table is created per file — drop existing SQLite audit files (or the table) before upgrading.

### Security — an HTTP header could impersonate any user, and the consent page trusted its own URL

Two findings from the 2026-09-09 facade audit, both fixed.

**Session identity was trusted from a request header.** The HTTP consumer copies every request
header into the exchange verbatim, and Identity carried the logged-in user between processors in
those same headers (`session_user_id`, set from the decrypted session cookie by `ReadSessionCookie`,
which returned without clearing anything when no cookie was present). `AttachSessionPrincipalHandler`
then read `session_user_id` and built the principal from it. So `GET /connect/authorize?...` with a
header `session_user_id: <victim>` — no cookie, no password — minted an authorization code for that
user; the same header forged consent and logged other users out. A `StripReservedInboundHeaders` pass
now runs first on every HTTP route (from `PropagateCorrelationId`, so no route can forget it) and
removes the internal-only names a client must never supply — `session_*`, `reauth_marked_sid`,
`client_id`, `client_secret`, `access_token`, `operation`, and the audit trio `user_id`,
`ip_address`, `user_agent` — leaving only the trusted processors (cookie, `Authorization` header,
Basic/body, request path) to populate them. In-process `direct-vm` callers are unaffected: the strip
is at the HTTP edge, which is the untrusted boundary.

The audit trio deserves its own sentence. `EventDispatchProcessor` reads `user_id`, `ip_address` and
`user_agent` from the WireTap copy of the business exchange — the same headers — and nothing trusted
ever set the latter two, so the security log's address and agent columns were either empty or
whatever the client typed into a header, and its user column could be pointed at someone else. For
HTTP-originated events the dispatcher now falls back to the transport-owned, proxy-sanitized
`redbHttp.RemoteAddress` and the real `User-Agent`, and the user id comes from the event payload.

**The consent page rendered from its own query string.** `GET /consent` showed `app_name` and
`scopes` taken directly from the URL, so a link like
`/consent?client_id=attacker&app_name=Your%20Bank&scopes=…` displayed the operator's own trusted
consent UI attributing an attacker's client to a familiar name — a click on Allow then granted the
attacker's client. The page now renders only from a server-signed **consent ticket** (`?ct=…`) minted
by the authorization server once it has decided consent is required; app name and scopes come from the
ticket, and the grant requires the ticket to have been issued for the current session's user (it
cannot be replayed under another session). The console's BFF, which renders its own consent screen and
posts with the session cookie, keeps working on the ticket-less, session-bound path.

### Security — the HTTP facade's consent form could be submitted for any user by anyone

The facade renders its own login, consent and MFA pages for deployments without the web console.
Its consent POST read the consenting user from a hidden `user_id` form field and only fell back to
the session cookie when the field was absent, while `ReadSessionCookie` let a request without any
cookie continue down the pipeline. Together that meant an anonymous cross-site POST to `/consent`
with `client_id`, `user_id` and `decision=allow` recorded a permanent authorization for the named
user — no session, no click, no frame: the consent screen the victim would have seen for that client
was silently pre-approved (and `decision=deny` revoked someone else's grant the same way).

The user now comes from the session cookie only. Without a session the POST is refused with 401
before anything downstream runs; the form and the redirect to `/consent` carry no `user_id` anymore.

Two further gaps closed in the same pass. The facade pages set none of the browser-protection
headers the web console has always sent, so login, consent and MFA could be embedded in a frame
(clickjacking on the consent "Allow" button); every response through the facade's serializer now
carries `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy`. And the form POSTs (`/login`, `/consent`,
`/mfa`, `/mfa/recovery`) had no cross-site request check: they now refuse a request whose `Origin`
(or, failing that, `Referer`) names another site, or is the opaque `null`, with 403 before reading the
body. A request carrying neither header is let through on purpose — that is the shape of the web
console's BFF (`RecordConsentGrantAsync`), the demo scripts and API clients, none of which a foreign
page can drive; browsers always announce the origin of a cross-site form. The session cookie's
`SameSite=Lax` default and the frame headers are the other two layers of the same defence.

### Added — access tokens carry an RFC 9068 audience, and the management API checks it

Issued access tokens matched the JWT profile for OAuth 2.0 access tokens (RFC 9068) in every
respect but one: they had no `aud`. The scope store already served `ScopeProps.Resources` and the
admin API let an operator set them, but no sign-in handler ever attached those resources to the
principal, so the claim the profile marks REQUIRED never appeared, and the local validation stack
never asked for one — any token our server signed was welcome at the management API regardless of
what it had been minted for.

`AttachAccessTokenResources` now composes the resource indicators at sign-in: the `Resources` of
the granted scopes, joined by the application's new `AccessTokenAudiences` (the access-token twin of
`IdTokenAudiences`, exposed on the application contracts and the Protocol tab of the console). The
server's own audience joins whenever an `identity:*` scope is granted — those scopes are the
server's own API — and stands alone as the §3 default resource indicator when nothing else names a
resource. It is `{issuer}/resources` unless `RedbIdentityOptions.DefaultAccessTokenAudience` says
otherwise. The requesting client's own `client_id` is always an audience as well (as with WSO2,
Keycloak and Entra self-scoped tokens): once a token carries audiences OpenIddict admits only
audience members to `/connect/introspect` and no longer falls back to the presenter, so without it a
client could no longer introspect the tokens it holds. The validation stack behind the management API
now requires the server's own audience (§4): a token minted for an external API only is refused with
401, not merely 403 for a missing scope.

Deployments that had set `Resources` on a scope will see those values steer `aud` for the first
time; a client granted such a scope without any `identity:*` scope gets a token for that API alone
and can no longer call the management API with it — which is what the resource assignment meant.

Introspection changes with it. Until now no access token carried `aud`, so OpenIddict skipped its
audience check at `/connect/introspect` and **any authenticated client could introspect any token** —
an oracle that let one client confirm validity and read the claims of tokens issued to another. With
`aud` present, OpenIddict admits only audience members (RFC 7662). A client introspecting its own
tokens is unaffected (its `client_id` is always an audience). A backend that introspects tokens issued
to *another* client — the classic SPA + BFF pair — must now be declared an audience of them: put the
backend's `client_id` into the SPA application's `AccessTokenAudiences`, or into the `Resources` of the
scopes it serves. The integration fixture does exactly that for its public/confidential pair.

### Fixed — the admin web console could not reach the identity server it sits next to

`redb.Identity.Web` was configured with `http://localhost:5002` while the HTTP facade serves TLS on
that port, so every backchannel call died with "The response ended prematurely" — discovery, login,
federation providers, the revoked-SIDs poll. And the scheme alone would not have been enough: the
server's issuer is `https://host.docker.internal:5002` (named so that the OpenID conformance suite,
which runs in Docker, can reach the host and match `iss` against the address it called), and an OIDC
client's authority must equal the issuer. The console now uses the issuer's own name — which Docker
Desktop also maps in the host's `hosts` file, so it resolves from the console too — plus
`AcceptAnyBackchannelCert` in the Development profile for the bundled self-signed certificate.

### Fixed — `demo_scim` no longer reports PASS while skipping its own body

The demo asked dynamic registration for `identity:admin`, which DCR deliberately never grants, then
aimed at the management mount (`/api/v1/identity/scim/v2`) that refuses DCR-obtainable tokens. Having
failed to get a token it skipped the entire CRUD body and exited 0 — green in every suite summary,
including nights when SCIM writes were actually broken. It now registers with the granular `scim`
scope, uses the `/scim/v2` mount like the other SCIM demos, runs all thirteen steps, and treats a
missing token as a loud failure instead of a shrug.

### Changed — the contracts now ride in a carrier package of their own, and reloading one module can no longer fork them

`redb.Identity.Contracts.dll` used to ship inside `Core.Module.tpkg`. A package's hot-reload
force-replaces its own companion assemblies in the worker's tracker, so reloading the core alone handed
the new core a new `Contracts` instance while every facade kept the old one — the same CLR type in two
copies, and a typed body crossing `direct-vm://` quietly became `null` on the other side: register and
SCIM writes answered "Request body is required" with nothing in the log (Tsak F-12).

The new `redb.Identity.Contracts.tpkg` is an empty module whose payload is its companion: the one
process-wide instance of the DTO assembly. Every other Identity package excludes it and declares the
dependency, so the loader's topological sort brings the carrier up first. Reloading core or any facade
now leaves the contracts untouched — verified live: after a core-only hot-reload, with no facade
touched, register answers 200 and SCIM create 201, the exact calls that used to break.

The deployment rule this makes explicit: redeploy the carrier only when the contracts change, and then
redeploy every Identity module after it — which a contract change requires in any architecture.


### Fixed — the upgrade-on-login rehash could silently undo a password change that landed after the login

The C12 upgrade-on-login rehash runs detached, about a second after the login that scheduled it:
Argon2id is slow by design, `Task.Run` adds scheduling, the fresh DI scope adds a connection. An admin
password reset fits into that window comfortably — and when the rehash landed last, it wrote the
**pre-login** password over the freshly set one. The account silently reverted to exactly the
credential the operator had just tried to retire, while the reset call had already answered
`success: true`.

Measured on a live worker before the fix: nine resets out of nine lost when a login preceded them,
three of three kept without one; every lost row still held the old hash in `_users`. Not
provider-specific and not redb.Core's doing — pure timing inside `LoginService`, on any database.

The rehash is now awaited on the login path, which removes the detached writer altogether: the login
answers only after the rehash is on disk, so a later reset writes last and wins by construction. A
check-before-write guard alone proved insufficient live — the ~250 ms of hashing sits between the
check and the write, and the reset lands inside it. The guard stays as a second layer against other
concurrent changers, and the attempt is capped to once per user per process, because the upgrade does
not currently converge: the write goes through the core provider's own hasher (BCrypt), so the
"upgraded" hash is BCrypt again and `NeedsRehash` stays true forever. Convergence needs a redb.Core
API for handing over a ready-made hash — reported, not worked around. Pinned by
`LoginRehashRaceTests`, red on the unguarded code; the second test holds the other half — an
untouched hash must still be upgraded.

The awaited rehash also goes through the request-scoped service rather than a fresh DI scope: the
fresh scope existed only because fire-and-forget outlived the request, and once awaited it just meant
a second connection — which on SQLite promptly answered `database is locked` against the login's own.
Same connection: no second writer, and inside a transacted route the rehash joins that transaction.


### Fixed — the identity core could not start in a Tsak worker, and three defects hid behind it

Deploying all four modules to a live worker surfaced what the test suite could not, because each defect
needed the real hosting model to appear at all.

**The core did not start.** `IdentitySchemaInitListener` synchronises every Identity Props type by
reflection, because the type is only known at runtime. When `ISchemeSyncProvider.SyncSchemeAsync<T>`
gained its `CancellationToken`, that call site kept compiling without a word and threw
`TargetParameterCountException` on the first type at startup. The loop then never ran, **no scheme was
synchronised at all**, and every listener behind it failed with `Scheme for type 'X' not found` —
`RoleProps`, `ScopeProps`, `DataProtectionKeyProps`, `SigningKeyProps`, `ApplicationProps`. One line
produced a dozen unrelated-looking symptoms, and `identity.core` and `identity.http` both refused to
come up. The arity is now checked once, up front, with a message naming what actually broke.

**The WS-Trust facade served no WSDL.** Tsak loads a module's assembly straight from its `.tpkg` with
`LoadFromStream`, so the assembly never lands on disk and `Assembly.Location` is empty: a file resolved
next to the assembly could not be found because there is no "next to". The facade therefore registered
`POST` only and answered `405` to the `GET` a client generator makes first — the one thing this facade
exists to serve. The contract is now an embedded resource, with the loose file still read when present.
`pack-tpkg.ps1` also ships content subdirectories, which it previously dropped.

**`Validate` on a revoked token blamed the caller.** OpenIddict reports a revoked token as an error
rather than RFC 7662's `active: false`, and the facade passed that through as a
`wst:FailedAuthentication` fault. That answer is about the caller, who had authenticated fine and asked
a fair question; a revoked token is the ordinary reason to run `Validate` at all. Token-scoped refusals
(`invalid_token`, `invalid_grant`) now answer `wst:Status` `status/invalid` with the reason, while a
refusal about the caller stays a fault. The existing test asserted only "not valid", which the fault
satisfied too — it is now on the shape of the answer.

Ten of ten demo steps pass against a live worker: WSDL, client registered over HTTP, token issued over
SOAP, validate, cancel, validate again, wrong secret, anonymous, junk body, and a token issued over SOAP
spent over HTTP.

### Fixed — an unreadable `X-Forwarded-For` entry no longer lets the walk reach the client's part of the header

`TrustedProxyResolverProcessor` walked the chain right to left and **skipped** any entry it could not
parse as an address. RFC 7239 allows a proxy to write `unknown` for a peer it cannot name, and some
emit an IPv6 with a zone id; after such an entry the walk carried on to the left, into the entries the
client supplied, and took one of them as the client. The entry now ends the walk and the socket peer
is kept. Pinned by `UnparseableHop_StopsTheWalk_KeepsSocketIp`, red on the previous code.

The walk itself is now `ForwardedHeaderResolver` from `redb.Route.Http.Hosting`, one implementation of
the trust model for the ecosystem; the processor keeps its gate (`TrustForwardedFor`, socket peer in
`KnownProxies` / `KnownNetworks`) and delegates the rest. Its remaining role is a context whose host did
not resolve; after the host did, the address it sees is the client's, which is not a trusted proxy,
so it leaves it alone. Pinned by `HostAlreadyResolved_PeerNotInList_IsIdempotent`.

### Changed — DPoP works behind a TLS-terminating proxy

RFC 9449 §4.3 has the server compare the proof's `htu` with the URL the client used. Behind a proxy
that terminates TLS the client signs `https://...` and the socket sees `http://...`, and
`redbHttp.Url`, which the check reads, was built from the socket. The shared HTTP host now applies
`X-Forwarded-Proto` from a trusted proxy, so the URL is the client's. When this module has to create
the host itself (no other component registered one), it hands the host the same proxies
`Identity:ReverseProxies` names, read as configuration because this facade does not reference Core.
Under a Tsak worker the host comes from the worker and `Tsak:Http:TrustedProxies` governs.
`Token_BehindTlsTerminator_HtuWithHttpsScheme_IsAccepted` was red before; its control,
`Token_WithoutForwardedProto_HtuWithHttpsScheme_IsRejected`, pins that the header is what makes the
difference and the scheme check is not loose.

### Added — WS-Trust facade (`redb.Identity.Soap`)

A third transport onto the same core routes HTTP and gRPC already use: `Issue`,
`Validate`, `Cancel` and `Renew` over SOAP, for the callers whose stack builds
clients from a WSDL and speaks WS-Trust rather than OAuth. Same issuer, same
client registry, same token store — a client registered over HTTP gets a token
over SOAP, which is the acceptance criterion the facade exists for and is
covered end to end against the production OpenIddict pipeline.

One route, not four. WS-Trust puts every operation on one address and tells them
apart by the WS-Addressing `Action`, which is what generated clients emit, so the
operation is resolved by parsing rather than by routing. The endpoint counter in
a worker log therefore reads 1 for this module.

The token in the `RequestSecurityTokenResponse` is our ordinary JWT, carried as a
`wsse:BinarySecurityToken`. No second token format enters the system, so
introspection and revocation work on it unchanged.

**TLS is mandatory and its absence is a refusal to start**, not a warning. This is
stricter than the other facades for a specific reason rather than a cautious one:
`UsernameToken` carries the client secret in clear text, so an STS on plain HTTP
publishes credentials to anyone on the path, and a warning in a log is read after
they have already travelled. `AllowPlaintext` is the single escape hatch, for a
connection already terminated by a trusted proxy, and it exists so an operator
states that choice instead of stumbling into it. mTLS is available with modes and
thumbprint pinning; an unrecognised mode is refused at start rather than read as
"no certificate", because a typo must not turn mTLS off on an endpoint whose
operator believes it is on.

Two gaps in `redb.Route.Soap` had to be closed first — the consumer could not
serve TLS at all, and surfaced nothing about the connection to a route. Both are
in that package's changelog.

### Changed — one reading of the core's verdict, three renderings

`redb.Identity.Contracts/IdentityVerdict.cs` now holds what every facade was
about to hold a copy of: where the core states its verdict, that the stated
status outranks the `error` string in the body, and how that string is read. Each
transport keeps its own vocabulary — a status code, a gRPC status, a SOAP fault —
and renders `IdentityVerdictKind` into it with a switch of a few lines.

The gRPC facade is moved onto it in the same change rather than later. Left for
later it would have become the third copy, which is exactly the outcome the SOAP
plan set out to avoid. Its own suite passes 67/67 with no behavioural change: the
tables matched down to `Unknown` for status codes outside the mapped bands.

The reason this matters is on record. Read from the error string alone, a
`rate_limited` answer falls through to "malformed request" and tells a caller to
fix what is not broken instead of to wait; that was found and fixed on gRPC, and
the fix is now in one place rather than three.

### Changed — uniqueness moved off the hand-rolled indexes onto the core's V4 primitives (V4-UNIQUE)

Verified on all three providers: 1962 of 1963 passed, the one long-standing deliberate skip,
zero failures — SQLite and PostgreSQL against the usual databases, MSSQL against a fresh
isolated database (which also exercised the from-scratch bootstrap: core bundle, scheme sync,
backfill no-op, convergence flag). 1963 = the 1945-test pre-refactor baseline plus 17 new
V4-UNIQUE tests; the hole-closing duplicate tests were proven red-before in a worktree on the
pre-change code (4 + 2 failing).

The pre-V4 mechanism was `IdentityUniqueIndexesInitListener`: raw `CREATE UNIQUE INDEX` DDL at
boot, eight per-scheme partial indexes on `_objects` guarding a `value_string`/`_key`/`_name`
column that mirrored a `[RedbIgnore]` phantom property, plus `Hydrate()` copying the mirror back
into Props on every read. It moved to the core's V4 machinery:

- **`[RedbUnique]` on the real properties** — `ApplicationProps.ClientId`, `ScopeProps.ScopeName`,
  `ClaimScopeProps.ScopeName`, `TokenProps.ReferenceId`, `FederatedIdentityProps.LinkKey` (new
  stored composite `"{provider}:{sub}"`), `FederationProviderProps.ProviderId`, and a new
  `UserId` on `MfaProps`/`UserProps` written alongside `key` at every creation site (the 52
  `Key ==` queries are untouched). Lookups are `GetByUniqueAsync` — one probe of the core's
  unique index; `FindByClientIdAsync` runs 8–11 times per `/connect/token` request.
- **`ValueUnique` for the root-only schemes** — `IdentitySystemFlagProps` (props empty by
  design; first-wins: the losing bootstrap gets its 410 from the typed violation) and
  `IdempotencyRecordProps`, whose enforced key is now the SHA-256 of the composite name
  (`IdempotencyKeyHash`) so no client-chosen key can outgrow the 440-char column; the readable
  composite stays in `_name`.
- **One typed catch** — the scheme-key paths catch `RedbUniqueViolationException` instead of
  duck-typing SQLSTATE/error numbers; `IsUniqueViolation` survives only for the two raw-index
  cases below and for the route-level 409 mapping (the typed exception satisfies it through its
  inner chain).
- **Transition backfill** (`V4UniqueBackfillListener`, idempotent by construction, no flag):
  copies the legacy mirrors into Props/`ValueUnique` on the first boot, reports duplicates and
  leaves the losers outside the index (owner decision R4a; a duplicated federated link is
  flagged loudly — it is a potential account-takeover), then drops the seven retired indexes —
  only when every scheme backfilled clean, otherwise the whole pass retries next boot. The
  federated-link lookup keeps a fallback to the old mirror until then: a miss there would
  auto-provision a second local user for an already-linked identity.
- **What stays, by owner decision**: only `UX_users_email` on `_users(_email)` (R1 — V4
  primitives cannot express it; note for shared databases: it imposes email uniqueness on
  every tenant of `_users`). The R2 interim index on redb.Route's idempotent-entry scheme
  was retired the same day: Route shipped its own fix (`ValueUnique` + the typed
  catch in `RedbIdempotentRepository`), so the index joined the
  retired-drop list. The LDAP sync's legacy `UserProps.value_string` reverse-lookup key is
  deliberately untouched — self-contained, never index-backed.

Migration notes: a cluster upgrades by stop-deploy, not rolling — an old node looks keys up in
`value_string`, which the new code no longer writes. A downgrade after this version needs the
mirrors re-filled (the old code cannot see new rows' keys). Identity no longer issues DDL against
`_objects` at boot; a role without DDL rights degrades to a logged statement for the two
remaining indexes and the retired-index drops, never a dead host.

### Fixed — two real uniqueness holes, proven red-before

- **SQL Server never had the ClientId / ScopeName / ReferenceId indexes at all** — documented
  trade-off of the old listener (NVARCHAR(MAX) cannot back a B-tree key), so those
  check-then-save races were unprotected on MSSQL. The `[RedbUnique]` hash column is indexable
  on every provider; the same duplicate tests are green on all three now.
- **Three schemes promised an index that never existed.** The XML docs of
  `FederatedIdentityProps`, `FederationProviderProps` and `ClaimScopeProps` claimed a partial
  unique index no code created: duplicates went through on every provider — for federated links
  that means one external identity could be linked to two local users by a race. Verified RED
  in a worktree on the pre-change code (4 + 2 failing duplicate tests), green after.

### Changed — admin console: pages, not dialogs (Phase 3)

A rich dialog is a page now: the rule applied to every surviving edit modal. Six entities left their overlays:

- **Federation providers** got what they never had at all: a detail page
  (`/admin/federation/{id}` — General / Credentials / Claim mappings / Danger zone tabs)
  plus `/admin/federation/new`. The modal could not even show Priority or the
  claim-mappings editor; the client secret is write-only with a show/hide toggle, and a
  provider still carrying the `REPLACE_ME` placeholder wears a NOT CONFIGURED banner
  explaining why it is hidden from `/login`.
- **Claim definitions** — the console's most crowded modal (~14 fields at 640px) became
  `/admin/claim-definitions/{id}` + `/new`, with the enforcement semantics explained next
  to each control and the immutable identity (claim name / scope) rendered read-only.
- **Claim mappers** — `/admin/claim-mappers/{id}` + `/new`. The page fixes the modal's
  blind spot: the OWNER of a rule (`global` / `application:{id}` / `scope:{id}`) was not
  selectable there, so every mapper landed global; the detail page renders the owner as a
  deep-linked badge to the owning application / claim scope.
- **Users** — the 4-field create overlay became a two-step wizard `/admin/users/new`
  exposing the account + profile surface (the overlay showed 4 of the contract's 9 fields).
- **Scopes and claim scopes** — `/admin/scopes/{id}` + `/new`,
  `/admin/claim-scopes/{id}` + `/new`; the claim-scope page absorbs the old inline
  master-detail panel — the scope's mappers are a section with deep links.

Deletes moved to the detail pages behind the typed-confirm dialog — the one dialog
pattern that stays, together with the shown-once webhook secret. The phase's own
review then caught the last rich dialog standing: the group-create wizard — ironically
the very component the plan cited as the wizard pattern to follow — floated in a
modal-backdrop itself; it is a plain card now, hosted by `/admin/groups/new`. What
remains overlaid is deliberate and light: typed confirms, shown-once secrets, the
read-only SCIM JSON viewer, a one-field WebAuthn rename, and the two-field
template-confirm inside application creation. No `modal-backdrop` edit overlay is left
in the console.

Two additions ride the same wave:

- **`/admin/api-resources`** — the `resource:action` catalogue got a home: the gate's
  precedence rules, the full resource tree with per-scope seeded/not-seeded state
  (deep-linked into the scope store), and the list of operator scopes outside the model.
- **Dashboard** rebuilt after the Tsak.Web composition the owner likes: a six-card KPI
  row (real `PagedResult.Total` probes), an audit-by-category donut and a clickable
  recent-activity table deep-linking into `/admin/audit`. No invented metrics: where no
  telemetry source exists (sparkline history) the element is simply absent.

Coverage: `Phase3PagesTests` pins all twelve new routes — each must exist (not 404) and
must never render anonymously (not 200); it deliberately tightens the old "not 200"
pattern, which a broken route template could satisfy by 404-ing.

### Removed — the Hydrate mirror machinery

`RedbObjectHydration` and its ~30 call sites are gone: a key found through `GetByUniqueAsync`
is a stored prop and needs no copying; the three dead `sql/indexes/*.sql` files (applied by
nothing since the listener took over) went with it.
