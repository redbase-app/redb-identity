# redb.Identity changelog: 3.x

Releases of the 3.x line, moved here unchanged from CHANGELOG.md when the main file started to
follow the current major only. Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [3.7.2] — 2026-08-27

No changes of its own. The version moves with the ecosystem so the exact-version pins between packages keep resolving, and the images pick up the fixed `redb.Tsak.Core` and core packages from their base layer.

## [3.7.1] — 2026-08-26

> **Why 3.7.1, and what happened to 3.7.0.** 3.7.0 is withdrawn: it was built on .NET 9 and carries
> known vulnerabilities in its dependencies (see **Security** below). Every 3.7.0 package is unlisted
> on nuget.org and the `v3.7.0` releases were deleted from the public mirrors. An unlisted version
> still installs by exact number — but there is no reason to: 3.7.1 replaces it completely.
>
> A patch, not a minor: the public API surface does not change. Adding `net10.0` to the target list
> breaks nothing for existing consumers, and `net8.0` / `net9.0` are kept.

### Changed — the build moved to .NET 10

The applications and artifacts were built on net9 while the core and `redb.Route` had long
multi-targeted `net8.0;net9.0;net10.0`. The gap surfaced on 3.7.0: images and archives shipped as net9.

The `redb.Tsak.*` and `redb.Identity.*` libraries now declare `net8.0;net9.0;net10.0` — exactly like
the core and Route, so the whole ecosystem is uniform. Host applications and tests are pinned to a
single `net10.0`. Images, archives and tags are `-net10`.

.NET 8 and .NET 9 both reach end of support on **10 November 2026** — the same day, Microsoft aligned
the STS 9 date with LTS 8. .NET 10 is supported until **14 November 2028**. `net8.0` and `net9.0`
remain in the libraries' target list for now.

### Security — six high-severity advisories

Found while moving to .NET 10: changing the TFM forced a from-scratch rebuild and the NuGet audit
spoke up. It stays silent on an incremental build, which is how all of this reached 3.7.0.
- **`redb.Identity.DataProtection` — `System.Security.Cryptography.Xml` 9.0.4, SEVEN advisories at
  once** ([GHSA-23rf-6693-g89p], [GHSA-37gx-xxp4-5rgx], [GHSA-6588-8gv4-xfgh], [GHSA-8q5v-6pqq-x66h],
  [GHSA-cvvh-rhrc-wg4q], [GHSA-g8r8-53c2-pm3f], [GHSA-mmjf-rqrv-855v] — all high). Pulled in
  transitively from `Microsoft.AspNetCore.DataProtection` 9.0.4. An XML cryptography library, inside
  the product that does authentication. Pinned to 9.0.18, the patched 9.x release.
- **`redb.Identity.Http` — `Microsoft.Bcl.Memory` 9.0.0** ([GHSA-73j8-2gch-69rq], high), transitively
  from `OpenIddict.Abstractions`. Pinned to 9.0.19.

The 9.x line rather than 10.x wherever the library multi-targets down to `net8.0`: 10.x does not
install there.

### Fixed — `redb.Identity.Grpc.tpkg` reached no artifact at all

`build-modules` produces three `.tpkg` files, but the list of what gets copied into artifacts was
hardcoded as exactly `Core.Module` + `Http` — in `build-archives.ps1` (three places) and in the
`backend`, `full` and `managed` Dockerfiles. When the gRPC facade shipped in 3.7.0 its `.tpkg` was
built and then silently dropped: anyone installing Identity from an archive or an image got no gRPC
facade at all, while the `redb.Identity.Grpc` package was published and announced in this changelog.

The archive script now enumerates `*.tpkg` from the build output and prints what it ships; the
Dockerfiles copy `output/*.tpkg` by glob. A new module now ships because it exists, not because
someone remembered to add a line.

[GHSA-23rf-6693-g89p]: https://github.com/advisories/GHSA-23rf-6693-g89p
[GHSA-37gx-xxp4-5rgx]: https://github.com/advisories/GHSA-37gx-xxp4-5rgx
[GHSA-6588-8gv4-xfgh]: https://github.com/advisories/GHSA-6588-8gv4-xfgh
[GHSA-8q5v-6pqq-x66h]: https://github.com/advisories/GHSA-8q5v-6pqq-x66h
[GHSA-cvvh-rhrc-wg4q]: https://github.com/advisories/GHSA-cvvh-rhrc-wg4q
[GHSA-g8r8-53c2-pm3f]: https://github.com/advisories/GHSA-g8r8-53c2-pm3f
[GHSA-mmjf-rqrv-855v]: https://github.com/advisories/GHSA-mmjf-rqrv-855v
[GHSA-73j8-2gch-69rq]: https://github.com/advisories/GHSA-73j8-2gch-69rq

## [3.7.0] — 2026-08-25

> **Why a minor.** Two new packages ship: `redb.Identity.Grpc` (a second facade beside HTTP) and
> `redb.Identity.Management`, the transport-neutral management controllers extracted out of
> `redb.Identity.Http` so both facades dispatch the same ones. New surface cannot be a patch.
>
> **The extraction moves types across packages.** `redb.Identity.Http.Controllers.*` is now
> `redb.Identity.Management.Controllers.*`; `redb.Identity.Http` depends on the new package, so a
> plain package upgrade keeps working, but code naming those types by full name must be updated.
> The ecosystem moves on one number; `redb` core, `redb.Route` and `redb.Tsak` ship 3.7.0 alongside.

### Changed — the packages now ship XML documentation

`GenerateDocumentationFile` was never enabled for redb.Identity, so all ten packages shipped a bare `.dll`
and gave consumers no IntelliSense. It is on now, and `lib/net9.0/*.xml` travels with every package —
670 KB of it for `redb.Identity.Core` alone.

CS1591 (public member without XML doc) is suppressed, unlike `redb.Route` where it is deliberately left on:
turning the doc file on without that adds over 3500 warnings in three of the ten projects alone, on members that
predate the policy. The doc-syntax warnings stay visible on purpose, and `redb.Identity.Core` alone raises
218 of them — 128 unresolved `cref`, 100 methods missing a `param` tag, 6 malformed XML comments. Nothing
fails to build; they are queued as a cleanup, not as a release blocker.

### Added
- **`redb.Identity.Grpc` — a gRPC facade for redb.Identity.** A second transport beside
  HTTP, talking to Core over the same `direct-vm://identity-*` routes: `Token`, `Introspect`, `Revoke`,
  `UserInfo`, `Discovery`, `Jwks`. Ships as its own `.tpkg` with `ContextName: identity.grpc` and zero
  compile-time dependency on `redb.Identity.Core` — the Phase 8 facade-isolation invariant, verified
  against the built assembly's `deps.json` rather than against its project file.

  One gRPC method address is one route, so every operation carries its own route id, policies, metrics
  and lifecycle instead of hiding inside a single dispatch switch. Ports mirror the HTTP facade
  (`PublicPort` / `ManagementPort ?? PublicPort`) and are never shared with it: gRPC needs HTTP/2 while
  the HTTP facade serves HTTP/1.1 + HTTP/2, and one listener has a single protocol set.

  Configuration lives in the shared `context.json` under `IdentityTransport:Grpc:*`, beside the HTTP
  facade's section; issuer and feature flags come from the same `Identity:*` root Core reads.
- **Published contract `identity.v1.proto`.** Lives in `redb.Identity.Contracts/Protos` as a file
  consumers generate stubs from — the `redb.Identity.Contracts` package ships both `.proto` files under
  `Protos/`, so a non-.NET client takes the contract from NuGet rather than from the repo. Compiled only
  by the facade, Contracts stays a dependency-free DTO package instead of dragging Google.Protobuf into
  Core, Http and Client. Requests carry the parameters the RFCs name plus a string map for extensions
  (the wire form of these endpoints has always been form-encoded key/value); responses type what the
  RFCs fix and carry the rest in a `google.protobuf.Struct`, because userinfo claims and introspection
  extensions are open sets.
- **Generic envelope as a fallback path.** The same six operations reachable through
  `RedbService/Process` with a JSON body and an `operation` header, for callers that would rather not
  carry the `.proto`. One surface, two spellings.
- **mTLS and gzip on the facade, off by default.** Client certificates can be required and pinned by
  thumbprint; recommended for the management port in production, not forced, so deployments without a
  client-certificate PKI are not blocked.
- **Correlation ids and idempotency across the gRPC boundary.** A caller's `X-Correlation-Id` is honoured
  (or derived from the ambient trace id) and echoed back in a trailer; each operation tags itself so
  Core's idempotency cache keys per operation instead of lumping every gRPC call into one bucket.

- **The management surface over gRPC.** Forty admin operations across five services — Users,
  Applications, Groups, Scopes, Tokens — on `ManagementPort`, each its own method address and its own
  route id. The chain per operation is the security property, in this order: name the call, decode it,
  authenticate, halt if refused, authorize, halt if refused, and only then dispatch. Both gates run on
  isolated exchanges, so the halt is explicit rather than inherited from Core's `exchange.Stop()` — the
  gate stays shut until it positively sees an allow.

  The controllers are the same ones the HTTP facade dispatches, which is what `redb.Identity.Management`
  was extracted for. Propagating `identity:management-*` into the inner exchange comes free as a result:
  `IdentityControllerBase.Forward` already does it, so Core's self-vs-admin protection works on this
  transport without a line written for it.

  Contract: `identity.management.v1.proto`. Addresses are typed and generate into client stubs; payloads
  are `Struct` / `Value`. Typing the bodies of forty operations — 142 across the whole admin surface —
  would freeze a surface that still grows, and raw JSON would have cost the generated client.

  Self-service (`/me`, account registration, password recovery, MFA enrolment) is deliberately absent: it
  is an end-user flow reached from a browser or an app session, not admin tooling, and hosting it on an
  admin port would widen that port's blast radius for a caller that does not exist.
- **Split ports, verified rather than declared.** `ManagementPort` defaults to sharing `PublicPort`, and
  until now that was the only branch ever executed — the split looked like a supported configuration
  without being one. It is now covered end to end: the admin addresses answer only on the management port,
  the protocol port returns `UNIMPLEMENTED` for them (which is what makes a firewall rule on the admin
  port worth writing), the protocol surface is unaffected, and the gate is still a gate.
- **TLS material travels through a named `GrpcConnectionFactory`, not in the endpoint URI.** Not because
  the URI would disclose it — `SslCertPassword` is `[Sensitive]` and is redacted wherever the URI is
  rendered — but because this keeps the secret out of the route key altogether, and the route key is
  handled as a plain string in plenty of places.

### Security
- **The management gate now requires proof that authentication ran, not merely the absence of a refusal.**
  A deployment can wire Core without a management auth processor, which leaves
  `direct-vm://identity-auth-management` unregistered. The hop then throws "No consumer registered", Core's
  context-level exception handler marks that handled and replaces the body with its own error document —
  and the gate saw exactly what success looks like: no refusal recorded, no non-2xx code. The call still
  did not execute, but only because that handler happened to end the pipeline and because the wire encoder
  happened to refuse the leftover dictionary. Two unrelated safety nets, neither of them an authentication
  decision; remove either and every admin operation runs unauthenticated. The gate after the
  authentication hop now demands the `identity:management-principal` the auth processor leaves behind, and
  answers `UNAUTHENTICATED` when it is absent. Covered by a fixture that boots Core without the processor
  and asserts both the status and — the part that actually matters — that no row was written.
- **Idempotency over gRPC verified, and the README corrected.** The claim was never tested: the key
  crosses two spellings (`idempotency-key` in metadata, `Idempotency-Key` in Core), and a case-sensitive
  dictionary anywhere on that path would have made replays create duplicates in silence. It works, and the
  test proves it both ways — the same key returns the original record, a different key is refused as a
  duplicate. The README claimed idempotency applied generally; in fact Core applies it to the management
  surfaces only, and the protocol operations have no idempotency layer at all. Documented where the line
  actually falls.
- **Per-IP protections keep working behind the gRPC facade.** Core keys its per-IP throttle, its
  brute-force lockout and its device metadata on `redbHttp.RemoteAddress`, and those checks **silently do
  nothing** when the header is absent rather than failing loudly. The facade therefore bridges the real
  client address into it (`EmitHttpCompatHeaders`, on by default), and callers cannot forge it — the
  transport drops inbound headers carrying a reserved prefix.
- **Upstream refusals reach the caller as refusals.** A status Core decided — 429 from rate limiting, 403
  from the scope guard, 503 from a database outage — is translated into the matching gRPC status instead
  of arriving as a successful call carrying an error document that no generated client inspects. OAuth
  errors map by RFC 6749 §5.2, and the machine-readable code travels in a trailer because a non-OK gRPC
  reply has its payload discarded.
- **The facade answers even when Core stops the exchange.** Several Core processors end their work with
  `exchange.Stop()` — the per-IP limiter and the granular scope guard among them — and `To` hands Core the
  facade's own exchange, so that flag ended the facade's pipeline too: the reply left as a raw dictionary
  that never went through status mapping or protobuf encoding. The security-relevant answers were exactly
  the ones losing their status. The hop into Core now goes through `Enrich` on a `CloneLinked` exchange
  (same exchange id, same DI scope, same properties, its own stop flag), and an unhandled fault is
  rethrown rather than adopted. Covered end to end: a caller over the per-IP limit is answered
  `RESOURCE_EXHAUSTED` with `rate_limited` and a `retry-after` trailer.
- **A rate-limited answer keeps its status.** Core's 429 carries an error document whose code is
  `rate_limited`, which appears in no RFC 6749 table; deriving the gRPC status from the error string
  demoted it to `INVALID_ARGUMENT` and dropped the backoff advice. A status Core decided itself now wins,
  and the error code still travels in a trailer.

### Changed
- **The granular scope table moved into Core**, behind `direct-vm://identity-authz-check`. It used to
  live in the HTTP facade; a second transport was about to need the same decisions, and the failure mode
  of two copies of an authorization table is not that they disagree loudly but that one of them quietly
  grants more than the other, on the surface where that matters most. Moved verbatim: same order, same
  write-implies-read rule, same `identity:account` branch, same default-deny, same refusal wording - the
  HTTP negative matrix reads that wording, and rewriting expectations is how a regression net stops
  catching anything.

  The contract is transport-neutral: `identity:authz-resource`, `identity:authz-action` and the scopes
  the authentication step already established. Resource identifiers are the canonical management paths,
  so the table stays whole rather than being split into "paths here, scopes there".
  `GranularScopeGuardProcessor` is now a thin wrapper that names resource and action, and Core falls back
  to `redbHttp.Path` / `redbHttp.Method` when nothing states them, so the path is never carried twice.

  The route is registered unconditionally: a facade calling an address that is not there would fail open,
  which is the one direction an authorization gate must never fail.

- **Management controllers moved into their own package, `redb.Identity.Management`.** 33 files, 142
  actions, and not one line of business logic: every action validates its DTO and forwards to a
  `direct-vm://identity-manage-*` route. They lived in the HTTP facade, where a second transport could not
  reach them without breaking the Phase 8 isolation. Now the facades reference the package rather than each
  other, and the package references no Core, so that isolation still holds.

  SCIM deliberately stayed in the HTTP facade: RFC 7644 is defined over HTTP, and `ScimControllerBase`
  reads `redbHttp.Url` to build `Location` headers. Moving it would have carried HTTP semantics into a
  transport-neutral package for a surface that does not exist off HTTP.

  Nothing breaks for consumers: same types, only the namespace changed
  (`redb.Identity.Http.Controllers` → `redb.Identity.Management.Controllers`). The suite after the move is
  identical to the baseline before it.

### Fixed
- **A duplicate is a conflict, not a database outage.** The builder-level `DbException` handler treated
  every database error as transient: a unique-constraint violation was retried three times with backoff —
  it collides on the third attempt exactly as on the first — and then answered `503 "Database temporarily
  unavailable"`, telling the caller to come back later about something only they can fix. It now answers
  `409` with `error: duplicate`, the same vocabulary the management processors already use, while real
  outages keep their retries and their 503.

  Surfaces that catch unique violations themselves — applications, claim scopes, bootstrap, idempotency —
  were always right; users, groups, roles and SCIM fell through to the handler and were not. Found through
  a SCIM demo that reused one e-mail address and was reported as a database outage, which is where the
  hunt started instead of ending.
- **A refusal that arrived as JSON bytes no longer loses its status.** `MapErrorToGrpcStatus` read only a
  dictionary body and returned immediately on bytes, without even reaching `redbHttp.ResponseCode`. Core's
  own processors hand back a dictionary, but the authentication gates and the controller dispatcher hand
  back serialized JSON — their refusals were reaching callers as successful calls. The response code is
  now always read, and the body is parsed in either shape.
- **The controller error table moved to `redb.Identity.Management`.** It lived inside the HTTP facade; a
  second transport needs the same verdicts, and two copies of a refusal table drift towards "one accepts
  what the other rejects".
- **README and `doc/DEPLOYMENT.md` documented an option that does not exist, and lied about its default.**
  The real name is `UsePropsSigningKeyStore` / `PropsSigningKeyStore`; the docs said
  `UseEavSigningKeyStore` / `EavSigningKeyStore`, which no type matches. The worse half: the default was
  documented as `true` while the code has `false`, and the verification table even labelled it
  "(default)". An operator running more than one replica read that a shared JWKS was on out of the box,
  when replicas in fact diverge on keys by default. Corrected to the fact, with an explicit "off by
  default, switch it on for multi-replica".

  Archived documents (`doc/rewiewFix/*`, `doc/webplan/*`, the Phase-8 plan) were deliberately left alone:
  they are records of finished sprints, and rewriting names inside them would falsify the record.

- **Audit DDL now reconciles an existing table instead of silently skipping it.** `CREATE TABLE IF NOT
  EXISTS` is a no-op when the table is already there, so a database created before a column existed never
  gained it — and nothing said so. The audit query selects `category` and `login`; on such a database it
  failed, the route's `DbException` handler retried three times and answered "Database temporarily
  unavailable", which reads as an outage rather than a schema gap. The two `CREATE INDEX` statements on
  those columns failed on every startup for the same reason, and the init listener logged the error and
  continued in degraded mode.

  The PostgreSQL and MSSQL scripts now add missing columns idempotently before the indexes, and Postgres
  additionally repairs two types that drifted after the first release: `details` jsonb → text (the
  dialect-agnostic parameter binding passes strings, and jsonb refuses them, so every audit write failed)
  and `user_id` varchar → bigint — the latter only when every existing value is numeric, otherwise the
  table is left alone with a notice, because nulling unparseable identifiers is a data loss nobody agreed
  to. Both conversions are guarded on the current type and cost a current database nothing. SQLite cannot
  express conditional DDL, so its script documents the two hand-migration statements instead of pretending.

  Found on the shared test database, where the drift had accumulated: the audit query had been answering
  503 there, and three `AuditCompletenessFullCycleTests` failed on PostgreSQL because of it.

### Documentation
- **A demo for the gRPC facade, in the same `run_all.ps1` gate as the other 61.** `demo_grpc_facade.ps1`
  drives ten steps against a live worker with an `@grpc/grpc-js` client running in a container, so the
  calls come from a stack that shares no code with ours: health, discovery, a client registered over HTTP
  getting its token over gRPC, introspection, a refusal arriving as `UNAUTHENTICATED` with an
  `invalid_client` trailer, and the management gate refusing without a token and admitting with one.

  Its last step closes the facade's acceptance criterion, which no test could: one token, two transports,
  the same verdict. A client holding `identity:users:write` is admitted over both; a client holding only
  `identity:users:read` is refused the write over both. In tests this was blocked because the HTTP and
  gRPC fixtures are separate stacks with separate registries — on a worker they are one server, so the
  token is literally the same one.

  The earlier decision to ship no demo was recorded as deliberate; it was not. It rested on an incomplete
  list of options — PowerShell cannot speak gRPC, and a .NET client against our own listener proves only
  self-consistency — while the container client that made it possible was already running in the interop
  tests at the time.
- **Package README for `redb.Identity.Grpc`** - both surfaces, the deliberate boundaries (browser flows,
  DPoP, self-service), every configuration key with its default and the reason for it, message shape, the
  status and trailer tables a caller has to read, correlation ids and idempotency, the envelope fallback,
  TLS/mTLS, the forty management operations with their payload shape, and splitting the ports for
  production.
- **`redb.Identity/README.md`** - the "planned" gRPC snippet replaced by the real route, the package added
  to the project structure, and an `identity.v1.Identity` section in the endpoint catalogue.
- **Interop fixture extended** (`C:\Work\yaml\grpc`): the published `identity.v1.proto` and an
  `@grpc/grpc-js` client generated from it, so the facade is proven by a stack that shares no code with
  it. Covers a real token, a refusal read as `UNAUTHENTICATED` plus an `invalid_client` trailer, and a
  `google.protobuf.Struct` decoded by a runtime that never saw our codec.

### Notes
- Browser flows (`authorize`, login, consent, MFA pages, device verification) and DPoP stay on HTTP by
  design, not by omission: the former need a browser, redirects and a cookie session; DPoP binds its
  proof to an HTTP method and URL per RFC 9449. Recorded as boundaries in `doc/gRPC/README.md`.
- `redbHttp.Method` is deliberately **not** synthesised by the facade. Core reads its absence as "this
  caller is not a browser" — synthesising it would flip `authorize` into emitting 302 redirects.

## [3.6.0] — 2026-08-13

> Ships with the ecosystem. The minor comes from `redb.Route`; the change below is Identity's own,
> and the rebuild additionally carries the redb.Core tree-scope fix into every deployment.

### Security — atomic e-mail uniqueness (register / bootstrap)

`RequireUniqueEmail` was enforced by a check-then-insert: `GetUsers(email)` → `Reject(409)` →
`CreateUser`. Between the check and the insert two concurrent registrations could both see "no
match" and both write the same address, so `RequireUniqueEmail` did not actually hold under
concurrency (login was already atomic via its relational UNIQUE; e-mail was not).

- **`UX_users_email` — a partial unique index on `_users(_email)`** (`WHERE _email IS NOT NULL`),
  created per-dialect by `IdentityUniqueIndexesInitListener` alongside the existing `_objects`
  indexes. This is the atomic DB guarantee — the check-then-insert is now only a fast, deterministic
  early error, not the enforcement. Partial (skips null e-mails, of which there are many) so it also
  works on SQL Server, whose plain UNIQUE allows only one NULL; `_email` is `NVARCHAR(450)` there, so
  it indexes on all three dialects (unlike the `_value_string` indexes that stay Postgres-only).
- **E-mail normalised to lower-invariant + trimmed** before the check and the insert
  (`AccountRegisterProcessor`, `BootstrapAdminProcessor`). Without it a plain index on `_email` would
  treat `A@x.com` and `a@x.com` as distinct; normalising makes the stored value canonical so the
  index (and `EmailExact` lookups) enforce one identity.
- **Index violation is surfaced as `409 duplicate`**, not a `500`: `AccountRegisterProcessor` catches
  a `UX_users_email` unique-violation (message or inner-exception) — the same shape login already
  used for its "already taken" 409. The loser of a register race now gets a clean duplicate error.

### Removed — debug scaffolding in the register hot path

`AccountRegisterProcessor` carried a per-exchange stopwatch with ~25 `__arMark(...)` calls (the
`Console.WriteLine` was commented out, so they were no-ops) **and a VERIFY block that issued two
extra `GetUsers` queries after every `CreateUser`** just to feed those no-op logs. Removed both —
two fewer DB round-trips per registration and no dead diagnostics in the hot path.
`PasswordForgotProcessor`'s commented `[Diag-PF]` lines cleaned up too.

## [3.5.1] — 2026-08-07

**No changes in redb.Identity itself — a rebuild that re-pins the dependency on `redb.Route`.**

`redb.Identity.Core` 3.5.0 pins `redb.Route.Http` **3.5.0**, the build that still contains
`SharedHttpServerManager` privately; `redb.Route` 3.5.1 moved it into `redb.Route.Http.Hosting` so
HTTP-based connectors can share one Kestrel per `host:port`. Identity is an HTTP-facing product
hosted next to other connectors inside a Tsak worker, so a stale pin here is not academic: with the
old `Http`, an AS2 endpoint and the OIDC facade could not sit on the same port, and NuGet would not
have corrected it on its own (`redb.Route.As2` depends on `Http.Hosting`, not on `Http`).

Nothing else changed — same code, same behaviour, rebuilt on `redb.Route` 3.5.1 and `redb.Tsak`
3.5.1. `redb` core stays 3.5.0: it does not reference `redb.Route` at all.

## [3.5.0] — 2026-08-05

**No changes in redb.Identity itself — a rebuild onto redb 3.5.0 / redb.Route 3.5.0 / redb.Tsak
3.5.0**, released with the ecosystem.

The dependency refresh is the point. Identity runs as `.tpkg` modules inside a Tsak worker, and that
worker loads the redb framework from its shared layer, which is gated on the **minor** version — so
an Identity built against 3.4.0 cannot be hosted on a 3.5.0 runtime, and vice versa. Rebuilding also
carries two redb.Core correctness fixes into every Identity deployment: a props-cache entry that
could be served stale after in-place mutation, and `RedbHash` being order-dependent for `Dictionary`
properties (both detailed in the root `CHANGELOG.md`). Identity stores clients, users and signing
keys through that same layer, so neither is academic here.

## [3.4.0] — 2026-07-27

> **Why the jump from 1.2.2 to 3.4.0 — aligning with the ecosystem, not a breaking rewrite.**
> Until now redb.Identity carried its own **1.x** line while the rest of the stack (`redb` core,
> `redb.Route`, `redb.Tsak`) moved together on **3.x**. Running two numbering schemes made "which
> Identity works with which core/Route/Tsak" a lookup instead of a glance. From now on redb.Identity
> **shares the ecosystem version**: it jumps straight to **3.4.0** to sit on the same number as the
> `redb.Route` 3.4.0 it is built against, and every future ecosystem release bumps Identity with it.
>
> This is a **version realignment, not a semver-breaking release** — there are no breaking API changes
> here (the only feature, JAR, is off by default and additive; see below). The major digit changes
> because the number is now the ecosystem's, not because Identity's contract broke. The old 1.x tags
> remain valid history; 3.4.0 simply continues the same package on the shared number.

### Added

- **JWT-Secured Authorization Request — JAR (Z7 / RFC 9101), off by default.** `/connect/authorize`
  now accepts a signed authorization request, gated behind `Features.EnableJar` (default `false`,
  so every prior release behaves identically — a `request` parameter is still answered with
  `request_not_supported`). When enabled:
  - a signed **`request`** object (inline) or **`request_uri`** (by reference, fetched over HTTP) is
    verified against the client's registered keys, and the parameters inside the JWT take precedence
    over the query string (RFC 9101 §6.1);
  - **`alg: none` is never accepted** — an unsigned request object drops the integrity guarantee JAR
    exists for; nor is a wrong-key signature, a mismatched inner `client_id`, an expired object, or
    (when the client declares `RequestObjectSigningAlg` under `JarEnforcementMode=Enforce`) a
    mismatched algorithm. Every failure is `invalid_request_object`;
  - **`request_uri` fetches are SSRF-guarded** (`OutboundUrlGuard`) and size/timeout-bounded; PAR's
    `urn:ietf:params:oauth:request_uri:*` is left untouched;
  - discovery advertises `request_parameter_supported`, `request_uri_parameter_supported` and
    `request_object_signing_alg_values_supported` — **only when JAR is on**, so discovery never
    promises what the endpoint won't do.
  - The formerly write-only client fields `RequestObjectSigningAlg` etc. now do something (see below).
  - New config: `JarOptions` (`Jar` section) — enforcement mode `Off`/`LogOnly`/`Enforce`, allowed
    algorithms (asymmetric only), clock skew, size limits, and the `request_uri` SSRF knobs.
  - Implemented as OpenIddict server handlers (`ValidateRequestObjectHandler`), replacing the built-in
    handlers that unconditionally rejected `request` / `request_uri`. 15 handler tests + a live
    conformance demo (`demo_jar_request_object.ps1`, wired into `run_all`).
- **Client public-key resolver — `IClientKeyResolver`** (Z7 / RFC 9101, phase 1). Resolves the keys
  that verify what a **client** signed: a JAR request object and a `private_key_jwt` assertion.
  Two sources — the inline `ApplicationProps.JsonWebKeySet`, or `JwksUri`, fetched and cached via
  `ConfigurationManager<JsonWebKeySet>` (background refresh on a TTL plus a rate-limited forced
  refresh on a `kid` miss, so a client rotating its keys does not break sign-in until the TTL expires).
  - **Fails closed.** An unreachable or malformed JWKS yields no keys, so there is nothing to verify
    against and the caller rejects. "Could not check" is never treated as "valid".
  - **A configured-but-broken inline JWKS does not fall back to `jwks_uri`.** A typo in the pasted
    key set must stay visible instead of being masked by a silent switch to another key source.
  - **Asymmetric algorithms only.** HMAC (`HS*`) is impossible: `ClientSecret` is stored as a BCrypt
    hash and verifying an HMAC needs the original secret. FAPI 2.0 forbids `HS*` for request objects
    anyway.
  - The service is **inert** for now — registered but called from no path, so server behaviour is
    unchanged. Wiring it into JAR is phase 2; into `private_key_jwt`, a separate step.
- **`OutboundUrlGuard` — SSRF filter for URLs that arrive from outside** (`jwks_uri`, later the JAR
  `request_uri`). Rejects anything that is not an absolute HTTPS URL, and anything resolving to a
  non-public address: loopback, RFC 1918, link-local — including `169.254.169.254`, the cloud
  metadata endpoint that hands instance credentials to whatever can reach it — CGNAT, IPv6
  unique-local, and the IPv4-mapped forms (`::ffff:10.0.0.1`) that a naive check walks straight past.
  The check runs **before** a socket is opened. Known limitation: this does not close DNS rebinding,
  which would require pinning the validated address onto the connection itself.
- **`ClientKeysOptions`** (`ClientKeys` section of `RedbIdentityOptions`) — cache lifetime, minimum
  refresh interval, fetch timeout, maximum document size, `RequireHttps`,
  `AllowPrivateNetworkTargets`. The last two are development-only relaxations.
- **40 tests** (`tests/Security/`): 29 for the SSRF guard — including one asserting that 172.32 and
  172.15 are public and must NOT be blocked — and 11 for the resolver. All stay offline: attempting
  a network call fails the test by itself.

### Docs

- **`doc/JAR_RFC9101_PLAN.md`** — JAR implementation plan: six phases, risks (SSRF, `alg:none`,
  algorithm substitution), a staged `Off → LogOnly → Enforce` rollout, and sizing. Records a verified
  finding: **OpenIddict 6.3.0 does not support request objects** — its assembly carries
  `ValidateRequestParameter` and the `request_not_supported` string, but nothing that parses a request
  object or checks its signature — and `request_uri` exists only as a PAR URN. `Z7` now links here.
- `ApplicationProps.RequestObjectSigningAlg` is **now enforced** under `JarEnforcementMode=Enforce`
  (was previously stored and ignored). `...EncryptionAlg` / `...EncryptionEnc` remain stored-only —
  request-object encryption (JWE) is the deferred phase 4. `JwksUri` is now resolved (phase 1).

### Conformance impact (OpenID Foundation Basic OP)

Advertising JAR changed the local Basic-OP run from **1 SKIPPED / 4 REVIEW** to **2 SKIPPED / 3 REVIEW**
— still **0 FAILED**. This is a net improvement, not a regression, and `OPENID_CERTIFICATION.md` §4.3
explains it in full for anyone reading the badge:

- Both SKIPPED modules test the **unsigned (`alg:none`) request object**. The suite skips them when the
  server does not advertise `none` in `request_object_signing_alg_values_supported` — which is exactly
  our stance: we support **signed** request objects only, because `alg:none` is an unsigned JWT that
  defeats JAR's integrity guarantee and is forbidden by FAPI 2.0. SKIPPED here = "the server declined
  an unsafe mode", the secure answer.
- One module (`ensure-request-object-with-redirect-uri`) moved REVIEW→SKIPPED precisely *because* the
  server now genuinely processes signed request objects and advertises that honestly, instead of the
  earlier no-support state that sent it down a screenshot path. Turning either skip into a pass would
  require accepting `alg:none` — a security regression we will not make.
