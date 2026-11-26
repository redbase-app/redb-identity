# Changelog

All notable changes to redb.Identity will be documented in this file.
This changelog covers the **planned NuGet/`.tpkg` packages** that ship from this repository:

| Package | Description |
|---------|-------------|
| `redb.Identity.Core` | OIDC / OAuth 2.1 engine: OpenIddict pipeline on redb.Route, redb-backed stores (Application, Authorization, Token, Scope, KeyRing, Session, Audit), `direct-vm://identity-*` API surface |
| `redb.Identity.Core.Module` | `.tpkg` host glue for `redb.Identity.Core` — `IRouteModule` entry point, configuration binding, named-redb wiring (`identity`) |
| `redb.Identity.Contracts` | Transport-agnostic request/response DTOs and route-name constants shared by Core, Http, and Client |
| `redb.Identity.Management` | Transport-neutral management and self-service controllers — thin adapters over the `direct-vm://identity-manage-*` routes, shared by every facade |
| `redb.Identity.Http` | HTTP / HTTPS facade `.tpkg` — OIDC discovery, `authorize`, `token`, `userinfo`, `introspect`, `revoke`, JWKS, PAR, DCR, SCIM, `/me`, management, browser flows |
| `redb.Identity.Grpc` | gRPC facade `.tpkg` — service-to-service surface (`Token`, `Introspect`, `Revoke`, `UserInfo`, `Discovery`, `Jwks`) + management services; contract shipped in `redb.Identity.Contracts` under `Protos/` |
| `redb.Identity.Soap` | WS-Trust facade `.tpkg` — `Issue`, `Validate`, `Cancel`, `Renew` over SOAP on the same core routes; WSDL published on GET |
| `redb.Identity.Web` | Server-rendered host pages: login, native consent, MFA enrollment, e-mail verification, password recovery, account self-service |
| `redb.Identity.Client` | In-process and HTTP client SDK for `direct-vm://identity-*` endpoints + backchannel OIDC client (`BackchannelOidcClient`) |
| `redb.Identity.DataProtection` | Standalone `Microsoft.AspNetCore.DataProtection` wiring on redb-backed key-ring storage (no ASP.NET) |
| `redb.Identity.Ldap` | LDAP / Active Directory federation provider — directory sync handler + bind-on-login adapter |
| `redb.Identity.Resource.Dpop` | Resource-server middleware: DPoP (RFC 9449) proof validation + replay cache for downstream APIs |

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on version history:** **`1.0.1`** is the first public source release
> (repo: [redbase-app/redb-identity](https://github.com/redbase-app/redb-identity)).
> The pre-1.0 history is preserved as `1.0.0-preview.*` in [changelog/CHANGELOG-1.x.md](changelog/CHANGELOG-1.x.md) — the engine ran
> in internal Tsak deployments through the whole `direct-vm://`-first design
> phase; those entries collapse that history. Versioning is unified across all
> packages in the table above — every release bumps every package together.
>
> **From `3.4.0` onward redb.Identity shares the ecosystem version** (`redb` core / `redb.Route` /
> `redb.Tsak`) instead of its own `1.x` line — see the `[3.4.0]` entry in [changelog/CHANGELOG-3.x.md](changelog/CHANGELOG-3.x.md). The `1.0.1`–`1.2.2` tags stay
> as valid history; the jump to `3.4.0` is a realignment onto the shared number, not a breaking change.
> NuGet publication follows the source cut.


## [Unreleased]

Pending changes live in `changelog/unreleased/` until the release; `pwsh scripts/changelog.ps1 -Preview` shows them.

## [4.7.6] — 2026-11-27

### Changed

- **Identity 4.7.6 and its images run on redb 4.7.6, which loads pages with less memory and plans more queries through
  the indexes.** Identity's own code is unchanged. A database needs no conversion step. Packages: `redb.Identity.Core`.

## [4.7.5] — 2026-11-24

### Security

- **Dynamic client registration no longer answers from the Idempotency-Key cache.** A second caller that sent the same
  `Idempotency-Key` to `POST /connect/register` received the first registration's answer, its `client_secret`
  included. A repeated registration now registers another client. Packages: `redb.Identity.Core`.
- **The Idempotency-Key cache no longer keeps a secret, and a repeat no longer shows it again.** Webhook create and
  rotate-secret, client secret rotation, MFA enrollment and recovery codes were cached with their answer, secret
  included; a repeat now gets `{"replayed":true,"secretWithheld":true,...}`. Earlier records go with the cleanup once
  they expire; to remove them at once, see the upgrade notes. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#idempotency-records-keep-no-secrets).

### Changed

- **Identity 4.7.5 runs on redb 4.7.5, which stores `TimeSpan` and `TimeOnly` as ticks.** Identity's own data holds no
  such values, so an existing Identity database needs no conversion before the first start. Every node and image that
  shares the database still moves to 4.7.5 together; there is no way back except a backup. Packages: `redb.Identity.Core`.

### Fixed

- **Changing the role of, or removing, a user who is not a member of the group answers `404`, not `500`.** The same
  holds when the group itself does not exist. `PUT` and `DELETE /groups/{id}/members/{userId}` answered
  `server_error` for such a request. Packages: `redb.Identity.Core`.
- **A management request for a role or a group that does not exist answers `404`, not `500`.** Updating a role, and
  updating, moving, adding a child or a member to, or reading the tree, path or children of a group with an unknown
  id answered `server_error`. They now answer `404 not_found`, like the other management endpoints. Packages: `redb.Identity.Core`.
- **A SCIM user create refused by a unique key answers with the SCIM error document and names the right attribute.**
  On SQLite the loser of two concurrent `POST /scim/v2/Users` could get `409` with the management error body instead
  of the SCIM error with `scimType: "uniqueness"` (RFC 7644 3.12). And a create whose e-mail was taken was told that
  its `userName` already exists; the detail now names the e-mail. Packages: `redb.Identity.Core`.
- **An audit event whose row could not be written is counted.** A failed insert into `identity_audit_log` was only
  logged, so a gap in the audit trail showed up nowhere an operator alerts on. The meter `RedbIdentity` now has the
  counter `identity.audit.write_failures` (tag `event_type`); the event itself still goes on to webhooks and targets. Packages: `redb.Identity.Core`.
- **The metric `identity.unique_violation` now counts.** It was defined and documented but nothing ever added to
  it. A unique-key violation that the server answers with the general `409 duplicate` is now counted, tagged
  `scheme` and `column` with what collided when the database says so (`unknown` otherwise). Packages: `redb.Identity.Core`.
- **A webhook delivery now waits for the subscriber no longer than the subscription's `timeoutMs`.** The value was
  stored and returned by the management API but not applied: every attempt waited up to the transport's own
  default, 30 seconds over http. A subscriber that answers later than `timeoutMs` (default 5000) is now a failed
  attempt and is retried by the subscription's `maxAttempts` and `retryBackoffMs`. Packages: `redb.Identity.Core`.
- **Updating a webhook subscription with `PUT /api/v1/identity/webhooks/{id}` works.** Every such request was refused
  with `400 validation_error` ("Body must be an UpdateWebhookSubscriptionRequest"); a subscription could only be
  deleted and created again. The fields sent are changed now, the others are left as they were. Packages: `redb.Identity.Core`.
- **An unreadable HTTP Basic client credential on the token endpoint gets 401 `invalid_client` instead of a 500.** A
  Basic value that is not base64 used to be answered with 500 and the text "An unexpected error occurred while
  processing the request". It is now answered with 401 `invalid_client`, also on introspection and revocation. Packages: `redb.Identity.Core`, `redb.Identity.Http`.
- **A failed notification mail no longer writes the recipient address to the error log.** The log line names the
  template and the mail endpoint; the address, which is personal data, is left out. Packages: `redb.Identity.Core`.
- **Expired idempotency records are deleted.** They were ignored by the cache but stayed in the database; the hourly
  timer route `identity-idempotency-cleanup` now deletes them in batches (`Identity:IdempotencyCleanupInterval`,
  `Identity:IdempotencyCleanupBatchSize`). Packages: `redb.Identity.Core`, `redb.Identity.Contracts`.
- **The admin MFA endpoints accept the granular MFA scopes.** A token with `identity:mfa:write` may run every
  operation under `/api/v1/identity/mfa` for any user, one with `identity:mfa:read` may read a user's MFA status.
  Before, these endpoints admitted only `identity:manage`. Review which clients hold `identity:mfa:write`: it now
  lets them set up, reset and disable another user's second factor. Packages: `redb.Identity.Core`.
- **`MfaWebAuthnRegistered` and `MfaWebAuthnRevoked` reach the audit from self-service.** Registering or deleting a
  WebAuthn credential through `/api/v1/identity/me/webauthn` recorded only the generic `MfaSelfService:webauthn:*`
  event; it now records the specific one. Packages: `redb.Identity.Core`.
- **`/connect/revocation` answers an error with 400, or 401 for `invalid_client`, instead of 200.** It used to send
  status 200 with the error in the body, so a client that checks only the status took a refused request for a
  revocation; such a client now sees the failure. A valid or unknown token is still answered with 200. Packages: `redb.Identity.Http`.
- **The `demos/grpc-viewer` sample builds again.** `dotnet run` in that folder failed with MSB6004 (`protoc` not
  found under an empty tools path) on every platform: the sample named its target framework in a way that made the
  restore skip the build files of `Grpc.Tools`. Only the sample's project file changed.

## [4.7.4] — 2026-11-18

### Security

- **A blank `DynamicRegistrationInitialAccessToken` now counts as not configured.** An empty or whitespace value
  means open registration, so an anonymous registrant is refused the administrative scopes (`identity:*` other than
  `identity:account`, and `scim`) whatever `DynamicRegistrationAllowedScopes` lists. Check your configuration: to
  require a token for registration set a non-blank value; to turn registration off set `EnableDynamicRegistration` to false. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#dynamic-client-registration-check-the-initial-access-token).

### Changed

- **Released alone on redb 4.7.2, redb.Route 4.7.2 and redb.Tsak 4.7.2.** The images sit on the Tsak 4.7.2 bases.
  The redb-identity-app template still defaults to 4.7.2: set IDENTITY_VERSION=4.7.4 and build the web part with
  --build-arg IDENTITY_IMAGE=ghcr.io/redbase-app/redb-identity-full:4.7.4.
- **Two defaults of the images change.** Dynamic client registration is off: if you register clients through
  `POST /connect/register`, turn it on with `EnableDynamicRegistration` in both `identity.core` and `identity.http` and set
  `DynamicRegistrationInitialAccessToken`. A JAR `request_uri` is fetched only over https and not from private network
  addresses: for a client that hosts request objects on such an address, set `Identity:Jar:RequestUriAllowPrivateNetworkTargets`
  and `Identity:Jar:RequestUriRequireHttps` in `identity.core` back. Upgrade: [UPGRADING.md](UPGRADING.md#image-defaults-from-474).

## [4.7.3] — 2026-11-14

### Changed

- **Released alone on redb 4.7.2, redb.Route 4.7.2 and redb.Tsak 4.7.2.** The images sit on the Tsak 4.7.2 bases.
  The redb-identity-app template still defaults to 4.7.2: set IDENTITY_VERSION=4.7.3 and build the web part with
  --build-arg IDENTITY_IMAGE=ghcr.io/redbase-app/redb-identity-full:4.7.3.

### Fixed

- **On PostgreSQL, the admin password reset and the admin password change work again.** With the default
  max_prepared_transactions = 0 they were rolled back and the caller got 400 "Id is required". The password
  history is now read and written on the route's own connection. Packages: `redb.Identity.Core`.

## [4.7.2] — 2026-11-13

### Changed

- **Built on redb 4.7.2, redb.Route 4.7.2 and redb.Tsak 4.7.2.** The images and archives take the SQLite fix of redb 4.7.2:
  a save repeated after a rolled-back transaction no longer overwrites another object. redb.Identity itself has no change.

## [4.7.1] — 2026-11-11

### Security

- **System.Formats.Cbor is pinned to the patched 9.0.24.** The WebAuthn dependency brought in 9.0.0, which is affected by
  CVE-2026-118747 (denial of service while parsing CBOR). The packages now name the patched version; the server
  archives ship the .NET 10.0.15 runtime, which carries the ASP.NET Core fix for CVE-2026-114147. Packages: `redb.Identity.Core`.

### Changed

- **Built on redb 4.7.1, redb.Route 4.7.1 and redb.Tsak 4.7.1.** The images and archives take the fixes of those
  releases, among them the SQL Server module version that made a start without schema rights fail.

### Fixed

- **On PostgreSQL the loser of a concurrent create is answered 409, not 500.** When two calls created the same
  record at once (the bootstrap administrator's client, a federation provider), the second one hit the unique key
  and was told `server_error`. It now gets `409 duplicate`, as on SQL Server and SQLite. Nothing was written twice. Packages: `redb.Identity.Core`.

## [4.7.0] — 2026-11-06

### Changed

- **Built on redb 4.7.0, redb.Route 4.7.0 and redb.Tsak 4.7.0.** The images and archives take the additions of those
  releases; redb.Identity itself has no change. Nothing to do on your side.

### Deprecated

- **.NET 8 and .NET 9 targets end with 4.7.** Microsoft's support for both ends on 10 November 2026, so 4.7.0 is the
  last release whose packages target them; from 4.8.0 the packages target .NET 10 and later. The images already run on
  .NET 10 and do not change. Fixes on the 4.7.x line are still built for .NET 8, 9 and 10 while those lines can be built
  without known vulnerabilities. Move projects that reference the packages to .NET 10 before taking 4.8.

## Earlier versions

Earlier releases are archived by line in [changelog/](changelog/): [4.6.x](changelog/CHANGELOG-4.6.x.md), [4.5.x](changelog/CHANGELOG-4.5.x.md), [4.4.x](changelog/CHANGELOG-4.4.x.md), [4.3.x](changelog/CHANGELOG-4.3.x.md), [4.2.x](changelog/CHANGELOG-4.2.x.md), [4.1.x](changelog/CHANGELOG-4.1.x.md), [4.0.x](changelog/CHANGELOG-4.0.x.md), [3.x](changelog/CHANGELOG-3.x.md), [1.x](changelog/CHANGELOG-1.x.md).
