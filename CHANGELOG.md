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

## [4.4.2] — 2026-10-23

### Changed

- **The `backend`, `managed` and `full` Dockerfiles build without `--build-arg TSAK_VERSION`.** The base Tsak image
  defaults to the Tsak release it was built with, and Docker no longer warns about an empty base image name. `publish/docker/DOCKER.md` now
  describes the 4.4 build: .NET 10 SDK, Tsak base images of the same release, `-net10` tags.

## [4.4.1] — 2026-10-21

### Changed

- **Rebuilt on redb.Route 4.4.1.** No changes of its own: the packages, images and archives are built on redb.Route 4.4.1, which fixes `seda:` after a context restart. 4.4.0 was withdrawn on the day of release.

## [4.4.0] — 2026-10-21

> **Withdrawn on the day of release because of the seda restart bug in redb.Route; use 4.4.1.**

### Breaking

- **`resource` (RFC 8707) is validated** on `/connect/authorize`, `/connect/par` and token exchange: an absolute URI
  listed in a scope's `Resources`, with the client's `rsrc:<resource>` permission. OpenIddict 6 ignored it. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#resource-parameter).
- **JWT client assertions (`private_key_jwt`, `client_secret_jwt`) follow draft-ietf-oauth-rfc7523bis**, as OpenIddict
  7 requires: the assertion must have the `typ` header `client-authentication+jwt` and the issuer as its `aud`, for every
  endpoint. An assertion typed plain `JWT` or aimed at an endpoint URL is rejected with `invalid_client`. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#client-assertions-private_key_jwt-client_secret_jwt).
- **A resource server that validates Identity's DPoP-bound access tokens with OpenIddict.Validation 7 fails on them**
  (internal error ID2196: OpenIddict 7 checks `cnf` and knows only the certificate-bound form, not the DPoP `jkt`),
  also in front of `redb.Identity.Resource.Dpop`. Skip OpenIddict's proof-of-possession check for tokens whose `cnf`
  holds only `jkt` and check the DPoP proof yourself, as Identity does for its own endpoints. Packages: `redb.Identity.Resource.Dpop`. Upgrade: [UPGRADING.md](UPGRADING.md#dpop-bound-access-tokens-at-third-party-resource-servers).

### Security

- **Token exchange (RFC 8693) runs on OpenIddict's built-in grant and checks who calls it**: a token bound to a
  client can no longer be exchanged by an unrelated one, and a token of a disabled or deleted user is rejected. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#openiddict-7).

### Changed

- **OpenIddict 7.7** (was 6.3), Microsoft.Extensions and ASP.NET Core 10.0.13, Microsoft.IdentityModel 8.23.0.
  Existing sessions survive the upgrade: tokens issued by 6.3 keep validating. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#openiddict-7).
- **`compose.managed.yml` and `compose.full.yml` mount the volume `dp_keys` on `/root/.aspnet/DataProtection-Keys`** for
  the key rings of the Tsak worker and dashboard. A 4.3 container without that volume: copy its ring out with `docker cp`
  and import it on the first start of 4.4 with `Identity:DataProtection:ImportKeysFromPath`. Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#dataprotection-key-ring).
- **The `redb-identity-web` image runs as the non-root `app` user (uid 1654)** instead of root. Its state lives on named
  volumes owned by that user; a host directory mounted on `/app/keys` or `/app/logs` instead must be writable by uid 1654.
  The `backend`, `managed` and `full` images still run as root, like the Tsak images they are built on. Packages: `redb.Identity.Web`.

### Fixed

- **The server's DataProtection key ring is stored in redb, as documented.** Up to 4.3 it stayed in the file system, so
  a container recreated without that directory did not start and each cluster node had a ring of its own. The first
  start of 4.4 imports the old file ring into redb once; signing keys, TOTP secrets and sessions stay valid. Packages: `redb.Identity.Core`, `redb.Identity.DataProtection`, `redb.Identity.Http`. Upgrade: [UPGRADING.md](UPGRADING.md#dataprotection-key-ring).
- **Identity Web keeps its sessions and file log across a recreated container.** New settings
  `Identity:DataProtectionKeysPath` and `Identity:LogsPath`; the `redb-identity-web` and `redb-identity-full` images set
  them to the volumes `web_keys` and `web_logs` of their compose files. Before, every recreated container signed all users out. Packages: `redb.Identity.Web`.

## Earlier versions

Earlier releases are archived by line in [changelog/](changelog/): [4.3.x](changelog/CHANGELOG-4.3.x.md), [4.2.x](changelog/CHANGELOG-4.2.x.md), [4.1.x](changelog/CHANGELOG-4.1.x.md), [4.0.x](changelog/CHANGELOG-4.0.x.md), [3.x](changelog/CHANGELOG-3.x.md), [1.x](changelog/CHANGELOG-1.x.md).
