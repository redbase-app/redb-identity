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

## [4.6.0] — 2026-11-03

### Fixed

- **An authorization request sent as POST no longer loses its parameters at the login page.** When the user had no
  session yet, `POST /connect/authorize` sent the browser to the login page without the request, and after login the
  server answered "The mandatory 'client_id' parameter is missing". The login and consent pages now return to the same
  request, including `client_id` with `request_uri` for pushed requests. Nothing to change on the client side. Packages: `redb.Identity.Http`.

## Earlier versions

Earlier releases are archived by line in [changelog/](changelog/): [4.5.x](changelog/CHANGELOG-4.5.x.md), [4.4.x](changelog/CHANGELOG-4.4.x.md), [4.3.x](changelog/CHANGELOG-4.3.x.md), [4.2.x](changelog/CHANGELOG-4.2.x.md), [4.1.x](changelog/CHANGELOG-4.1.x.md), [4.0.x](changelog/CHANGELOG-4.0.x.md), [3.x](changelog/CHANGELOG-3.x.md), [1.x](changelog/CHANGELOG-1.x.md).
