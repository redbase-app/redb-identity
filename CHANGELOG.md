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

## [4.5.0] — 2026-10-29

### Breaking

- **A role's scopes reach a token only when the client asks for them.** They used to be added to every token of the
  user for any client, past the client's permissions, so an administrator's sign-in to any application gave it a
  token that administered Identity. Request the scope explicitly. Upgrade: [UPGRADING.md](UPGRADING.md#role-scopes-only-when-the-client-asks-for-them). Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](UPGRADING.md#role-scopes-only-when-the-client-asks-for-them).

### Fixed

- **`Identity:Audit` takes effect when Identity runs as a Tsak module.** The targets the audit events are multicast
  to (Kafka, Elasticsearch, RabbitMQ, a log, a `direct-vm` route), the filter and the switches were ignored there, and
  events reached only the built-in audit table. They are now read from the context configuration. Packages: `redb.Identity.Core`, `redb.Identity.Core.Module`.
- **`Identity:SeedAdmin:Password` takes effect on a database shared with the Tsak dashboard.** In cluster mode the
  dashboard gives the empty `admin` its own default password first, and the configured one was then never applied.
  It now replaces a stored password that is still admin/admin; a password that was changed is left as it is. Packages: `redb.Identity.Core`.
- **The `TokenRevoked` audit event names the token's user.** A revocation at `/connect/revocation` or through the
  token management API now carries the user's id, like `TokensRevokedByUser` does, so a subscriber can act on that
  user alone. A client-credentials token has no user, and its event still carries none. Packages: `redb.Identity.Core`.
- **A group created with a name only works again.** For a member of a group without type and description, the user's
  group list failed with a `NullReferenceException`, and so did reading or updating that group. At sign-in this member
  got no group roles and was refused scopes and applications that require group membership. Nothing to do after
  upgrading. Packages: `redb.Identity.Core`.
- **`compose.managed.yml` and `compose.full.yml` no longer expose the Tsak management API.** It has no API keys in
  these images and answered on a published port 9090; it now listens on 127.0.0.1 inside the container, behind the
  dashboard, and the dashboard's password `TSAK_WEB_ADMIN_PASSWORD` is required instead of the image's admin/admin. Packages: `redb.Identity.Core.Module`.
- **Identity Web no longer warns on every start of the `full` image.** Its first revoked-sessions poll ran before
  the Identity host answered and was then retried only after a full poll interval. While the host is still starting,
  the poll now retries within seconds and logs that at information level; a refused secret still warns at once. Packages: `redb.Identity.Web`.

## Earlier versions

Earlier releases are archived by line in [changelog/](changelog/): [4.4.x](changelog/CHANGELOG-4.4.x.md), [4.3.x](changelog/CHANGELOG-4.3.x.md), [4.2.x](changelog/CHANGELOG-4.2.x.md), [4.1.x](changelog/CHANGELOG-4.1.x.md), [4.0.x](changelog/CHANGELOG-4.0.x.md), [3.x](changelog/CHANGELOG-3.x.md), [1.x](changelog/CHANGELOG-1.x.md).
