# redb.Identity

> **A transport-agnostic OAuth 2.1 / OpenID Connect server for the redb ecosystem.**
> Built on [OpenIddict](https://documentation.openiddict.com/) and [redb.Route](https://github.com/redbase-app/redb-route). Every endpoint is a `direct-vm://` route — call it over HTTP, gRPC, RabbitMQ, SignalR, or **straight from another in-process module with zero network overhead**. Ships as `.tpkg` packages for [redb.Tsak](https://github.com/redbase-app/redb-tsak). REDB-backed, cluster-ready, standards-compliant.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-purple)](https://dotnet.microsoft.com)
[![Tests](https://img.shields.io/badge/tests-1767%20passing%20(PG%20%7C%20MSSQL%20%7C%20SQLite)-brightgreen)](#testing)
[![Providers](https://img.shields.io/badge/storage-PostgreSQL%20%7C%20MSSQL%20%7C%20SQLite-336791)](#provider-matrix-zero-code-changes-between-rows)
[![Status](https://img.shields.io/badge/status-1.0.1-orange)](#)
[![OIDC](https://img.shields.io/badge/OpenID_Connect-Core_1.0-1F4E79)](#openid-connect)
[![OAuth](https://img.shields.io/badge/OAuth-2.1_%2B_RFC_6749-4A148C)](#oauth-2x-core)
[![DPoP](https://img.shields.io/badge/DPoP-RFC_9449-1565C0)](#oauth-2x-core)
[![PAR](https://img.shields.io/badge/PAR-RFC_9126-1565C0)](#oauth-2x-core)
[![DCR](https://img.shields.io/badge/DCR-RFC_7591%2F7592-1565C0)](#oauth-2x-core)
[![SCIM](https://img.shields.io/badge/SCIM-2.0_(RFC_7643%2F7644)-2E7D32)](#scim-20-rfc-7643--7644)
[![FIDO2](https://img.shields.io/badge/FIDO2-WebAuthn_L2-006064)](#mfa)
[![Engine](https://img.shields.io/badge/engine-OpenIddict-512BD4)](#)
[![Runtime](https://img.shields.io/badge/runtime-redb.Route-FF6F00)](#)

---

## TL;DR

| If you want… | redb.Identity gives you… |
|---|---|
| A full OIDC / OAuth 2.1 server without ASP.NET coupling | A `direct-vm://`-only core: `token`, `authorize`, `userinfo`, `introspect`, `revoke`, `jwks`, `.well-known/openid-configuration`, PAR, Device Code, Dynamic Registration. |
| To call Identity from another in-process module **with no HTTP** | `To("direct-vm://identity-token")` from your own `RouteBuilder`. Zero serialization, zero loopback, zero TLS handshake, same exchange. |
| HTTP / gRPC / RabbitMQ / SignalR endpoints | Drop in the matching facade `.tpkg`. Each facade is a thin transport bridge — no business logic. |
| A drop-in user / group / scope / client / consent / audit / session store | Built-in storage via [redb.Core](https://github.com/redbase-app/redb) typed `*Props` objects. Code-first schemes, no migrations. |
| Multi-instance / cluster deployment | DataProtection key-ring + signing keys shared through redb object store. Cleanup timers run leader-only via `.Cluster(true)`. |
| Modern MFA | TOTP (RFC 6238) + SMS/Email OTP + WebAuthn (FIDO2) + Recovery codes. |
| Self-service for end users | `/me/profile`, `/me/sessions`, `/me/mfa`, `/me/webauthn`, `/me/consents`, `/me/federated`. |
| Federation | OIDC / GitHub external providers, stored as redb props objects, admin CRUD. |
| Backchannel logout that works across replicas | RFC 8417-style revoked-SID list (`/revoked-sids/add` + `/since`) + push-and-poll fallback. |
| SCIM 2.0 provisioning | Users + Groups + Bulk endpoints (RFC 7644). |
| RFC compliance | OIDC Core, OAuth 2.1, RFC 7662 (Introspection), RFC 7591/7592 (DCR), RFC 8628 (Device Code), RFC 9126 (PAR), RFC 9449 (DPoP), RFC 8417 / OIDC Backchannel Logout. |

**Not on NuGet yet.** The project is in active development; this README documents what is shipped today inside the source tree. NuGet packages and versioning will land with the public release.

---

## Why redb.Identity exists

Most .NET Identity products force one of three uncomfortable choices:

1. **ASP.NET-bound stacks** (Duende IdentityServer, ASP.NET Identity Core) — every endpoint is an HTTP middleware. Want to call `token` from a Worker Service or a message bus consumer? You have to spin up an HTTP listener and loopback. Want to test the issuance pipeline in isolation? You need `WebApplicationFactory`.
2. **Heavy IAM platforms** (Keycloak, Auth0, Okta) — full-featured, but standalone services with their own runtime, their own admin UI, their own database, their own configuration model, and their own deployment story. Multi-tenant, but not embeddable.
3. **Roll your own** — and re-implement OAuth Code+PKCE, refresh-token rotation, consent storage, session revocation, MFA replay protection, JWKS rotation, key-ring sharing across replicas, RFC 8417 backchannel logout — for the third time this decade.

redb.Identity is the missing fourth option: **the IS engine is just a set of `direct-vm://` routes**. The transport is your choice — and "no transport, just call it from the next module over" is a first-class deployment mode. You get the standards conformance and the storage model of a full IS server, but you wire it into your topology the same way you wire any other redb.Route pipeline.

| | ASP.NET-bound IS (Duende, OpenIddict samples) | redb.Identity | Standalone IAM (Keycloak / Auth0) |
|---|---|---|---|
| Call `token` from another in-process module | Loopback HTTP | **`To("direct-vm://identity-token")`** — same exchange, zero copy | Network hop |
| Add a new transport (gRPC, MQ, SignalR) | Rewrite endpoints as gRPC services / consumers | Add a facade `.tpkg`, point it at `direct-vm://` | Vendor adapter (if it exists) |
| Replace HTTP with RabbitMQ entirely | Major refactor | **Drop the HTTP facade. Keep Core.** | Not possible |
| Storage | Custom EF Core schema + migrations | redb `RedbObject<TProps>` — code-first, no migrations | Vendor schema, vendor migrations |
| Multi-replica key sharing | DIY DataProtection persistence + JWKS rotation | Built-in: redb-backed key-ring + signing key store | Built-in (vendor-specific) |
| Embeddable in a Tsak worker | No | **Yes — as one or two `.tpkg` packages** | No |
| License | Mixed (Duende: commercial) | Apache 2.0 | Mixed |

---

## The killer feature: in-process direct-vm calls

Every public endpoint in Identity is registered on a `direct-vm://identity-*` route. `direct-vm` is redb.Route's in-process, cross-`RouteContext`, **zero-copy synchronous** transport. Three consequences fall out for free:

### 1. Other Tsak modules in the same worker call Identity with no network at all

```csharp
// Inside another .tpkg module loaded into the same Tsak worker
public class CheckoutRoutes : RouteBuilder
{
    protected override void Configure()
    {
        From("rabbitmq:checkout.orders")
            // Need a service-account access token to call a downstream API?
            // Just hit Identity's token endpoint inline — same process, no socket.
            .Process(async (e, ct) =>
            {
                var token = await e.Context.RequestBody<TokenResponse>(
                    IdentityEndpoints.Token,                // "direct-vm://identity-token"
                    new { grant_type = "client_credentials", client_id = "checkout-svc", ... });
                e.In.SetHeader("Authorization", $"Bearer {token.AccessToken}");
            })
            .To("http://pricing-api/quote");
    }
}
```

No HTTP listener. No TLS handshake. No JSON over the loopback. The exchange flows straight from your route into the Identity processor and back, in the same thread, with the same `IExchange` instance. Total cost: a method call plus the existing OpenIddict pipeline work.

### 2. Facades are pure transport adapters — pick the ones you need

```csharp
// HTTP facade — included
From(Http.From("0.0.0.0:5000"))
    .RedbController<TokenController>();                  // POST /connect/token
    // ↓ The controller's only job is:
    //   exchange.To(IdentityEndpoints.Token)           // direct-vm://identity-token

// gRPC facade (planned) — same pattern
From(Grpc.Server("0.0.0.0:5001/IdentityService"))
    .Filter(e => e.In.GetHeader("grpc.method") == "Token")
    .To(IdentityEndpoints.Token);

// RabbitMQ RPC facade (planned)
From("rabbitmq:identity.rpc.token")
    .InOut()
    .To(IdentityEndpoints.Token);
```

Adding a new transport never touches Core. **There is no business logic in the facades to break.** Removing a transport is `rm facade.tpkg`.

### 3. Standards-bound flows that need a browser still get one — only those

The only OAuth interaction that fundamentally requires a browser is the **authorization-code redirect** (and its sibling, the device-code verification URL). Every other endpoint — `token`, `refresh_token`, `introspect`, `revoke`, `userinfo`, `device_code` request, management API, MFA verify, SCIM — is transport-neutral and works perfectly over gRPC, AMQP, MQ, or a direct call.

| Flow / endpoint | Needs HTTP + browser | Works on any transport |
|---|---|---|
| `client_credentials` (M2M) | — | ✅ |
| `authorization_code` — redirect to `/authorize` | ✅ | — |
| `authorization_code` — `code → token` exchange | — | ✅ |
| `refresh_token`, `revoke`, `introspect`, `userinfo` | — | ✅ |
| `device_code` — initial request | — | ✅ |
| `device_code` — user verification URL | ✅ | — |
| Management API, SCIM 2.0, audit query | — | ✅ |

---

## Architecture

### Two contexts, hosted in one Tsak worker

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                Tsak worker                                    │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  RouteContext "identity"   ← redb.Identity.Core.Module.tpkg              │ │
│  │  ────────────────────────────────────────────────────────────────────── │ │
│  │  • IdentityCoreRouteBuilder — ~50 direct-vm:// routes                   │ │
│  │  • OpenIddict server pipeline (token, authorize, userinfo, ...)         │ │
│  │  • redb stores: Users, Apps, Scopes, Tokens, Sessions, Audit, ...      │ │
│  │  • DataProtection key-ring  (RedbXmlRepository)                         │ │
│  │  • Signing keys             (EavSigningKeyStore — RSA 2048, encrypted)  │ │
│  │  • MFA: TOTP / SMS-Email OTP / WebAuthn / Recovery codes                │ │
│  │  • Cleanup timers (.Cluster(true) → leader-only in a cluster):          │ │
│  │     identity-token-cleanup  /  -session-cleanup                          │ │
│  │     identity-mfa-otp-cleanup  /  -revoked-sids-cleanup                  │ │
│  │     identity-mfa-webauthn-challenge-cleanup                             │ │
│  │  • XML key-ring refresh (NOT cluster-gated — every replica refreshes)   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                            ▲                                                  │
│           direct-vm:// (synchronous, in-process, cross-context)               │
│                            │                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  RouteContext "identity.http"  ← redb.Identity.Http.tpkg                 │ │
│  │  ────────────────────────────────────────────────────────────────────── │ │
│  │  • Kestrel listener  →  redb.Route.Http  →  RedbController dispatcher   │ │
│  │  • Controllers: ApplicationsController, UsersController, MfaController, │ │
│  │                 SessionsController, RevokedSidsController, ScimUsers,   │ │
│  │                 MeProfileController, MePasswordController, ...          │ │
│  │  • OIDC paths: /connect/token, /authorize, /userinfo, /introspect, ... │ │
│  │  • Management API: /api/v1/identity/* (identity:manage scope)           │ │
│  │  • Self-service: /me/* (identity:account scope)                         │ │
│  │  • SCIM 2.0: /scim/v2/Users, /Groups, /Bulk                             │ │
│  │  • Cross-context brokers: CORS check, post-logout validate, MFA state   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  Other Tsak modules (your code)                                          │ │
│  │  ────────────────────────────────────────────────────────────────────── │ │
│  │  • Call IdentityEndpoints.Token / .Userinfo / .ManageUsers / ...        │ │
│  │    via direct-vm:// directly — no HTTP needed                            │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                        ┌────────────────────────────────────┐
                        │  redb store (Postgres / MSSQL / SQLite)│
                        │  - Users, Groups, Apps        │
                        │  - Tokens, Authorizations     │
                        │  - Sessions, MFA, Federation  │
                        │  - DataProtection keys, JWKS  │
                        │  - Audit trail (H9)           │
                        │  - Idempotency cache (E2)     │
                        └───────────────────────────────┘
```

### Project-reference isolation (Phase 8)

```
redb.Identity.Http  ─project-ref→  redb.Identity.Contracts          ✅
redb.Identity.Http  ─project-ref→  redb.Identity.DataProtection     ✅
redb.Identity.Http  ─project-ref→  redb.Identity.Core               ❌ FORBIDDEN
```

The HTTP facade compiles **without seeing a single type from Identity.Core**. It only sees:

- Wire DTOs and endpoint constants (`redb.Identity.Contracts`)
- The shared XML key repository (`redb.Identity.DataProtection`)
- A few SPI interfaces (`IMfaStateInspector`, `IRegisteredClientOriginRegistry`, `IIdentityClient`)

This is what makes the `.tpkg` story honest: the two packages are independently buildable, independently versionable, and Core's internal types never leak across the ABI boundary. CI fails the build if a `using redb.Identity.Core;` shows up anywhere under `redb.Identity.Http/`.

### Anatomy of a token request — three transports, one pipeline

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Caller                                                                    │
├────────────────────────────────────────────────────────────────────────────┤
│  Browser:   POST /connect/token  (form-encoded)                            │
│  In-proc:   exchange.To("direct-vm://identity-token")                      │
│  Future:    grpc client.Token(request) — same direct-vm under the hood     │
└────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Transport facade (only for non-direct-vm callers)                         │
│  HTTP:  HeaderBridge → CorsCheck → AuthScope → To("direct-vm://identity…") │
└────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  IdentityCoreRouteBuilder.tokenRoute  (RouteId: identity-token)            │
│                                                                            │
│  WithRedbTx(...)                  ← E1: atomic write boundary              │
│    .Process(trustedProxy)         ← C2: sanitize X-Forwarded-For           │
│    .Process(perIpThrottle)        ← C1: per-IP rate limit (optional)       │
│    .OnException<InvalidOperation> ← RFC 6749 error mapping                 │
│    .Throttle(clientId, ...)       ← per-client token bucket                │
│    .Traced("identity.token-request")                                       │
│      .Metered(...,                                                         │
│        new TokenEndpointProcessor(handler, timeProvider))                  │
│        ↑                                                                   │
│        OpenIddict server pipeline                                          │
│        ↑                                                                   │
│        redb stores (RedbTokenStore, RedbApplicationStore, ...)             │
│    .EndTraced()                                                            │
│    .WireTap("direct-vm://identity-events")  ← H9: audit + multicast        │
└────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                  { access_token, refresh_token, expires_in, ... }
```

The same `TokenEndpointProcessor` runs whether the call came in over HTTP, gRPC, RabbitMQ, or a direct-vm call from the next module. **One pipeline, one set of tests, one audit trail.**

---

## Project structure

```
redb.Identity/
├── src/
│   ├── redb.Identity.Core/             OAuth 2.1 / OIDC engine — OpenIddict + processors
│   │                                   + redb stores + MFA + WebAuthn + federation
│   │                                   + DataProtection + signing-key store
│   │                                   (~50 direct-vm:// route registrations)
│   ├── redb.Identity.Core.Module/      Thin Tsak entry point (InitRoute.main),
│   │                                   lifecycle listeners, child SP build
│   ├── redb.Identity.Contracts/        Wire DTOs (System.Text.Json only),
│   │                                   endpoint URIs, route IDs, feature flags
│   ├── redb.Identity.Http/             HTTP facade — Kestrel + RedbControllers,
│   │                                   project-ref-isolated from Core (Phase 8)
│   ├── redb.Identity.DataProtection/   RedbXmlRepository — ASP.NET DP keys in redb
│   ├── redb.Identity.Resource.Dpop/    RFC 9449 DPoP resource-server validation
│   ├── redb.Identity.Ldap/             LDAP external provider + sync (optional)
│   ├── redb.Identity.Client/           Typed C# SDK — IIdentityClient, partial classes
│   │                                   per area (Users, Apps, MFA, SCIM, Audit, …)
│   └── redb.Identity.Web/              Reference BFF + Blazor admin UI
│                                       (only refs Contracts + Client — HARDLINE)
├── tests/                              1767 passing / 1 skipped on PG · MSSQL · SQLite
│   ├── redb.Identity.Tests/            Unit + integration (multi-provider harness)
│   ├── redb.Identity.Client.Tests/     SDK transport contract tests
│   └── redb.Identity.Web.Tests/        BFF smoke acceptance
├── demos/                              ~55 live-server RFC-conformance probes + run_all.ps1
├── scripts/
│   └── pack-tpkg.ps1                   Build + pack both .tpkg into Tsak Worker/Libs
├── doc/                                Architecture notes, RFC mappings, sprint plans (internal — not published)
├── README.md                           This file
└── Directory.Build.props
```

---

## Endpoint catalogue

**44 HTTP endpoints across 5 surfaces.** Every protocol endpoint (`/connect/*`) is *also* registered on `direct-vm://identity-*` for zero-network in-process calls — see [IdentityEndpoints.cs](src/redb.Identity.Contracts/Routes/IdentityEndpoints.cs).

### OAuth 2.1 / OIDC protocol surface (`/connect/*`, `/.well-known/*`)

Wired in [HttpFacadeRouteBuilder.cs](src/redb.Identity.Http/HttpFacadeRouteBuilder.cs).

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/connect/token` | POST | `client_credentials` / `password` / `refresh_token` / `device_code` | OAuth 2.1 token endpoint |
| `/connect/authorize` | GET, POST | session cookie | Authorization endpoint (browser redirect) |
| `/connect/par` | POST | `client_credentials` | Pushed Authorization Request (RFC 9126) |
| `/connect/userinfo` | GET, POST | Bearer | OpenID Connect userinfo |
| `/connect/introspect` | POST | `client_credentials` | RFC 7662 token introspection |
| `/connect/revocation` | POST | `client_credentials` | RFC 7009 token revocation |
| `/connect/logout` | GET, POST | session cookie (optional) | OIDC RP-Initiated Logout |
| `/connect/register` | POST | Bearer (optional) | RFC 7591 Dynamic Client Registration |
| `/connect/register/{client_id}` | GET, PUT, DELETE | Bearer | RFC 7592 DCR Management |
| `/connect/deviceauthorization` | POST | `client_credentials` | RFC 8628 Device Authorization |
| `/connect/device/verify` | POST | anonymous | RFC 8628 §3.3 end-user verification |
| `/.well-known/openid-configuration` | GET | anonymous | OIDC Discovery 1.0 |
| `/.well-known/oauth-authorization-server` | GET | anonymous | RFC 8414 metadata |
| `/.well-known/jwks` | GET | anonymous | JSON Web Key Set |

### Admin REST (`/api/v1/identity/*`) — requires Bearer + `identity:manage` scope

| Path | Method | Purpose | Source |
|---|---|---|---|
| `/applications` (+ `/{id}/rotate-secret`) | GET/POST/PUT/DELETE | OAuth client CRUD + secret rotation | [ApplicationsController.cs](src/redb.Identity.Http/Controllers/ApplicationsController.cs) |
| `/users` (+ `/search`, `/{id}/change-password`) | GET/POST/PUT/DELETE | User management | [UsersController.cs](src/redb.Identity.Http/Controllers/UsersController.cs) |
| `/groups` (+ `/{id}/children`, `/members`, `/move`) | GET/POST/PUT/DELETE | Hierarchical groups & membership | [GroupsController.cs](src/redb.Identity.Http/Controllers/GroupsController.cs) |
| `/scopes` | GET/POST/PUT/DELETE | OAuth scope catalogue | [ScopesController.cs](src/redb.Identity.Http/Controllers/ScopesController.cs) |
| `/claim-mappers` | GET/POST/PUT/DELETE | Declarative claim mapping rules (H5) | [ClaimMappersController.cs](src/redb.Identity.Http/Controllers/ClaimMappersController.cs) |
| `/claim-scopes` (+ `/assignments`) | GET/POST/PUT/DELETE | Reusable Client Scope bundles + per-app assignment | [ClaimScopesController.cs](src/redb.Identity.Http/Controllers/ClaimScopesController.cs) |
| `/audit` | GET | Audit log query (H9) | [AuditController.cs](src/redb.Identity.Http/Controllers/AuditController.cs) |
| `/tokens` | GET/POST/DELETE | Token lifecycle management | [TokensController.cs](src/redb.Identity.Http/Controllers/TokensController.cs) |
| `/consents` | GET/DELETE | User-consent admin | [ConsentsController.cs](src/redb.Identity.Http/Controllers/ConsentsController.cs) |
| `/sessions` | GET/POST/DELETE | Admin session control | [SessionsController.cs](src/redb.Identity.Http/Controllers/SessionsController.cs) |
| `/mfa` | GET/POST/DELETE | Admin MFA lifecycle | [MfaController.cs](src/redb.Identity.Http/Controllers/MfaController.cs) |
| `/federation-providers` | GET/POST/PUT/DELETE | External IdP CRUD (H8, redb-stored) | [FederationProvidersController.cs](src/redb.Identity.Http/Controllers/FederationProvidersController.cs) |
| `/revoked-sids` | GET/POST | W6-0 backchannel revoked-SIDs delta feed | [RevokedSidsController.cs](src/redb.Identity.Http/Controllers/RevokedSidsController.cs) |

### Self-service (`/me/*`) — requires Bearer + `identity:account` scope

`RequireSelfOrAdminProcessor` guards every `/me/*` route: a token with `identity:account` can never mutate another user's data (B8).

| Path | Method | Purpose | Source |
|---|---|---|---|
| `/me` | GET, PUT | Profile read/update | [MeController.cs](src/redb.Identity.Http/Controllers/MeController.cs) |
| `/me/password` | PUT | Self-service password change | [MePasswordController.cs](src/redb.Identity.Http/Controllers/MePasswordController.cs) |
| `/me/sessions` | GET, DELETE | List/revoke own sessions (SSO) | [MeSessionsController.cs](src/redb.Identity.Http/Controllers/MeSessionsController.cs) |
| `/me/mfa` | GET/POST/DELETE | Self-service MFA enroll/disable | [MeMfaController.cs](src/redb.Identity.Http/Controllers/MeMfaController.cs) |
| `/me/webauthn` | GET/POST/PATCH/DELETE | WebAuthn credentials (FIDO2 / MFA-3) | [MeWebAuthnController.cs](src/redb.Identity.Http/Controllers/MeWebAuthnController.cs) |
| `/me/consents` | GET, DELETE | Consent dashboard | [MeConsentsController.cs](src/redb.Identity.Http/Controllers/MeConsentsController.cs) |
| `/me/federated-identities` | GET/POST/DELETE | Link/unlink external IdP accounts (H8) | [MeFederatedIdentitiesController.cs](src/redb.Identity.Http/Controllers/MeFederatedIdentitiesController.cs) |

### SCIM 2.0 (`/scim/v2/*`)

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/Users` | GET/POST/PUT/PATCH/DELETE | Bearer + `scim` scope | RFC 7644 §3.2–3.5 |
| `/Groups` | GET/POST/PUT/PATCH/DELETE | Bearer + `scim` scope | RFC 7644 §3.2–3.5 |
| `/Bulk` | POST | Bearer + `scim` scope | RFC 7644 §3.7 |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | GET | anonymous | RFC 7643 §5 discovery |

### BFF / convenience (`redb.Identity.Web`)

| Path | Method | Purpose |
|---|---|---|
| `/api/auth/login` | POST | Form-based browser login over BFF |
| `/api/auth/logout` | POST | BFF logout |
| `/account/login` | GET | Back-compat redirect to `/login` |
| `/health` | GET | BFF liveness probe |

---

## Standards compliance

RFC compliance is verified by integration tests (`tests/redb.Identity.Tests/`) — every spec below is wired in code, not aspirational. Section references and §-citations live next to the matching assertions. **40 RFCs are referenced by number across the source tree**; the tables below are exhaustive.

### OAuth 2.x core

| RFC | Spec | Coverage |
|---|---|---|
| **6749** | OAuth 2.0 Authorization Framework | Authorization Code, Client Credentials, Refresh Token, Resource Owner Password Credentials (§4.3, opt-in). RFC 6749 §5.2 error mapping (`invalid_request`/`invalid_grant`/`unsupported_grant_type` → correct HTTP status), §10.5 single-use authorization code (atomic consume), §10.12-style one-time `jti` enforcement. |
| **6750** | Bearer Token Usage | `Authorization: Bearer …`. Query-parameter transport (§2.3) explicitly rejected by management API. |
| **7009** | Token Revocation | Always 200 (§2.1), idempotent re-revocation, refresh-token rotation. |
| **7591** | Dynamic Client Registration | `POST /connect/register`, optional initial access token (§1.2). |
| **7592** | DCR Management Protocol | `GET/PUT/DELETE /connect/register/{client_id}` with `registration_access_token`. |
| **7521 / 7523** | Assertion Framework + JWT Bearer client authentication | `private_key_jwt` — DCR accepts `token_endpoint_auth_method=private_key_jwt` with inline `jwks`; `/connect/token` + `/connect/introspect` authenticate via an RS256-signed client assertion (RFC 7521 §4.2 / RFC 7523 §2.2); advertised in discovery `token_endpoint_auth_methods_supported`. Tampered signature → 401 `invalid_client`. Pinned by `demo_private_key_jwt`. |
| **7636** | PKCE | `S256` mandated; `plain` rejected per OAuth 2.1 / RFC 7636 §4.2. |
| **7662** | Token Introspection | RS256-signed, audience-checked, scope-filtered. |
| **8252** | OAuth 2.0 for Native Apps (BCP 212) | Partial — private-use URI scheme redirect (§7.1), `application_type=native` and `token_endpoint_auth_method=none` accepted by DCR (`Register_NativeApp_SetsApplicationType`). Loopback IP redirect (§7.3) not yet specially handled. |
| **8414** | Authorization Server Metadata | `/.well-known/oauth-authorization-server` (separate from OIDC Discovery, for non-OIDC clients) — verified by `DiscoveryD1ConformanceTests`. |
| **8628** | Device Authorization Grant | `/connect/deviceauthorization`, `/connect/device/verify`, configurable `expires_in` / `interval` (§3.2). |
| **8693** | Token Exchange (opt-in) | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` — delegation + impersonation. |
| **9126** | Pushed Authorization Requests (PAR) | `POST /connect/par`, configurable `Require PAR`, `request_uri` lifetime (§2.2). |
| **9449** | DPoP — Demonstrating Proof-of-Possession | Issuance binding + `DPoP-Nonce` (§8) with HMAC-signed stateless nonces + resource-server validator (`redb.Identity.Resource.Dpop`). Per-`jkt` replay store (`DpopConsumedJtiProps`). |

### OpenID Connect

| Spec | Coverage |
|---|---|
| **OIDC Core 1.0** | Authorization Code + PKCE, ID Token (RS256), Userinfo, claim mappers, `prompt=login\|consent\|none`, `max_age`, `acr_values`. |
| **OIDC Discovery 1.0** | `/.well-known/openid-configuration` — verified by `DiscoveryD1ConformanceTests` against §3 + RFC 8414 §2. |
| **OIDC RP-Initiated Logout 1.0** | `/connect/logout` with `post_logout_redirect_uri` allow-list. |
| **OIDC Backchannel Logout 1.0 / RFC 8417** | SET event sink (`BackchannelLogoutEndpoint`), push to RPs **plus** pull-based revoked-SID list (`/revoked-sids/add` + `/revoked-sids/since?cursor=`) for multi-replica RPs — survives lost RP nodes and partitions. |
| **OIDC Form Post Response Mode** | `response_mode=form_post`. |

### JOSE / JWT cryptography

| RFC | Spec | Coverage |
|---|---|---|
| **7515** | JSON Web Signature | RS256 / ES256 issuance + validation. |
| **7517** | JSON Web Key + JWKS | `/.well-known/jwks` — verified by `JwksHttpContractTests` (RFC 7517 §5 top-level `keys` array). |
| **7518** | JSON Web Algorithms | Algorithm allow-list, asymmetric proofs only (matches RFC 9449 §4.2). |
| **7519** | JSON Web Token | ID tokens, access tokens, DPoP proofs. |
| **7638** | JWK Thumbprint | SHA-256 thumbprint, base64url-encoded — used as DPoP `jkt` per RFC 9449 §10 (`DpopProofValidator.ComputeJktAsync`, `DpopFullCycleTests`). |
| **7800** | PoP Key Semantics for JWTs | `cnf` claim with `jkt` (DPoP proof-of-possession-bound access tokens — `AttachDpopConfirmationClaimHandler`). |
| **8176** | Authentication Method Reference Values | `amr` claim values (`pwd`, `mfa`, `otp`, `face`, `fpt`, `hwk`, etc.) emitted by `IdentityPrincipalBuilder`, plus the standardised `mfa` marker per §2. |

### SCIM 2.0 (RFC 7643 / 7644)

| Surface | Notes |
|---|---|
| `/scim/v2/Users` (CRUD + PATCH) | RFC 7644 §3 |
| `/scim/v2/Groups` (CRUD + PATCH) | RFC 7644 §3 |
| `/scim/v2/Bulk` | RFC 7644 §3.7, partial-success semantics |
| `/scim/v2/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` | Unauthenticated per RFC 7643 §5 |
| Attribute names | Verbatim per RFC 7643 §7 — `IdentityCodecProfilesTests` pins that no naming policy mangles them. |
| Wire serialization | UTF-8 JSON per RFC 8259 §8.1; null attributes omitted per RFC 7644 §3.8. |

### MFA

| RFC / Spec | Coverage |
|---|---|
| **4226** | HOTP — the basis for TOTP (20-byte HMAC-SHA1 key per §4). |
| **6238** | TOTP — with G2 atomicity (`SELECT FOR UPDATE` + `FailedAttempts++`) and G3 replay protection per §5.2 (a code from an already-accepted step is rejected even within skew). Pinned by `TotpReplayTests`. |
| **WebAuthn Level 2 / FIDO2** | Registration + assertion (Fido2NetLib), consumed-challenge cleanup timer, per-credential admin. |
| SMS / Email OTP, Recovery codes | One-shot, marked consumed in the same transaction as session creation. |

### Federation & directory

| Spec | Coverage |
|---|---|
| **OIDC** external providers | Per-provider redb CRUD, `IdentityCookie` state binding. |
| **GitHub OAuth** | First-class adapter on top of the federation provider. |
| **LDAP** (binding) | Search + bind authentication. |
| **RFC 4514** | LDAP DN string representation — CN extraction in `LdapGroupMapper`. |
| **RFC 4515** | LDAP search filter escaping (`LdapExternalUserProviderTests`). |

### HTTP / transport hygiene

| RFC | Coverage |
|---|---|
| **6265 / 6265bis** | `SameSite=Lax\|Strict\|None`; `__Host-` prefix only emitted when `Secure=true` per §4.1.3.2; empty-value cookie treated as delete directive per §5.2.2. Pinned by `CookieDefaultsTests` + `IdentityCookieFormatterTests`. |
| **6585** | Additional HTTP Status Codes — `429 Too Many Requests` + `Retry-After` on rate-limited `/connect/token`, `/connect/par`, `/connect/register` (§4). Pinned by `demo_throttle_rfc6585`. |
| **7230** | HTTP/1.1 Message Syntax — Bearer-header OWS tolerance (`ManagementBearerAuthProcessor`, `BearerParsingD6Tests`). |
| **7231** | HTTP/1.1 Semantics — `Retry-After` delta-seconds format (§7.1.3) emitted by rate-limit responses (`RateLimitMetricsAndRetryAfterTests`). |
| **7232** | HTTP Conditional Requests — `ETag` / `If-Match` → 412 on stale resource (SCIM, per RFC 7644 §3.14 + RFC 7232 §4.2 — `ScimEtagTests`). |
| **7234** | HTTP Caching — `Cache-Control` on metadata endpoints (§5.2). |
| **7235** | HTTP/1.1 Authentication — quoted-string escaping in `WWW-Authenticate` Bearer challenges (§2.1) on userinfo error responses. |
| **7807 / 9457** | `application/problem+json` for HTTP error responses — surfaced by the SDK as `ApiException`. |
| **8259** | UTF-8 JSON wire format — locked `JsonSerializerOptions` profiles in `Contracts`. |

### Cryptographic primitives & hardening (OWASP-aligned)

| Primitive | Coverage |
|---|---|
| **Argon2id** | Password hashing — PHC string format with unpadded base64 per **RFC 7693 §3.5** (`Argon2idPasswordHasher`). |
| **PBKDF2 / RFC 2898** | Secret derivation for MFA shared-secret encryption (`MfaService` via `Rfc2898DeriveBytes.Pbkdf2(SHA-256)`). |
| Recovery codes | One-shot, pepper-encrypted, marked consumed in the same transaction as session creation. |
| Brute-force defense | Per-IP rate limits (C1), per-`(IP+user)` failure ceiling with security-channel logger (E5). |
| Trusted proxies | `X-Forwarded-For` sanitized BEFORE rate-limit / lockout sees it (C2). |
| Idempotency | E2 cache placed AFTER authorization — revoked tokens can't unlock cached responses. |
| Self-vs-admin | `RequireSelfOrAdminProcessor` on every `/me/*` route (B8). |
| Constant-time comparisons | All secret comparisons. |

### Tally

**40 RFCs referenced by number in code** (verified via `grep -rE 'RFC\s*[0-9]{4}'` across `redb.Identity/**/*.cs`):

> 2898, 4226, 4514, 4515, 6238, 6265, 6585, 6749, 6750, 7009, 7230, 7231, 7232, 7234, 7235, 7515, 7517, 7519, 7521, 7523, 7591, 7592, 7636, 7638, 7643, 7644, 7662, 7693, 7800, 7807, 8176, 8252, 8259, 8414, 8417, 8628, 8693, 9126, 9449, 9457
>
> Plus RFC 5737 (TEST-NET-1) used only in LDAP-resilience tests, not on a production code path. RFC 8707 (Resource Indicators) and RFC 9101 (JAR) appear as forward-looking references / advisory client fields, not yet as wired features — see *Not implemented yet* below.

Additional standards referenced without an explicit RFC tag in the source: OIDC Core 1.0, OIDC Discovery 1.0, OIDC RP-Initiated Logout 1.0, OIDC Backchannel Logout 1.0, OIDC Form Post Response Mode, WebAuthn Level 2 / FIDO2, SCIM 2.0, OAuth 2.1 PKCE-required profile, RFC 7515 / 7518 / 7519 (transitively via OpenIddict / `Microsoft.IdentityModel.Tokens`).

### Not implemented yet

None are blockers for the core IS profile; PRs welcome:

- RFC 8705 — Mutual-TLS client authentication + certificate-bound access tokens
- RFC 8707 — Resource Indicators for OAuth 2.0 (referenced as a composition concept; explicit `resource` parameter handling not yet wired)
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (`typ=at+jwt` header — OpenIddict emits default `typ=JWT`)
- RFC 9101 — JAR (JWT-Secured Authorization Request) — the request-object signing / encryption algorithm hints are stored per-client on `ApplicationProps` (advisory), but request objects are not yet consumed
- RFC 9207 — `iss` parameter in authorization response
- RFC 9396 — RAR (Rich Authorization Requests)
- RFC 9470 — Step-up Authentication Challenge
- FAPI 2.0 profile, CIBA, OIDC Federation 1.0

---

## Storage model — built on the REDB object engine

> redb.Identity does not own a database schema. It is built on top of **[REDB](https://github.com/redbase-app/redb)** — the typed object / props storage engine that ships with this repo (`redb.Core`, `redb.Core.Pro`, `redb.Postgres`, `redb.Postgres.Pro`, `redb.MSSql`, `redb.MSSql.Pro`, `redb.SQLite`, `redb.SQLite.Pro`). This is the single biggest architectural difference vs every other .NET identity server.

### What this buys you over an EF-Core-on-tables identity server

| Property | redb.Identity | Typical EF-Core identity server (IdentityServer/OpenIddict-EF/ASP.NET Identity) |
|---|---|---|
| **Storage engines** | Postgres, MSSQL **and** SQLite from one codebase \u2014 swap by changing the provider package the host loads | One provider per build; switching requires re-writing the EF model + migrations |
| **Schema evolution** | No migrations. Add a property to a `*Props` class \u2014 the redb scheme picks it up at next `InitializeAsync` | Generate migration, review SQL, run `Update-Database`, hope rollback works |
| **Custom claims / per-tenant extensions** | `Dictionary<string,string>? CustomClaims` on `UserProps` \u2014 each key becomes a queryable, indexed props row | `jsonb`/`nvarchar(max)` blob; you write your own GIN / computed-column indexes |
| **Multi-provider federation links** | `Dictionary<string, ExternalIdentity>` on User \u2014 native props rows, hot reverse-lookup via `value_string = "{provider}:{sub}"` | One-to-many join table, scaffolding per provider |
| **Hot + cold attribute split** | Hot keys (login, password, status) stay in the relational `_users` table; cold OIDC profile lives in props rows linked by `RedbObject.key = _users._id`. No over-indexed wide rows, no JSON-blob lookups | Either everything in one wide table, or normalised into 8 satellite tables |
| **Multi-tenant data isolation** | `context.GetRedbService("identity")` \u2014 named instance can target a separate DB / schema / connection or share one with your business module | Single `DbContext`; isolation requires separate ASP.NET apps |
| **Caching tier** | `Global*Cache` in `redb.Core` makes scheme + struct lookups O(1) in-process | Bring your own (`IDistributedCache` plumbing) |

### Provider matrix (zero code changes between rows)

| Engine | Open-source package | Pro package | Notes |
|---|---|---|---|
| PostgreSQL 13+ | `redb.Postgres` | `redb.Postgres.Pro` | Battle-tested production target; `LISTEN/NOTIFY`-aware caches in Pro |
| Microsoft SQL Server 2019+ | `redb.MSSql` | `redb.MSSql.Pro` | Full parity for OAuth / SCIM / MFA / WebAuthn; Service Broker hooks in Pro |
| SQLite 3.44+ | `redb.SQLite` | `redb.SQLite.Pro` | Single-file / embedded target for dev, edge and small deployments; same schemes, same contracts |

> Identity references only the `redb.Core` OSS abstraction — **the host worker picks the provider**, Identity code never names one. The **same** test suite (1768 tests) runs green on all three: `Passed: 1767, Skipped: 1, Failed: 0` on PostgreSQL, MSSQL **and** SQLite by flipping a single `REDB_PROVIDER` env-var.

### The 24 typed redb schemes that compose redb.Identity

All defined via `[RedbScheme("identity.*")]` in [src/redb.Identity.Core/Models/](src/redb.Identity.Core/Models/) (+ DataProtection):

| Domain | Schemes |
|---|---|
| OAuth / OIDC core | `identity.application`, `identity.scope`, `identity.token`, `identity.authorization`, `identity.session`, `identity.idempotency_record` |
| Users & groups | `identity.user`, `identity.group`, `identity.group_member`, `identity.password_history` |
| MFA / WebAuthn | `identity.mfa`, `identity.mfa_otp`, `identity.webauthn_consumed_challenge` |
| Federation (H8) | `identity.federation_provider`, `identity.federated_identity` |
| Claims engine (H5) | `identity.claim_mapper`, `identity.claim_scope`, `identity.claim_scope_assignment` |
| DPoP / replay (Z4) | `identity.dpop_consumed_jti` |
| Cluster / cleanup | `identity.revoked_sid` (W6-0), `identity.system_flag` |
| Crypto / DP-keys | `identity.signing_key`, `identity.dp_key` |
| Audit (H9) | `identity.audit_event` |

### What a "table" looks like \u2014 zero migrations, full IntelliSense

```csharp
// src/redb.Identity.Core/Models/UserProps.cs
[RedbScheme("identity.user")]
public class UserProps
{
    // Standard OIDC profile claims
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Picture { get; set; }
    public bool EmailVerified { get; set; }

    // Structured OIDC address (\u00a75.1.1) \u2014 nested redb object, not JSON
    public AddressClaim? Address { get; set; }

    // Arbitrary tenant-specific claims \u2014 each pair becomes its own props row,
    // queryable and indexable without ALTER TABLE.
    public Dictionary<string, string>? CustomClaims { get; set; }

    // Multi-provider federation links \u2014 native props rows, hot reverse lookup
    // uses RedbObject.value_string = "{providerId}:{sub}".
    public Dictionary<string, ExternalIdentity>? ExternalIdentities { get; set; }

    public string? ScimExternalId { get; set; } // RFC 7643 \u00a73.1
}
```

To add a property to your User \u2014 a `LoyaltyTier`, a `ManagerSubject`, a `DepartmentCode` \u2014 you literally just add it to the class. No migration, no DBA call, no downtime. redb reads/writes it the next instant; once it's in production data, queries can filter and project it.

### Bootstrap & isolation

- **Schema sync.** `IdentitySchemaInitListener` walks `[RedbScheme]`-marked types in loaded assemblies on `InitializeAsync()` and reconciles the redb scheme metadata.
- **TOCTOU-safe unique indexes.** `IdentityUniqueIndexesInitListener` applies partial unique indexes that the cleanup races depend on (ClientId, ScopeName, MFA-per-user, idempotency keys, federated `{providerId}:{sub}`).
- **Per-context isolation.** Identity always resolves a **named** redb instance (`"identity"`) \u2014 it can coexist with other modules' redb usage in the same Tsak worker without sharing connections, transactions, or caches. Or, point it at a dedicated DB and your business data never sees an OAuth row.

---

## Cluster-readiness

Identity is designed for N-replica deployments where leadership rotates without coordination across the runtime.

| Concern | Mechanism |
|---|---|
| DataProtection key-ring across replicas | `RedbXmlRepository` — redb-persisted XML keys; every replica refreshes its in-memory snapshot every `XmlRepositoryRefreshInterval` (default 60s). **Not** cluster-gated by design — every node must catch keys rotated by others. |
| OAuth signing keys across replicas | `EavSigningKeyStore` — RSA 2048 PEMs, DataProtection-encrypted at rest, bootstrapped under a distributed lock so only one replica generates the first key. |
| Cleanup timers (tokens / sessions / MFA OTP / WebAuthn challenges / revoked SIDs) | Registered with `.Cluster(true)` — leader-only in a clustered Tsak deployment, silently ignored in standalone. Even without the marker, every cleanup uses `IBackgroundDeletionService` (claim pattern), so concurrent execution is safe — `.Cluster(true)` is belt-and-suspenders + log-noise reduction. |
| MFA atomicity under concurrency | `SELECT FOR UPDATE` on the MFA row + `FailedAttempts++` inside the same transaction (G2). TOTP replay window enforced per RFC 6238 §5.2 (G3). |
| Backchannel logout across replicas | `/revoked-sids/add` writes the revocation; `/revoked-sids/since?cursor=` lets every RP replica pull deltas. Push-and-poll, not push-only — survives lost RP nodes and broken network partitions. |
| OpenIddict per-request scoping | `RedbRouteOpenIddictServerHandler` captures `IServiceScopeFactory` and opens a fresh per-request scope — works correctly under .tpkg child SP isolation (Phase 9g). |

---

## Observability

First-class OpenTelemetry surface, structured security log, and Tsak-aggregated health probes — all wired in-tree, no extra package required.

### Metrics — meter `RedbIdentity`

Consume from any OTel pipeline:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("RedbIdentity"));
```

Defined in [IdentityMetrics.cs](src/redb.Identity.Core/Metrics/IdentityMetrics.cs):

| Instrument | Type | Tags | What it tells you |
|---|---|---|---|
| `identity.login.attempts` | Counter | — | Password login throughput |
| `identity.login.failures` | Counter | `reason` | Bad-password / unknown-user / locked / mfa-required |
| `identity.mfa.verifications` | Counter | `method`, `result` | TOTP / SMS / email / recovery code outcomes |
| `identity.mfa.lockouts` | Counter | `method` | MFA brute-force lockouts triggered |
| `identity.tokens.issued` | Counter | `grant_type`, `token_type` | Tokens minted by OpenIddict |
| `identity.tokens.errors` | Counter | `error` | `invalid_grant`, `invalid_client`, `invalid_dpop_proof`, … |
| `identity.rate_limit.rejections` | Counter | `endpoint`, `key_dimension` | Throttled requests (per-IP / per-client / per-user) |
| `identity.password.verify.duration` | Histogram (ms) | `algorithm` | Hash-verify wall-clock (BCrypt / PBKDF2 / Argon2) — catches CPU regressions |
| `identity.unique_violation` | Counter | `scheme`, `column` | DB unique-index hits (TOCTOU guard fired) |

### Security log channel

All audit-grade events route through a dedicated logger category so SIEM can subscribe without sifting routine logs:

- **Category:** `RedbIdentity.Security`
- **Source:** [IdentitySecurityLog.cs](src/redb.Identity.Core/Security/IdentitySecurityLog.cs)
- **Wired into:** `LoginService`, `MfaService`, `IdentityCoreRouteBuilder`, `BootstrapAdminProcessor`, rate-limit / RBAC rejections (E5)

### Health checks — module `identity`

Surface under Tsak's aggregated `/api/health/{startup,live,ready}`. Defined in [IdentityHealthContributor.cs](src/redb.Identity.Core/Health/IdentityHealthContributor.cs).

| Probe | Healthy when … | Failure semantics |
|---|---|---|
| `db` | `IRedbService.GetDbVersionAsync()` returns non-empty | Unhealthy — storage unreachable |
| `signing-keys` | ≥ 1 signing credential registered with OpenIddict | Unhealthy — token issuance would fail |
| `data-protection` | Active key-ring exposes ≥ 1 key | Degraded — cookies still work on bootstrap key |

---

## Security highlights

| Surface | Defense |
|---|---|
| Token endpoint | Per-IP rate limit (C1) + per-`client_id` throttle (token bucket) + RFC 6749 error mapping |
| Login endpoint | Per-IP rate limit + per-`(IP+username)` failure ceiling with security-channel logger (E5) |
| MFA verify | DB row-lock + `IdempotentConsumer` keyed by `(jti, code)` — defeats retransmit / captured-request replay |
| Recovery codes | One-shot — marked consumed in the same transaction as session creation |
| Self vs admin | `RequireSelfOrAdminProcessor` on every `/me/*` route — a token with `identity:account` can never mutate another user's MFA, password, sessions, or consents (B8) |
| Idempotency | E2 cache placed AFTER authorization so a revoked token cannot unlock cached responses |
| Trusted proxies | `TrustedProxyResolverProcessor` (C2) — `redbHttp.RemoteAddress` is sanitized BEFORE any rate-limit / lockout sees it |
| Password history | Configurable depth, rejects reuse |
| Federation | OIDC + GitHub, secrets server-side, never returned over the wire |
| Audit (H9) | redb sink + optional external multicast (Kafka / Elasticsearch / RabbitMQ / log) — typed payloads, then JSON for external transports |
| DPoP | RFC 9449 — issuance binding + resource-server `redb.Identity.Resource.Dpop` for downstream APIs |
| Secrets | Never in `context.json` — only via Tsak L5 override env-vars (`Tsak__Contexts__identity__Override__Identity__*`) |

Critical-severity findings from internal review (CLU-1 .. CLU-5) are closed and pinned by tests:

- **CLU-1** ✅ Singleton + immutable XML snapshot; per-replica refresh
- **CLU-2** ✅ Per-request scope for OpenIddict handlers
- **CLU-3** ✅ `AllowEphemeralKeys = false` (default) — prod always uses persisted signing keys
- **CLU-4** ✅ All cleanup routes carry `.Cluster(true)` — pinned by `ClusteredRouteMarkingTests`
- **CLU-5** ✅ `LockForUpdateAsync(mfaObjId)` BEFORE `MfaService.VerifyAsync`

---

## Audit event catalogue

**79 typed audit events across 7 categories** — single source of truth in [IdentityAuditEventIds.cs](src/redb.Identity.Contracts/Routes/IdentityAuditEventIds.cs). Every event lands in the `AuditEventProps` redb sink and, if configured, is multicast to Kafka / Elasticsearch / RabbitMQ / log (H9). Plaintext secrets are never persisted to audit — rotations log a `ClientSecretRotated` marker only.

| Category | Count | Examples |
|---|---:|---|
| `authentication` | 4 | `UserLoggedIn`, `UserLoggedOut`, `LoginFailed`, `PasswordChanged` |
| `authorization` | 14 | `TokenIssued`, `TokenRevoked`, `TokenIntrospected`, `AuthorizationGranted`, `ConsentGranted` / `Revoked` / `AllConsentsRevoked`, `DeviceCodeIssued` / `Verified` / `Denied`, `ParRequestAccepted` / `Rejected`, `DpopBindingApplied`, `DpopReplayDetected` |
| `admin` | 22 | `ClientRegistered` / `Updated` / `Deleted` / `SecretRotated`, `Scope*`, `ClaimMapper*`, `ClaimScope*` (+ `Assigned` / `Unassigned`), `User*`, `Group*` (+ `Moved`), `Member*` |
| `federation` | 9 | `FederationChallengeInitiated`, `FederationStateValidationFailed`, `FederatedUserLoggedIn`, `FederatedIdentityLinked` / `Unlinked`, `FederatedEmailConflict`, `FederationProvider*` |
| `mfa` | 11 | `MfaEnrolled`, `MfaDisabled`, `MfaChallengeIssued`, `MfaVerifyFailed`, `MfaRecoveryCodeUsed` / `Downloaded`, `MfaWebAuthnRegistered` / `Asserted` / `Revoked` / `SignCounterAnomaly` |
| `scim` | 9 | `ScimUserCreated` / `Replaced` / `Patched` / `Deleted`, `ScimGroupCreated` / `Replaced` / `Patched` / `Deleted`, `ScimBulkProcessed` |
| `system` | 9 | `SessionRevoked` / `AllSessionsRevoked` / `SessionsPruned`, `SidRevoked` / `RevokedSidsPruned`, `MfaOtpPruned`, `TokenCleanupRan` / `TokensPruned`, `TokensRevokedByUser` |

> Notable security events to wire into your SIEM first: `LoginFailed`, `MfaVerifyFailed`, `MfaWebAuthnSignCounterAnomaly`, `DpopReplayDetected`, `FederationStateValidationFailed`, `FederatedEmailConflict`, `ClientSecretRotated`, `AllSessionsRevoked`, `AllConsentsRevoked`.

---

## Quick start

> Until packages are on NuGet, building from source is the only path. NuGet + Docker images will follow the public release.

### 1. Build

```pwsh
cd redb.Identity
dotnet build redb.Identity.slnx --nologo
```

### 2. Pack the `.tpkg` modules

```pwsh
.\scripts\pack-tpkg.ps1                # produces redb.Identity.Core.Module.tpkg + redb.Identity.Http.tpkg
                                       # and copies both into the Tsak Worker's Libs/ directory
```

Two `.tpkg` files are produced:

| Package | Contains | Loads into Tsak context |
|---|---|---|
| `redb.Identity.Core.Module.tpkg` | Core + Contracts + DataProtection + OpenIddict + Fido2 + Argon2 companion DLLs | `identity` |
| `redb.Identity.Http.tpkg` | HTTP facade — controllers, Kestrel listener, broker SPIs | `identity.http` |

### 3. Configure (`context.json` overrides)

Identity reads its configuration from the merged 5-layer Tsak config under the `Identity` key. A minimal `context.json` for the `identity` Tsak context:

```jsonc
{
  "Identity": {
    "Shared": {
      "Issuer": "https://identity.local/"
    },
    "Features": {
      "EnableScim": true,
      "EnableDeviceCodeFlow": true,
      "EnablePushedAuthorization": true,
      "EnableDynamicRegistration": false
    },
    "TokenCleanupInterval": "01:00:00",
    "SessionCleanupInterval": "01:00:00",
    "RevokedSidsCleanupInterval": "01:00:00",
    "MfaOtpCleanupInterval": "00:15:00",
    "XmlRepositoryRefreshInterval": "00:01:00",
    "WebAuthn": { "Enabled": true, "RpId": "identity.local" }
  }
}
```

Secrets live ONLY in L5 env-vars (never in `context.json`):

```
Tsak__Contexts__identity__Override__Identity__RecoveryCodePepper=...
Tsak__Contexts__identity__Override__Identity__FederationProviders__0__ClientSecret=...
Tsak__Contexts__identity__Override__Identity__Ldap__Providers__0__BindPassword=...
```

### 4. Start the Tsak worker

```pwsh
cd ..\redb.Tsak\src\redb.Tsak.Worker
dotnet run
```

```
[INF] Tsak worker starting…
[INF] Loaded package redb.Identity.Core.Module (1.0.0)
[INF] Loaded package redb.Identity.Http (1.0.0)
[INF] redb.Identity: redb base schema ready (22 scheme types synced)
[INF] redb.Identity: unique indexes bootstrap complete (PostgreSQL) — applied=12 skipped=0
[INF] redb.Identity: DataProtection key-ring snapshot loaded (3 keys)
[INF] context 'identity' started
[INF] context 'identity.http' started, listening on http://0.0.0.0:5000
[INF] Ready
```

### 5. Verify

```bash
curl http://localhost:5000/.well-known/openid-configuration | jq
curl http://localhost:5000/.well-known/jwks | jq
```

### 6. Bootstrap the first admin user (one-shot)

The first admin / first OAuth client is created atomically through a one-time endpoint that self-locks via a `SystemFlag(bootstrap_completed)` sentinel:

```bash
curl -X POST http://localhost:5000/internal/bootstrap-admin \
  -H "Content-Type: application/json" \
  -d '{ "username": "admin", "password": "...", "email": "admin@local" }'
# Second call returns 410 Gone.
```

---

## Runnable demos (`demos/`)

Beyond the xUnit suite, `demos/` holds **~55 self-contained PowerShell probes** that drive a **live** Identity server over its real HTTP surface — one `demo_*.ps1` per protocol contract. They double as executable RFC documentation and as a black-box regression net: each script sets up its own client (via DCR), runs the flow end-to-end, and asserts the wire-level result (status codes, headers, token/JWKS shape, replay rejection, …). Most print an `N/N PASS` line and exit non-zero on the first broken assertion.

A sampling of what they pin (see the directory for the full set):

| Demo | Contract exercised |
|---|---|
| `demo_discovery_jwks.ps1` | OIDC Discovery + JWKS shape, RFC 8414 metadata |
| `demo_client_credentials.ps1` / `demo_password_ropc.ps1` / `demo_authcode_pkce.ps1` | Core grants + PKCE (`S256`) |
| `demo_private_key_jwt.ps1` | `private_key_jwt` client auth (RFC 7521 / 7523) |
| `demo_dpop.ps1` | DPoP proof binding + replay (RFC 9449) |
| `demo_par.ps1` / `demo_par_per_client.ps1` | Pushed Authorization Requests (RFC 9126) |
| `demo_throttle_rfc6585.ps1` | `429 Too Many Requests` + `Retry-After` (RFC 6585) |
| `demo_backchannel_logout.ps1` | OIDC Back-Channel Logout + `logout_token` fan-out |
| `demo_scim.ps1` / `demo_scim_bulk.ps1` / `demo_scim_etag.ps1` | SCIM 2.0 CRUD + Bulk + ETag concurrency (RFC 7643 / 7644) |
| `demo_mfa_totp.ps1` / `demo_mfa_recovery_codes.ps1` | TOTP (RFC 6238) + one-shot recovery codes |
| `demo_federation_e2e.ps1` / `demo_federation_github.ps1` | OIDC + GitHub federation, provision-on-first-login |
| `demo_jwks_rotation.ps1` | Live JWKS key rotation / retire against a running server |
| `demo_roles_registry.ps1` / `demo_claim_definitions.ps1` / `demo_webhooks.ps1` | Roles, declarative claim schema, signed outbound webhooks |

### Run them all

```pwsh
cd redb.Identity\demos
pwsh -File .\run_all.ps1                 # run every demo_*.ps1 in canonical order
pwsh -File .\run_all.ps1 -Only mfa       # only demos whose name matches "mfa"
pwsh -File .\run_all.ps1 -StopOnFail     # bail out on the first failing demo
```

`run_all.ps1` executes each demo in its own `pwsh` child process (a hard failure in one can't abort the rest), streams stdout live, captures a per-demo transcript to `demos/_logs/<demo>.log`, and prints a final pass/fail summary table. Browser-in-the-loop demos (e.g. `demo_device_code.ps1`) are skipped unless `-IncludeInteractive` is passed. Point the demos at a running worker (default `http://localhost:5000`) started per the [Quick start](#quick-start) above.

---

## Typed SDK (`IIdentityClient`)

```csharp
services.AddIdentityClient(options =>
{
    options.BaseUrl = "https://identity.local";
    options.AccessTokenProvider = new ClientCredentialsAccessTokenProvider(
        clientId: "my-svc",
        clientSecret: builder.Configuration["IdentitySvcSecret"]!,
        scopes: ["identity:manage"]);
});

public class UserSync(IIdentityClient identity)
{
    public async Task RunAsync(CancellationToken ct)
    {
        var page = await identity.Users.ListAsync(new UsersListRequest { Limit = 100 }, ct);
        foreach (var u in page.Items)
            await PersistAsync(u, ct);

        // Backchannel revocations — pull deltas since the last cursor
        var since = await identity.RevokedSids.GetSinceAsync(_cursor, ct);
        foreach (var entry in since.Entries) _cache.Apply(entry);
        _cursor = since.NextCursor;
    }
}
```

Partial classes group endpoints by area: `Users`, `Groups`, `Applications`, `Scopes`, `ClaimMappers`, `Federation`, `Sessions`, `Tokens`, `Mfa`, `Audit`, `Account`, `Token`, `Scim`, `Info`, `RevokedSids`.

Two access-token providers ship:

- `ClientCredentialsAccessTokenProvider` — for daemons / CLIs / hosted services
- `HttpContextAccessTokenProvider` — for BFF replay of an end-user's bearer

Every HTTP error is normalized to RFC 7807 `ProblemDetails` and surfaced as `ApiException`.

---

## Reference BFF + admin UI (`redb.Identity.Web`)

A reference Blazor Server app demonstrating the HARDLINE BFF pattern:

- Project references **only** `redb.Identity.Contracts` + `redb.Identity.Client` — no `Identity.Core`, no `Identity.Http`
- All Identity calls go through `IIdentityClient` — **never** a raw `HttpClient`
- OIDC Authorization Code + PKCE, `SaveTokens=true`, `SameSite=Lax`
- Backchannel logout sink + `IRevokedSidsCache` (push + 60s poll fallback for multi-replica RPs)

Pages cover both self-service (`/Me/*`) and admin (`/Admin/*`) surfaces:

| Self-service | Admin |
|---|---|
| Profile, Password, MFA (TOTP), WebAuthn credentials, Sessions, Federated identities, Consents | Users (CRUD + password reset), Groups (tree + members), Applications (CRUD + scopes), Scopes, Claim Mappers, Federation providers, Sessions (revoke single/all), Tokens (prune), Audit (15 event types + JsonViewer), SCIM browser, Settings (health / discovery / JWKS) |

---

## Testing

```pwsh
# default provider (SQLite)
dotnet test redb.Identity\tests\redb.Identity.Tests\redb.Identity.Tests.csproj --nologo

# pick the storage engine with one env-var — the same suite runs on all three
$env:REDB_PROVIDER = "postgres"   # or "mssql" or "sqlite" (default)
$env:REDB_USE_PRO  = "true"       # Pro tier (ChangeTracking); "false" for Free
dotnet test redb.Identity\tests\redb.Identity.Tests\redb.Identity.Tests.csproj --nologo
```

**The full suite is green on all three redb providers from one identical codebase:**

```
Test Run Successful.
Total tests: 1768
     Passed: 1767
    Skipped: 1
```

…on **PostgreSQL**, **Microsoft SQL Server** and **SQLite** alike (the single skip is a known PostgreSQL-specific test-host teardown probe). Provider selection is a runtime env-var; no Identity source changes between rows.

| Project | Count | Notes |
|---|---:|---|
| `redb.Identity.Tests` | **1767 passing / 1 skipped** | Unit + integration; real PostgreSQL / MSSQL / SQLite via `HttpIdentityFixture` for HTTP E2E |
| `redb.Identity.Client.Tests` | 136 passing | SDK transport / serialization contract |
| `redb.Identity.Web.Tests` | 7 passing | BFF smoke acceptance |

Key invariants pinned by tests (non-exhaustive):

- **Cluster-route marking**: only cleanup routes are `.Cluster(true)` (`ClusteredRouteMarkingTests`)
- **Multi-replica key-ring**: two `RedbXmlRepository` instances against the same DB see each other's keys (G1)
- **MFA concurrency**: parallel verify never double-spends a recovery code, atomic `FailedAttempts++` (G2)
- **TOTP replay**: identical code rejected within RFC 6238 §5.2 window (G3)
- **DataProtection at rest**: AES-GCM via DP, not plaintext PEMs (C10)
- **Project-reference isolation**: zero `using redb.Identity.Core;` under `redb.Identity.Http/` (Phase 8)
- **DTO validation boundary**: comprehensive `DtoValidationTests` over every wire DTO

---

## Roadmap (excerpt)

Shipped today: HTTP facade, full management API, SCIM 2.0, MFA (TOTP / SMS / Email OTP / WebAuthn), federation (OIDC + GitHub), backchannel logout (push + pull), DPoP, PAR, DCR, audit (redb sink + multicast).

Planned facades & integrations (same `.tpkg` pattern, no Core changes):

- `redb.Identity.Grpc` — gRPC facade for non-browser flows
- `redb.Identity.Rmq` / `.Amqp` / `.IbmMq` — message-bus RPC facades
- `redb.Identity.SignalR` — push of audit events to subscribed clients
- `redb.Identity.Kafka` — event-only sink (Kafka has no RPC)

NuGet publication, Docker images (Worker + Web stack), and signed release artifacts will follow the public release.

---

## Contributing & license

- License: [Apache 2.0](LICENSE)
- Engine: [OpenIddict](https://documentation.openiddict.com/) (Apache 2.0)
- Runtime: [redb.Route](https://github.com/redbase-app/redb-route)
- Container: [redb.Tsak](https://github.com/redbase-app/redb-tsak)
- Storage: [redb.Core](https://github.com/redbase-app/redb)

Contributions welcome once the repository is public. Until then, internal contribution guide lives in `doc/`.
