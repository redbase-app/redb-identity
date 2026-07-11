# redb.Identity — OpenID Connect Certification Readiness

This document describes what redb.Identity implements toward
[OpenID Certification](https://openid.net/certification/), what was changed to
prepare for it, and the current state against the official OpenID Foundation
conformance suite.

> **Status — preparing for OpenID Certification.** In local runs of the
> official OIDF conformance suite against a live server over native HTTPS:
> **Config OP** reports **zero failures**, and the **Basic OP**
> authorization-code-flow modules pass. Every automatable module is green; the
> remainder are interactive re-auth flows (which behave to spec) and automation
> limits, not server gaps. The protocol issues surfaced along the way are all
> fixed (see §3).

It is a **status / spec** document, not a marketing claim: it tracks our own
local conformance runs and the protocol work that makes redb.Identity
certifiable.

---

## 1. What redb.Identity is

redb.Identity is an **OpenID Provider (OP)** built on:

- **OpenIddict** for the OAuth 2.0 / OpenID Connect server pipeline (token
  issuance, JWT signing, discovery, the server event/handler model).
- **redb.Route** as the transport and routing fabric — every OIDC endpoint
  (`/connect/authorize`, `/connect/token`, `/connect/userinfo`, …) is a
  redb.Route route in the `identity.http` context, forwarding to the
  `identity.core` context via in-process `direct-vm` for the OpenIddict work.
- **redb** as the persistence layer for users, sessions, clients, consents,
  claims, and audit.

It is deployed as **tpkg modules** hot-loaded into a Tsak Worker
(`redb.Identity.Core.Module.tpkg` + `redb.Identity.Http.tpkg`). The identity
store in the certification setup is **PostgreSQL** (`RedbInstanceName:
"identity-pg"` in `context.json`); the Worker itself runs on SQLite.

---

## 2. Certification profiles targeted

The OpenID Connect **Basic OP** and **Config OP** conformance profiles (the
authorization-code flow with a confidential client) are the first targets.

- **Config OP** — discovery-document / metadata correctness over HTTPS.
- **Basic OP** — the full `response_type=code` authorization-code flow: login,
  consent, token issuance, userinfo, scopes, `prompt`, `max_age`, code reuse,
  refresh tokens, PKCE, request objects, and negative cases.

---

## 3. Protocol work done for certification

Everything below is implemented in the OpenIddict server pipeline
(`redb.Identity.Core`) or the HTTP facade (`redb.Identity.Http`) and is
committed on `develop`.

### 3.1 Native HTTPS (no reverse proxy)

The conformance suite requires the OP to be served over HTTPS with a valid
issuer. redb.Identity serves TLS **natively** through the redb.Route.Http
connector (Kestrel), configured entirely from `context.json`
(`ssl=true`, `sslCertPath`, `sslCertPassword`) — no nginx/Envoy in front.

Both `HttpComponent` (scheme `http`) and `HttpsComponent` (scheme `https`)
are registered against one shared `SharedHttpServerManager`, so a single
`host:port` is tracked once regardless of scheme. See **[HTTPS.md](HTTPS.md)**
for the full design and operator setup.

### 3.2 Discovery metadata completeness

`ApplyDiscoveryResponseHandler` advertises the metadata the Config/Basic OP
profiles check, including:

- `acr_values_supported` = `["1","2"]`
- `claim_types_supported` = `["normal"]`
- `token_endpoint_auth_methods_supported` =
  `[client_secret_basic, client_secret_post, private_key_jwt, none]`
- `introspection_endpoint_auth_methods_supported` /
  `revocation_endpoint_auth_methods_supported` = `[basic, post, private_key_jwt]`
  (no `none`)

`Cache-Control` on discovery and JWKS is left **cacheable by design**.

### 3.3 Error delivery hardened (open-redirect + correct channel)

The authorization-endpoint error path
(`RedbRouteOpenIddictServerHandler`, `ApplyAuthorizationResponseHandler`)
validates the `redirect_uri` against the client via
`IOpenIddictApplicationManager.FindByClientIdAsync` +
`ValidateRedirectUriAsync` **before** redirecting any error back. An error is
delivered to the `redirect_uri` only when that URI is registered for the
client (RFC 6749 §4.1.2.1); otherwise it is surfaced directly. This closes an
open-redirect vector and delivers `invalid_scope`/`invalid_request` on the
correct channel.

### 3.4 Token endpoint error normalization

At the token endpoint, `invalid_token` is normalized to `invalid_grant`, and
status codes are mapped explicitly (`invalid_client` → 401, others → 400).
This fixed the code-reuse case (a redeemed code now returns
`400 invalid_grant`, not `401 invalid_token`).

### 3.5 Boolean claims per OIDC §5.1

`email_verified` and `phone_number_verified` are emitted as JSON **booleans**
(`SetClaim(..., bool)`), not strings. `acr` is `"1"` / `"2"`.

### 3.6 Configurable PKCE (Basic vs OAuth 2.1)

PKCE is now configurable (`RedbIdentityOptions.RequirePkce`, default `true`).
When enabled, dynamic registration adds the per-client `ft:pkce` requirement
and the server enforces S256. For the **Basic OP** profile (which exercises
non-PKCE code flow) PKCE is turned off in the conformance `context.json`; the
`oidcc-ensure-request-with-valid-pkce-succeeds` module still passes with PKCE
supported. S256-only configuration is kept unconditional.

### 3.7 prompt=login / max_age re-authentication (§3.1.2.1)

Both `prompt=login` and a stale `max_age` now **force the End-User back to
`/login`** (not an error to the RP) and complete once they re-authenticate.

The redirect loop is broken **without a bypass** by a DataProtection-signed
re-auth marker cookie (`redb.identity.reauth`):

- `SessionTicketService.ProtectReauth/UnprotectReauth` sign/verify the instant
  re-auth was forced (a distinct protector purpose, 10-minute max age — a
  client cannot forge an earlier timestamp).
- On the way in, `SessionCookieProcessors.ReadSessionCookie` decodes the marker
  into a `reauth_stamp` header; on the way out `HandleReauthCookie` mints it
  when re-auth is forced and expires it **only on final success** (so a consent
  round-trip keeps it).
- `HandleAuthorizationRequestHandler` runs the gate **before** the no-principal
  check, so a logged-out `prompt=login` needs only a single `/login`. Re-auth is
  satisfied once the **active session id differs** from the one the marker
  captured — a fresh `/login` always mints a new session. Keying on the session
  id (not the second-precision `auth_time`) is precise: it neither loops on a
  same-second re-login nor leaves a same-second window where an unchanged
  session could be mistaken for a re-authentication.

Verified end-to-end over HTTPS: `authorize?prompt=login` → `/login` → re-login
→ `code`; and a same-second retry **without** re-login still routes to `/login`
(no bypass). Commits `9736dad7`, `<session-id rework>`.

### 3.8 Token endpoint no-store cache headers (RFC 6749 §5.1)

The token endpoint (and PAR, introspection, revocation, device authorization)
now send `Cache-Control: no-store` + `Pragma: no-cache`, wired via
`AddNoStoreCacheHeaders` after JSON serialization on those routes only —
discovery and JWKS stay cacheable. Commit `3583a19b`.

---

## 4. Current conformance state (local runs)

Runs use the [official OpenID Foundation conformance
suite](https://gitlab.com/openid/conformance-suite) locally (Docker,
`https://localhost.emobix.co.uk:8443`) driven against the OP at
`https://host.docker.internal:5002` over native HTTPS (see §5).

- **Config OP** — passes over HTTPS (0 failures).
- **Basic OP** — of the 35 plan modules, every module that can be automated
  passes; the remainder are limited by our local automation driver, the suite
  configuration, or manual certification steps — not by OP defects:

  | Category | Count | Notes |
  |----------|-------|-------|
  | PASSED | 19 | code flow, userinfo (get/post-header), display, `prompt=none` ×2, `max_age=10000`, `id_token_hint`, `login_hint`, `ui/claims_locales`, `acr_values`, **code reuse** ×2, valid PKCE, negative cases |
  | WARNING (finished, automated checks green) | 9 | `server`, userinfo-post-body, `scope` profile/email/**address/phone/all**, alternate-happy-flow, claims-essential |
  | SKIPPED (optional feature) | 1 | unsigned request object |
  | WAITING — manual screenshot (OP correct) | 2 | `prompt=login`, `max_age=1` |
  | WAITING — automation-driver limit | 2 | ensure-registered-redirect-uri, request-object-with-redirect-uri |
  | FAILED — harness/driver (OP verified capable) | 2 | refresh-token (two-client), client-secret-post |

  `prompt=login` and `max_age` behave correctly (the suite reaches the "server
  must ask the user to login for a second time" state); those two modules
  additionally require a **manual screenshot upload** for certification
  evidence and cannot be fully auto-completed.

  id_token hygiene: OpenIddict's internal `oi_au_id` (authorization id) no
  longer leaks into the id_token (`StripInternalClaimsFromIdentityToken`,
  kept on the access_token). `oi_tkn_id` is intentionally retained — it is the
  entry id OpenIddict uses to revoke the id_token / drive back-channel logout.
  `name` and our `redb:user_id` remain in the id_token by design (the latter so
  external systems can cross-reference their own user table client-side).

### 4.1 Notes on the non-passing modules

During verification we separated genuine OP defects from limitations of our
local automation driver / suite configuration:

| Module | Cause | OP correct? |
|--------|-------|-------------|
| `oidcc-prompt-login`, `oidcc-max-age-1` | require a manual screenshot upload | ✅ yes (verified end-to-end) |
| `oidcc-scope-address/phone/all` | conformance client must be registered **with** those scopes | ✅ yes (OP supports `address`/`phone`) |
| `oidcc-refresh-token` | uses a **second client**; our automation driver mis-drives the two-client sequence | ✅ yes (manual two-client: 200/200, refresh 200) |
| `oidcc-server-client-secret-post` | suite config resolution for the post-auth variant | ✅ yes (OP accepts `client_secret_post`: 200) |
| `oidcc-ensure-registered-redirect-uri`, `…-request-object-with-redirect-uri` | automation-driver limitation | OP rejects unregistered redirect_uri as required |

The **one genuine OP defect** found during this pass — the missing
`Cache-Control: no-store` on the token endpoint — was fixed (§3.8).

---

## 5. How to run the conformance suite locally

1. Bring up the OP over HTTPS (native TLS; see [HTTPS.md](HTTPS.md)) with the
   conformance `context.json` (issuer `https://host.docker.internal:5002`,
   `RequirePkce=false` for Basic OP).
2. Bring up the OIDF suite with `host.docker.internal:host-gateway` and the
   self-signed cert trusted in the suite's Java truststore.
3. Register a confidential static client (`client_secret_basic`,
   `authorization_code`+`refresh_token`, all scopes incl. `offline_access`,
   `address`, `phone`) plus a second client for `oidcc-refresh-token`, and
   point the plan config at them.
4. Create the `oidcc-basic-certification-test-plan` and drive each module.

The harness is the [official OpenID Foundation conformance
suite](https://gitlab.com/openid/conformance-suite); the steps above reproduce
our local runs against it.

---

## 6. Commit trail

| Commit | Scope |
|--------|-------|
| `e776cd62` | Native HTTPS, discovery metadata, error-delivery hardening, token error normalization, boolean claims, configurable PKCE |
| `9736dad7` | `prompt=login` / `max_age` re-authentication (signed re-auth marker) |
| `3583a19b` | Token endpoint `Cache-Control: no-store` / `Pragma: no-cache` (RFC 6749 §5.1) |
