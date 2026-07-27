# redb.Identity — OpenID Connect Certification Readiness

This document describes what redb.Identity implements toward
[OpenID Certification](https://openid.net/certification/), what was changed to
prepare for it, and the current state against the official OpenID Foundation
conformance suite.

> **Status — preparing for OpenID Certification.** In local runs of the official
> OIDF conformance suite against a live server over native HTTPS:
> **Config OP — zero failures**, and **Basic OP — 35 modules, zero failures**
> (29 PASSED, 3 REVIEW awaiting a screenshot, 1 WARNING that is a deliberate
> extension, 2 SKIPPED optional features). Every defect the suite found is fixed;
> §4.1 lists them, including the ones we had previously — and wrongly — written
> off as harness limitations.
>
> **Both SKIPPED modules are `alg:none` (unsigned) request objects — skipped *because* the
> server refuses to advertise the unsafe mode, which is the correct, secure answer, not a gap.**
> See §4.3. `FAILED` is `0`.

It is a **status / spec** document, not a marketing claim: it tracks our own
local conformance runs and the protocol work that makes redb.Identity
certifiable.

> **We do not carry the OpenID Certified™ mark.** That is a trademark, granted by
> the OpenID Foundation through a formal (and paid) submission. What is claimed
> here is only what is true: the server is run against the official OIDF
> conformance suite, and these are the results.

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
- **Basic OP** — **35 modules, 0 failures.**

  | Result | Modules | Notes |
  |--------|---------|-------|
  | PASSED | 29 | |
  | REVIEW | 3 | the suite requires a human-uploaded screenshot — pass-equivalent |
  | WARNING | 1 | `oidcc-server` — two deliberate id_token claims (below) |
  | SKIPPED | 2 | **both** are `alg:none` (unsigned) request objects — skipped because we correctly refuse the unsafe mode; see §4.3 |
  | **FAILED** | **0** | |

  The three REVIEW modules (`prompt-login`, `max-age-1`,
  `ensure-registered-redirect-uri`) behave correctly end to end; the suite
  additionally wants a screenshot as certification evidence and therefore never
  auto-finishes them.

### 4.1 What the suite actually found

An earlier revision of this document attributed several non-passing modules to
"automation-driver limits" and "suite configuration". **That was wrong, and it
is worth saying so plainly**: when we stopped excusing them and dug in, most
turned out to be **genuine OP defects**. All are now fixed.

| What the suite flagged | What it really was | Fix |
|------------------------|--------------------|-----|
| `oidcc-scope-address/phone/all` — WARNING | **Not** "the client wasn't registered with those scopes." The `profile` claim set was **incomplete** — the suite diffs userinfo against the exact OIDC §5.1 list and warns per missing claim | Full §5.1 set emitted; `updated_at` as a JSON number, `*_verified` as JSON booleans |
| `oidcc-server` — id_token claims | Scope-derived `profile`/`email`/`phone`/`address` claims were **embedded in the id_token**. In the code flow they belong in UserInfo (§5.4). An id_token is forwarded to third parties and logged as proof of sign-in — the user's phone number travelled far further than the RP intended. **A PII leak** | Scope-derived claims are now AccessToken-destination only: served from `/connect/userinfo`, absent from the id_token |
| userinfo returning extra fields | UserInfo was copying claims through a *deny-list*, leaking token plumbing: OpenIddict's `oi_*` internals, `jti`/`exp`/`iat`/`at_hash`. Those describe the **token**, not the user (§5.3) | Explicit allow-list |
| `oidcc-userinfo-post-body` | `/connect/userinfo` (POST) did not accept the access token in the form-encoded body (RFC 6750 §2.2) | Route now maps form to body |
| `oidcc-claims-essential` — WARNING | The test requests `name` as an essential claim via the **`claims` parameter** (§5.5), which we had **not implemented at all** — and our own discovery said so: `claims_parameter_supported: false` | §5.5 implemented; discovery now says `true` |
| `oidcc-server-client-secret-post` — FAILED | **Suite config, not an OP defect** — and this one really was the harness. The test does `config.add("client", config.get("client_secret_post"))`, overwriting `client` with a key our plan didn't have, so it died *before* issuing a single request to the OP | Plan config gained a third client under the `client_secret_post` key. Module passes |

Earlier passes also fixed: the error open-redirect (RFC 6749 §4.1.2.1), reused
authorization code → `400 invalid_grant` (§5.2), `Cache-Control: no-store` on
token/introspect/revoke (§5.1), and boolean `*_verified` claims (§5.1).

### 4.2 The one remaining WARNING is deliberate

`oidcc-server` finishes WARNING on two non-requested id_token claims:

```
id_token contains non-requested claim 'oi_tkn_id'
id_token contains non-requested claim 'redb:user_id'
```

These are **warnings, not failures**. OIDC Core does not forbid additional
id_token claims; the suite warns because an extra claim *can* mean user data is
leaking — and its own message concedes the alternative: *"…or that it implements
an extension the conformance suite is not aware of."* That is our case. Neither
claim is data about the user:

- **`oi_tkn_id`** — the id of the token's entry in the store. It is what makes
  the id_token **revocable** and what drives back-channel logout. Dropping it
  means giving up id_token revocation: a real capability traded for a clean
  warning list.
- **`redb:user_id`** — a namespaced private claim (RFC 7519 §4.3). The public
  `sub` is a GUID (stable across instances); the hot key in the relational
  `_users` table is a bigint. This lets a client decode the id_token and join the
  user to **its own** table without a round-trip back to us.

And the part that makes this a judgement rather than a rationalisation: in the
same pass we **deleted** a third such claim. OpenIddict was also stamping
`oi_au_id` — its internal link to the authorization entry — into the id_token.
That one means nothing to a client and there was no defending it
(`StripInternalClaimsFromIdentityToken`; kept on the access_token, where
introspection needs it). We kept the two we can answer for and cut the one we
could not.

### 4.3 The two SKIPPED modules are a security choice, not a gap

Both skipped modules test the **unsigned** (`alg:none`) request object:

- `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
- `oidcc-ensure-request-object-with-redirect-uri`

Read the suite's own words on them: each is *"skipped if the server discovery
document does not indicate support for unsigned request objects — i.e. if
`alg:none`"*, i.e. if `request_object_signing_alg_values_supported` does not
contain `none`. Ours does not:

```json
"request_parameter_supported": true,
"request_uri_parameter_supported": true,
"request_object_signing_alg_values_supported": ["RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
```

An `alg:none` request object is a JWT **with no signature** — it throws away the
exact integrity guarantee that JWT-Secured Authorization Requests (RFC 9101)
exist to provide, and lets the authorization parameters be tampered with in
transit. We refuse it on purpose:

- **FAPI 2.0 forbids `alg:none`** for request objects and mandates asymmetric signing;
- accepting it would open a request-parameter-tampering hole.

So the suite sees "this server supports request objects, but only **signed** ones"
and correctly marks the two `alg:none` tests **not applicable**. `SKIPPED` here
means *"the server declined to advertise an unsafe mode"* — it is the secure
answer, and Basic OP treats it as such (`FAILED = 0`).

**What actually changed since the earlier run.** Before we implemented RFC 9101,
the server advertised no request-object support at all, and
`ensure-request-object-with-redirect-uri` ran down a screenshot (REVIEW) path.
Now that the server genuinely processes **signed** request objects (both `request`
and `request_uri`) and honestly advertises exactly that, the suite moves the
`alg:none` variants to SKIPPED. The count went 1→2 SKIPPED and 4→3 REVIEW; the
real gain is that signed request objects now work end-to-end rather than being
attested by a screenshot. Turning either skip into a pass would require
advertising and accepting `alg:none` — a deliberate security regression we will
not make.

> For readers scanning the badge: **two skips, zero failures.** Both skips are the
> server refusing an unsigned-JWT mode that the OAuth security profiles (FAPI 2.0)
> tell it to refuse. That is the correct outcome, not a missing feature.

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
