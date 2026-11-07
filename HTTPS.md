# redb.Identity over HTTPS

How the redb.Identity OpenID Provider (OP) serves its HTTP facade over **native TLS/HTTPS**,
why you need it, how to configure it, and how to operate it day-to-day.

> TL;DR — redb.Identity can terminate TLS **itself** (no reverse proxy required). Point
> `IdentityTransport:Http:Ssl=true`, give it a PFX, and set the `Issuer` to the matching
> `https://…` URL. Every facade endpoint then binds with TLS via Kestrel.

---

## 1. Why HTTPS is not optional for an OP

An OpenID Provider is a security authority: it mints ID tokens, access tokens and sets session
cookies. The OpenID Connect / OAuth 2.x specs and every conformance/certification profile treat
plain HTTP as a hard error for anything but throwaway local development:

- **OIDC Discovery / RFC 8414** — the `issuer` identifier and every advertised endpoint
  (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`,
  `registration_endpoint`, …) **must** use the `https` scheme. The OpenID conformance suite
  fails the *Config OP* profile outright on an http issuer (`"issuer is not a valid RFC 8414
  issuer identifier URL"`, `"… must use the https scheme"`).
- **Tokens & cookies** — bearer tokens and the session cookie must never travel in clear text.
  redb.Identity automatically sets the cookie `Secure` flag when the `Issuer` scheme is `https`
  (see `HttpFacadeRouteBuilder`, `_transportOptions.Issuer.Scheme == "https"`).
- **PKCE / DPoP / PAR** protect against interception, but they assume the transport itself is
  confidential. Without TLS the whole chain is moot.

So: **dev-only** may run http on `127.0.0.1`; **anything reachable by another machine — including
the OpenID conformance suite — must be https.**

---

## 2. You do NOT need a reverse proxy

The `redb.Route.Http` connector that powers the facade supports TLS natively through Kestrel:

- URI scheme `https:` is a first-class component (`HttpsComponent`, registered alongside
  `HttpComponent`).
- `HttpEndpointOptions` exposes `Ssl` (bool), `SslCertPath` (PFX path), `SslCertPassword`.
- `SharedHttpServerManager` configures Kestrel to listen with the supplied certificate.

redb.Identity wires this into the HTTP facade so a single config switch flips **all** endpoints
on the public port from `http:` to `https:`. A TLS-terminating reverse proxy (nginx/Caddy) is
still a perfectly valid deployment choice — but it is **optional**, not required.

---

## 3. Configuration

All settings live under `IdentityTransport:Http` (context.json → identity.http context, or host
appsettings / env overrides). The relevant fields:

| Field | Meaning |
|-------|---------|
| `Ssl` | `true` → serve the facade over HTTPS. Default `false` (plain http, dev only). |
| `SslCertPath` | Filesystem path to a **PFX (PKCS#12)** certificate. Required when `Ssl=true`. |
| `SslCertPassword` | Password for the PFX (`null` if none). **Secret** — supply via env override in prod. |

And the issuer (both contexts must agree with the scheme you actually serve):

- `identity.core` → `Identity:Issuer`
- `identity.http` → `IdentityTransport:Issuer`

### Example (context.json)

```jsonc
// identity.core
"Identity": {
  "Issuer": "https://id.example.com",     // MUST be https when Ssl=true
  ...
}

// identity.http
"IdentityTransport": {
  "Issuer": "https://id.example.com",      // mirror of the above
  "Http": {
    "PublicPort": 5002,
    "Ssl": true,
    "SslCertPath": "C:/certs/id.example.com.pfx",
    "SslCertPassword": "…"                 // prod: leave out of the file, use an env override
  }
}
```

### Env-var override for the secret (recommended in production)

```
Tsak__Contexts__identity.http__Override__IdentityTransport__Http__SslCertPassword=<value>
```

### The Issuer MUST match the URL clients use

The `issuer` string is emitted verbatim in discovery and as the `iss` claim of every token. It
**must** be identical to the origin clients (and the conformance suite) use to reach the OP,
including scheme and host. A mismatch (`iss` says one thing, the URL another) breaks RP validation
and fails conformance. Bind host and issuer host are independent: the facade binds `0.0.0.0:{port}`
(all interfaces) regardless; the issuer is a static advertised URL.

---

## 4. How it works internally (for maintainers)

1. `HttpFacadeRouteBuilder.Configure()` reads `IdentityTransport:Http:Ssl`. When true it computes,
   once:
   - `_scheme = "https"`
   - `_sslParams = "&ssl=true&sslCertPath=…&sslCertPassword=…"` (URL-encoded)
2. Every endpoint is registered as `From($"{_scheme}:{METHOD}:0.0.0.0:{port}{path}?inOut=true{_sslParams}…")`.
   Because **all** endpoints on a host:port must agree on TLS (`SharedHttpServerManager` throws
   *"already registered as HTTP/HTTPS"* on a mismatch), the scheme + ssl params are applied
   uniformly — never mix http and https endpoints on the same port.
3. `InitRoute` registers **both** the `http` and `https` route components (sharing one
   `SharedHttpServerManager`). If only `http` were registered you'd get
   *"No component registered for scheme 'https'"* at startup.
4. `Uri.EscapeDataString` escapes the cert path/password so Windows paths and special characters
   survive the URI query.

---

## 5. Certificates

You need a **PFX** whose Subject Alternative Names (SAN) cover every host clients use to reach the
issuer.

### Production
Use a certificate from a real CA (Let's Encrypt, your corporate PKI, …) for your public issuer
host, e.g. `id.example.com`. Export it to PFX and point `SslCertPath` at it. Rotate before expiry;
the cert is re-read when the facade (re)starts / hot-reloads.

### Local development / conformance testing (self-signed)
A self-signed cert is fine as long as the *client* trusts it. Generate one with OpenSSL (note the
SANs — include every host you'll use):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 825 -nodes \
  -subj "/CN=redb-identity-dev" \
  -addext "subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1"
openssl pkcs12 -export -out redb-identity-dev.pfx -inkey key.pem -in cert.pem -passout pass:changeit
```

Because it is self-signed, any RP/tool that talks to the OP must trust it (add the cert to the OS
or the tool's trust store). Browsers will warn until you trust it locally.

---

## 6. The OpenID conformance-suite case (why the odd host + self-signed)

When validating against the official OpenID Foundation conformance suite (which runs in Docker):

- The suite (Java, in a container) reaches the OP on the Windows host via
  `host.docker.internal:5002`, so the **issuer is set to `https://host.docker.internal:5002`** for
  the duration of that testing (plain non-Docker dev would use `https://127.0.0.1:5002` or
  `http://127.0.0.1:5002` with `Ssl=false`).
- The suite is an RP and validates the OP's TLS cert. For a self-signed dev cert this means the
  suite's **Java truststore must contain the cert** — we build a truststore from the image's
  `cacerts` + `keytool -importcert …` and mount it into the suite container.
- With that in place the *Config OP* profile goes from **8 failures (all "must use https")** to
  **0 failures** — the discovery document itself was already structurally conformant; TLS was the
  only gap.

The full suite setup lives in `C:\Work\yaml\conformance\` (compose + certs + truststore).

---

## 7. Operating notes / "how to live with it"

- **Switching http ⇄ https is a per-port, all-or-nothing change.** Flip `Ssl` and update the
  `Issuer` scheme together, then restart / hot-reload. A hot-reload tears down the old server on
  the port and binds a fresh one with the new scheme; if a switch ever fails to bind, restart the
  worker so the port is fully released first.
- **Cookie `Secure` follows the issuer scheme automatically** — no separate flag. If you serve
  https but leave `Issuer` on http, cookies won't be `Secure` and browsers may reject them.
- **Behind a load balancer / TLS-terminating proxy** you may instead keep the facade on http and
  let the proxy do TLS. In that case set `Ssl=false` but STILL set `Issuer` to the public
  `https://…` URL (what the world sees), and configure `ReverseProxies` (forwarded-header trust)
  so the OP honours `X-Forwarded-Proto`. Native TLS (this document) and proxy-TLS are the two
  supported topologies — pick one.
- **Password hygiene** — never commit a real `SslCertPassword`. Use the L5 env-var override. The
  dev value in the repo (`changeit`) protects only a throwaway self-signed cert.
- **Cert expiry** — self-signed dev certs above last 825 days; production certs rotate on the CA's
  schedule. Re-point `SslCertPath` (or replace the file) and restart to load a new cert.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|--------|-------------|
| `No component registered for scheme 'https'` at startup | The `https` route component wasn't registered. `InitRoute` must add `HttpsComponent` alongside `HttpComponent`. |
| `SslCertPath is required when Ssl=true` | `Ssl=true` but no `SslCertPath`. Provide the PFX path. |
| `already registered as HTTP/HTTPS` on a port | Some endpoints on that port are http and others https. All endpoints on one host:port must share the same scheme. |
| Suite / RP: `PKIX path building failed` / TLS handshake error | The client doesn't trust the OP's (self-signed) cert. Add it to the client's trust store (Java: `keytool -importcert` into `cacerts`; OS: install the cert). |
| Conformance: `issuer is not a valid RFC 8414 identifier URL` / `must use the https scheme` | The OP is still on http, or `Issuer` isn't https. Set `Ssl=true` and both `Issuer`s to the https URL. |
| `iss` mismatch at the RP | The `Issuer` value doesn't match the URL clients use (scheme/host). Make them identical. |
| Port 5002 unreachable after flipping `Ssl` | The old server didn't release the port in time on hot-reload. Restart the worker. |
