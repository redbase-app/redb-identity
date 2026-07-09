# redb.Identity.Web

The official **BFF** (Backend-For-Frontend) console for the REDB Identity server.
It is a Blazor Server application that the operator and end-user point their
browser at; every interaction with the actual identity-server happens through
the public SDK (`redb.Identity.Client`) over HTTP/JSON.

> **Isolation HARDLINE.** This project must only consume
> `redb.Identity.Contracts` and `redb.Identity.Client`. It does **not**
> reference `redb.Identity.Core`, `.Persistence`, `.Http`, `.Federation`, etc.
> The boundary is enforced in three places:
>
> 1. CI workflow: [`.github/workflows/identity-web-isolation.yml`](../../../.github/workflows/identity-web-isolation.yml).
> 2. Runtime assertion: [`IsolationTests`](../../tests/redb.Identity.Web.Tests/IsolationTests.cs).
> 3. Build-time: [`deploy/identity-web/Dockerfile`](../../../deploy/identity-web/Dockerfile)
>    copies only the three allowed projects, so any forbidden `ProjectReference`
>    fails the image build.

---

## Quick start (development)

```powershell
# 1. Provision a locally-trusted TLS certificate.
#    Uses mkcert if installed, otherwise falls back to `dotnet dev-certs --trust`.
pwsh ./redb.Identity/scripts/dev-certs.ps1
```

```bash
# Same on macOS / Linux:
./redb.Identity/scripts/dev-certs.sh
```

```powershell
# 2. Make sure /etc/hosts (or %WINDIR%\System32\drivers\etc\hosts) maps the dev
#    hostnames to loopback. Skip if you only use localhost.
#       127.0.0.1   identity.local
```

```powershell
# 3. Bring up the identity-server (separate process, separate repo target).
#    Defaults to https://localhost:7001.
dotnet run --project redb.Identity/src/redb.Identity --launch-profile https
```

```powershell
# 4. Seed the development bootstrap admin (one-time, only on first run).
pwsh ./redb.Identity/scripts/seed-dev.ps1
```

```powershell
# 5. Run the BFF.
cd redb.Identity/src/redb.Identity.Web
dotnet user-secrets set "Identity:ClientSecret" "<paste-from-server-seed>"
dotnet run --launch-profile https
# → https://localhost:7000
```

---

## Configuration

The BFF is configured exclusively via the `Identity:` section. All values are
read from `appsettings.json` + environment-specific overrides + user-secrets +
environment variables (standard ASP.NET Core configuration ladder).

| Key | Required | Description |
|---|---|---|
| `Identity:Authority` | yes | Public issuer URL of the identity-server (HTTPS). Used as the OIDC discovery base. |
| `Identity:MetadataAddress` | yes | Usually `{Authority}/.well-known/openid-configuration`. Set explicitly when the discovery host differs from the issuer (e.g. internal network). |
| `Identity:RequireHttpsMetadata` | yes | `true` in production. Setting `false` disables TLS chain validation for the metadata fetch — only use for a loopback dev server with `http://`. |
| `Identity:ApiBaseUrl` | yes | Base URL of the identity-server REST API (`/api/v1/identity/...`). Typically equals `Authority`. |
| `Identity:ClientId` | yes | OIDC client id assigned to this BFF instance (e.g. `identity-web`). |
| `Identity:ClientSecret` | yes | Confidential client secret. Prefer user-secrets in dev and `Identity__ClientSecret` env var in containers; never commit to source. |
| `Identity:Scopes` | yes | OAuth scopes requested during the auth code flow. Minimum: `openid profile email offline_access identity:manage identity:account`. |
| `Identity:BackchannelClient:ClientId` | yes | Service-account client id used by the revoked-sids poller (W6-0). |
| `Identity:BackchannelClient:ClientSecret` | yes | Secret for the backchannel client. Same rules as `Identity:ClientSecret`. |
| `Identity:BackchannelClient:Scopes` | no | Defaults to `[ "identity:manage" ]`. |
| `Identity:RevokedSids:PollInterval` | no | TimeSpan, default `00:00:30`. Set to `01:00:00` or higher in tests to avoid hot-looping a fake authority. |
| `Bootstrap:Enabled` | no | `true` only on the very first run against an empty identity-server, to call its `/internal/bootstrap-admin` endpoint. Always `false` afterwards. |
| `Bootstrap:Endpoint` | when enabled | URL of the server-side bootstrap endpoint. |
| `Bootstrap:Secret` | when enabled | Shared secret required by the server bootstrap endpoint. |

### Per-environment files

- `appsettings.json` — production-shape defaults; HTTPS-only, `Bootstrap:Enabled=false`.
- `appsettings.Development.json` — points at `https://localhost:7001` with
  `RequireHttpsMetadata=true`. The dev certificate is provisioned by
  `scripts/dev-certs.{ps1,sh}`.

---

## Deployment

### Docker (compose)

```bash
cp deploy/.env.example deploy/.env
# Edit IDENTITY_DB_PASSWORD, IDENTITY_WEB_CLIENT_SECRET, IDENTITY_PUBLIC_AUTHORITY, …

docker compose -f deploy/docker-compose.identity.yml up -d --build
```

The Dockerfile at [`deploy/identity-web/Dockerfile`](../../../deploy/identity-web/Dockerfile)
performs a multi-stage build that copies **only** the three allowed projects
(`Contracts`, `Client`, `Web`), restores, publishes, and runs as a non-root
user. The runtime image exposes port `8080` and ships a `wget`-based
healthcheck targeting `/health`.

Nginx terminates TLS and dispatches between BFF and server — see
[`deploy/nginx/sites/identity.conf`](../../../deploy/nginx/sites/identity.conf).
Note the explicit `/_blazor` location: the Blazor Server circuit needs the
WebSocket `Upgrade` / `Connection` headers, which a generic `location /` would
drop.

### Reverse-proxy invariants

If you front the BFF with your own reverse proxy, preserve these headers:

- `Host` — both BFF and server compute the OIDC issuer from it. Rewriting it
  breaks token issuer validation.
- `X-Forwarded-Proto` — the BFF sets cookies with `Secure` only when the
  request scheme is `https`. A missing header behind a TLS-terminating proxy
  silently disables the `Secure` flag.
- For `/_blazor`, set `Upgrade: $http_upgrade` and `Connection: upgrade`, and
  raise the proxy read timeout (the example uses 24 h).

---

## Troubleshooting

1. **`InvalidOperationException: IDX10500: Signature validation failed`** at
   sign-in. The BFF cannot verify the id_token signature.
   Check that `Identity:Authority` (and `Identity:MetadataAddress` if set) is
   exactly the **public** issuer of the server. A mismatch between
   `Authority` and the value the server returns in
   `/.well-known/openid-configuration → issuer` is rejected by
   `OpenIdConnectHandler` even when both URLs are reachable.

2. **Redirect loop between `/signin-oidc` and `/login`.** The auth cookie is
   set without the `Secure` flag (browser drops it on HTTPS pages) or the
   identity-server's session cookie is on a different host than its TLS
   certificate. Verify `X-Forwarded-Proto` is being forwarded and the
   reverse proxy is not splitting cookie domains.

3. **`identity:account` scope denied at `/connect/authorize`.** The client
   `Identity:ClientId` does not have the `identity:account` scope permission
   in the server-side OpenIddict application descriptor. Re-run the server
   bootstrap script or add the scope to the client via the management API.

4. **Blazor circuit disconnects every minute.** The reverse-proxy timeout is
   shorter than the SignalR keep-alive. Raise `proxy_read_timeout` for
   `/_blazor` to at least `300s` (the sample nginx config uses `86400s`).
