# redb.Identity.Web

The official **BFF** (Backend-For-Frontend) console for the REDB Identity server.
It is a Blazor Server application that the operator and end-user point their
browser at; every interaction with the actual identity-server happens through
the public SDK (`redb.Identity.Client`) over HTTP/JSON.

> **Isolation HARDLINE.** This project must only consume
> `redb.Identity.Contracts` and `redb.Identity.Client`. It does **not**
> reference `redb.Identity.Core`, `.Http`, `.DataProtection` and the other server
> projects. [`IsolationTests`](../../tests/redb.Identity.Web.Tests/IsolationTests.cs)
> checks the boundary, and the image build copies only the three allowed
> projects, so a forbidden `ProjectReference` fails it.

---

## Quick start (development)

1. Start an Identity server on `https://localhost:5002`, for example the backend image with the
   service-account secret the console's revoked-sessions poll uses:

   ```bash
   docker run -d --name identity -p 5002:5002 \
     -e Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret=<backchannel-secret> \
     ghcr.io/redbase-app/redb-identity-backend:latest
   ```

   On a fresh database Identity sets up what the console needs by itself: the `admin` user
   (password `admin`, or `Identity:SeedAdmin:Password` set before the first start), the public
   client `identity-web` with the redirect address `https://localhost:7000/signin-oidc`
   (`Identity:SeedWebClient`), and the service account `identity-backchannel` once its secret is set.
   `scripts/dev-backchannel-secret.ps1` generates one secret and sets it for both sides.

2. Run the console:

   ```powershell
   cd redb.Identity/src/redb.Identity.Web
   $env:Identity__BackchannelClient__ClientSecret = "<backchannel-secret>"
   dotnet run --launch-profile https
   # → https://localhost:7000
   ```

   `appsettings.Development.json` points at `https://host.docker.internal:5002` and accepts the
   server's self-signed development certificate (`Identity:AcceptAnyBackchannelCert`, Development only).
   `scripts/dev-certs.{ps1,sh}` provisions a locally trusted certificate for the console's own HTTPS port.

3. Sign in as `admin` and change the password.

---

## Configuration

The BFF is configured via the `Identity:` section. All values are read from `appsettings.json` +
environment-specific overrides + user-secrets + environment variables (standard ASP.NET Core
configuration ladder).

| Key | Required | Description |
|---|---|---|
| `Identity:Authority` | yes | Public issuer URL of the identity-server (HTTPS). Used as the OIDC discovery base. |
| `Identity:MetadataAddress` | yes | Usually `{Authority}/.well-known/openid-configuration`. Set explicitly when the discovery host differs from the issuer (e.g. internal network). |
| `Identity:RequireHttpsMetadata` | yes | `true` everywhere but a loopback dev server on plain `http://`. |
| `Identity:AcceptAnyBackchannelCert` | no | Development only: accept the identity-server's self-signed certificate on the console's server-to-server calls. |
| `Identity:ApiBaseUrl` | yes | Base URL of the identity-server REST API (`/api/v1/identity/...`). Typically equals `Authority`. |
| `Identity:ClientId` | yes | OIDC client id of this console, `identity-web` by default. |
| `Identity:ClientSecret` | no | Empty: the console is a public client (PKCE), as Identity seeds it. Set it only after registering the client as confidential; never commit it. |
| `Identity:Scopes` | yes | OAuth scopes requested during the auth code flow. Minimum: `openid profile email offline_access identity:manage identity:account`. |
| `Identity:BackchannelClient:ClientId` | yes | Service-account client id used by the revoked-sessions poll. |
| `Identity:BackchannelClient:ClientSecret` | no | Secret of that client, the same value as the server's `Identity:SeedBackchannelClient:ClientSecret`. Empty: the poll is off. |
| `Identity:BackchannelClient:Scopes` | no | Defaults to `[ "identity:manage" ]`. |
| `Identity:RevokedSids:PollInterval` | no | TimeSpan, default `00:01:00`. While the server is still starting, the first poll retries within seconds. |
| `Identity:DataProtectionKeysPath` | no | Directory of the console's DataProtection key ring; a volume in a container, so sign-ins survive a restart. |
| `Identity:LogsPath` | no | Directory of the rolling file log. |
| `Bootstrap:Enabled` | no | `true` only on the very first run against an empty identity-server, to call its `/internal/bootstrap-admin` endpoint. Always `false` afterwards. |
| `Bootstrap:Endpoint` | when enabled | URL of the server-side bootstrap endpoint. |
| `Bootstrap:Secret` | when enabled | Shared secret required by the server bootstrap endpoint. |

### Per-environment files

- `appsettings.json`: production-shape defaults; HTTPS only, `Bootstrap:Enabled=false`.
- `appsettings.Development.json`: points at `https://host.docker.internal:5002` and accepts its
  development certificate.

---

## Deployment

The console ships as the `redb-identity-web` image and inside `redb-identity-full`; ports, volumes,
secrets and the run commands are in [DEPLOYMENT.md](../../DEPLOYMENT.md). The image runs as a non-root
user, listens on 8087 and keeps its key ring and log on volumes.

A console with its own address needs that address in the server's client registration: set
`Identity:SeedWebClient:RedirectUris` and `PostLogoutRedirectUris` on the server before its first
start, or change the `identity-web` client in the management API.

### Reverse-proxy invariants

If you front the BFF with your own reverse proxy, preserve these headers:

- `Host`: both BFF and server compute the OIDC issuer from it. Rewriting it
  breaks token issuer validation.
- `X-Forwarded-Proto`: the BFF sets cookies with `Secure` only when the
  request scheme is `https`. A missing header behind a TLS-terminating proxy
  silently disables the `Secure` flag.
- For `/_blazor`, set `Upgrade: $http_upgrade` and `Connection: upgrade`, and
  raise the proxy read timeout: the Blazor Server circuit is a long-lived WebSocket.

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

3. **`invalid_request` about the redirect URI at `/connect/authorize`.** The console runs on an address
   the `identity-web` client does not list. See "Deployment" above.

4. **`identity:account` scope denied at `/connect/authorize`.** The client
   `Identity:ClientId` does not have the `identity:account` scope permission. Add it to the client
   in the management API, or list it in the server's `Identity:SeedWebClient:Scopes` before the client
   is first created.

5. **Blazor circuit disconnects every minute.** The reverse-proxy timeout is
   shorter than the SignalR keep-alive. Raise `proxy_read_timeout` for
   `/_blazor` to at least `300s`.
