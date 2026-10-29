# redb.Identity: Deployment Guide

redb.Identity is an OIDC/OAuth2 identity server that runs as **Tsak modules** on the
[redb.Tsak](https://github.com/redbase-app/redb-tsak) Worker runtime. The backend is a set of `.tpkg` modules
(`identity.contracts` carrier, `identity.core` engine, `identity.http` facade, optional `identity.grpc` and
`identity.soap` facades) plus a `context.json`; the login/admin UI is a separate Blazor **BFF** (`redb.Identity.Web`).

You pick a distribution shape based on what you want bundled, from the OIDC backend alone to backend, Tsak
dashboard and Identity's own UI in one container.

---

## Port matrix

| Port | Service | In which artifacts |
|------|---------|--------------------|
| **9090** | Tsak Worker management API; in managed and full only on 127.0.0.1 inside the container, behind the dashboard | backend, (archive) |
| **5002** | **Identity OIDC** (HTTPS): `/connect/*`, `/.well-known/*`, userinfo | backend, managed, full, (archive) |
| **8085** | Tsak dashboard (manages the Worker) | managed, full, (archive) |
| **8087** | **Identity BFF**: login, consent, admin UI | full, web, (archive) |

The OIDC default in code is 8080; `context.json` pins it to **5002**. Every host port can be remapped
(`-p <host>:<container>`, or `PublicPort` in `context.json`).

---

## Artifacts

### Images (`ghcr.io/redbase-app/…`)

| Image | What's inside | Ports | Use it when |
|-------|---------------|-------|-------------|
| `redb-identity-backend` | Tsak Worker + Identity modules | 9090, 5002 | pure OIDC backend, you already have UIs |
| `redb-identity-managed` | + **Tsak dashboard** | 5002, **8085** | backend you want to **manage** via the Tsak dashboard |
| `redb-identity-full` | + **Identity BFF** | 5002, 8085, **8087** | everything: managed backend **and** Identity's own login UI |
| `redb-identity-web` | Identity BFF only | 8087 | scale/deploy the UI separately, point it at any backend |

Tags: `:<version>`, `:<version>-net10` and `:latest`. The images start on SQLite with a bundled self-signed
certificate for `localhost` (password `changeit`); call them with `curl -k` until you replace it ([HTTPS.md](HTTPS.md)).

### Archives (GitHub Release assets)

| Archive | What's inside | For |
|---------|---------------|-----|
| `redb-identity-<ver>-<rid>` | self-contained worker + dashboard + modules + BFF + start scripts | run the **full** stack without Docker |
| `redb-identity-modules-<ver>` | the `.tpkg` modules + `context.json` | **updating** an existing backend (drop into Worker `modules/`, hot-reload) |

> **Version coupling.** The backend, managed and full images are built on the Tsak Worker/stack image of the same
> release, and the modules are packed against that Worker. Deploy the modules onto the matching Tsak version.

---

## Run

Named volumes keep the state across a recreated container: the SQLite store (`/app/data`), the Identity Web key
ring and log, and the key rings of the Tsak worker and dashboard. Without them, every recreated container signs
all users out.

### Full (backend + dashboard + Identity UI)
```bash
docker run -d --name redb-identity-full \
  -p 8087:8087 -p 8085:8085 -p 5002:5002 \
  -e Tsak__Api__Host=127.0.0.1 -e Tsak__Web__AdminPassword=<dashboard-password> \
  -e Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret=<backchannel-secret> \
  -e Identity__BackchannelClient__ClientSecret=<backchannel-secret> \
  -v identity_data:/app/data \
  -v web_keys:/app/web-keys -v web_logs:/app/web-logs \
  -v dp_keys:/root/.aspnet/DataProtection-Keys \
  ghcr.io/redbase-app/redb-identity-full:latest
#  Identity login/admin : http://localhost:8087
#  Tsak dashboard       : http://localhost:8085
#  OIDC discovery       : https://localhost:5002/.well-known/openid-configuration
```

### Managed (backend + Tsak dashboard, no Identity UI)
```bash
docker run -d --name redb-identity-managed -p 8085:8085 -p 5002:5002 \
  -e Tsak__Api__Host=127.0.0.1 -e Tsak__Web__AdminPassword=<dashboard-password> \
  -v identity_data:/app/data -v dp_keys:/root/.aspnet/DataProtection-Keys \
  ghcr.io/redbase-app/redb-identity-managed:latest
```

### Backend only (OIDC, no UI)
```bash
docker run -d --name redb-identity-backend -p 5002:5002 -p 9090:9090 \
  -v identity_data:/app/data \
  ghcr.io/redbase-app/redb-identity-backend:latest
```

### Web BFF only (against an external backend)
```bash
docker run -d --name redb-identity-web -p 8087:8087 \
  -e Identity__Authority=https://your-backend:5002 \
  -e Identity__MetadataAddress=https://your-backend:5002/.well-known/openid-configuration \
  -e Identity__ApiBaseUrl=https://your-backend:5002 \
  -e Identity__BackchannelClient__ClientSecret=<same-as-backend> \
  -v web_keys:/app/keys -v web_logs:/app/logs \
  ghcr.io/redbase-app/redb-identity-web:latest
```

`your-backend` is the backend's public Issuer: the BFF calls it from the container and sends the browser to it,
so the name must resolve in both places and match the backend's `Issuer`, and the container must trust its
certificate. For a local check against a backend on the same Docker host with the bundled self-signed certificate,
set the backend's Issuer to `https://host.docker.internal:5002` (a name the certificate covers), run the BFF with
`--add-host host.docker.internal:host-gateway` and `-e Identity__AcceptAnyBackchannelCert=true`; that flag is for
development only. The `web` image runs as the non-root user `app` (uid 1654): a host
directory mounted on `/app/keys` or `/app/logs` instead of a named volume must be writable by that uid. The
`backend`, `managed` and `full` images run as root, like the Tsak images they are built on.

### Standalone archive (no Docker)
```bash
tar -xzf redb-identity-<ver>-linux-x64.tar.gz && cd redb-identity-<ver>-linux-x64
./scripts/start-full.sh          # worker(9090+5002) + dashboard(8085) + BFF(8087)
# or ./scripts/start-backend.sh  # OIDC backend only
```

### Update an existing backend (no redeploy)
```bash
# from redb-identity-modules-<ver>.zip:
cp *.tpkg context.json  <tsak-worker>/modules/
# The Tsak Worker hot-reloads the modules. OIDC stays on 5002.
```

---

## Configuration & secrets

**No secret ships in any artifact.** Supply them at deploy time through the Tsak layered configuration; the env
override form is `Tsak__Contexts__<context>__Override__…`. The annotated `context.sample.json` lists every setting.

Minimum to boot a real backend:
- **Issuer**: the public https URL, in both `identity.core` (`Identity:Issuer`) and `identity.http`
  (`IdentityTransport:Issuer`).
- **Backchannel secret**: the **same** value on both sides so the BFF can talk to the backend:
  - backend: `Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret`
  - BFF: `Identity__BackchannelClient__ClientSecret`
- **Tsak management API**: the images ship it without API keys. In `managed` and `full` it listens on 127.0.0.1
  inside the container (`Tsak__Api__Host=127.0.0.1`), where the dashboard reaches it, and the dashboard needs its
  password (`Tsak__Web__AdminPassword`); the compose files set both. In `backend` it answers on 9090 to whoever
  reaches the port: publish it only to a trusted network, or turn on Tsak's API keys (`Tsak:Auth`).
- **First administrator**: a fresh database has `admin` / `admin`. `Identity:SeedAdmin:Password` replaces it while
  it is still the default and never overwrites a changed password; on a database shared with the Tsak dashboard
  the account is the dashboard's too (README, "First administrator").

### Postgres instead of SQLite

The same image runs on Postgres through env overrides. `identity.core` and `identity.http` must share one redb
store, because the DataProtection key ring lives in it, so set both contexts:

```yaml
environment:
  Tsak__Contexts__identity.core__Override__Identity__RedbInstanceName: identity-pg
  Tsak__Contexts__identity.http__Override__RedbInstanceName:           identity-pg
  Tsak__Contexts__identity.core__Override__Redb__identity-pg__ConnectionString: "Host=postgres;Port=5432;Username=identity;Password=***;Database=identity;Pooling=true"
  Tsak__Contexts__identity.http__Override__Redb__identity-pg__ConnectionString: "Host=postgres;Port=5432;Username=identity;Password=***;Database=identity;Pooling=true"
```

### DataProtection key rings

The Identity server keeps its key ring in the database. The Tsak worker and dashboard keep theirs in
`/root/.aspnet/DataProtection-Keys`, hence the `dp_keys` volume for `managed` and `full`; the Identity Web BFF keeps
its own on `/app/keys` (`web`) or `/app/web-keys` (`full`). Upgrading a 4.3 container that had no volume on
`/root/.aspnet/DataProtection-Keys`: copy the ring out before removing the container, as described in
[UPGRADING.md](UPGRADING.md#dataprotection-key-ring).

Federation / LDAP / dynamic-registration / MFA-recovery secrets: see `context.sample.json`.

---

## Verify signatures

All images and archives are cosign-signed; the public key `cosign.pub` is attached to every GitHub release:
```bash
cosign verify --key cosign.pub ghcr.io/redbase-app/redb-identity-backend:<ver>
cosign verify-blob --key cosign.pub \
  --bundle redb-identity-<ver>-linux-x64.tar.gz.bundle redb-identity-<ver>-linux-x64.tar.gz
```

---

## Build the modules yourself

```powershell
pwsh scripts/pack-tpkg.ps1 -TsakModules <tsak-worker>/modules
```
builds every `.tpkg` and copies them into the given Worker `modules/` directory; take `context.sample.json` as the
`context.json` next to them.
