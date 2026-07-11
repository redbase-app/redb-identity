# redb.Identity — Deployment Guide

redb.Identity is an OIDC/OAuth2 identity server that runs as **Tsak modules** on the
[redb.Tsak](https://github.com/redbase-app/redb-tsak) Worker runtime. The backend is two
`.tpkg` modules (`identity.core` = OIDC engine, `identity.http` = 26-controller HTTP facade)
plus a `context.json`; the login/admin UI is a separate Blazor **BFF** (`redb.Identity.Web`).

You pick a distribution shape based on what you want bundled — from "just the OIDC backend"
to "backend + Tsak dashboard + Identity's own UI".

---

## 🔌 Port matrix (memorise this)

| Port | Service | In which artifacts |
|------|---------|--------------------|
| **9090** | Tsak Worker management API | backend, managed, full, (archive) |
| **5002** | **Identity OIDC** — `/connect/*`, `/.well-known/*`, userinfo | backend, managed, full, (archive) |
| **8085** | Tsak dashboard (manages the Worker) | managed, full, (archive) |
| **8087** | **Identity BFF** — login / consent / admin UI | full, web, (archive) |

All four are distinct and deliberately avoid **8080** (common) — note the OIDC default in code is
8080 but `context.json` pins it to **5002**. `8086` is skipped (firebase-emulator uses it on our dev box).
Every host port is overridable (compose `*_PORT`, or `ASPNETCORE_URLS` / `PublicPort`).

---

## 📦 Artifacts

### Images (`ghcr.io/redbase-app/…`)

| Image | What's inside | Ports | Use it when |
|-------|---------------|-------|-------------|
| `redb-identity-backend` | Tsak Worker + Identity modules | 9090, 5002 | pure OIDC backend, you already have UIs |
| `redb-identity-managed` | + **Tsak dashboard** | 9090, 5002, **8085** | backend you want to **manage** via the Tsak dashboard |
| `redb-identity-full` | + **Identity BFF** | 9090, 5002, 8085, **8087** | everything: managed backend **and** Identity's own login UI |
| `redb-identity-web` | Identity BFF only | 8087 | scale/deploy the UI separately, point it at any backend |

### Archives (GitHub Release assets)

| Archive | What's inside | For |
|---------|---------------|-----|
| `redb-identity-<ver>-<rid>` | self-contained worker + dashboard + modules + BFF + start scripts | run the **full** stack without Docker |
| `redb-identity-modules-<ver>` | the two `.tpkg` + `context.json` only | **updating** an existing backend (drop into Worker `modules/` → hot-reload) |

> **Version coupling.** Backend/managed/full are `FROM redb-tsak-worker/-stack:<TsakVersion>`, and the
> modules are packed against that Worker. Deploy the modules onto the matching Tsak version.

---

## 🚀 Run

### Full (backend + dashboard + Identity UI) — the usual choice
```bash
cd publish/docker
cp compose.full.env.example .env      # set DB password + BACKCHANNEL_SECRET + TSAK_AUTH_SECRET
docker compose -f compose.full.yml --profile redb up -d
#  Identity login/admin : http://localhost:8087
#  Tsak dashboard        : http://localhost:8085
#  OIDC discovery        : http://localhost:5002/.well-known/openid-configuration
```

### Managed (backend + Tsak dashboard, no Identity UI)
```bash
docker compose -f publish/docker/compose.managed.yml --profile redb up -d
#  dashboard 8085 | OIDC 5002 | mgmt 9090
```

### Backend only (OIDC, no UI)
```bash
docker compose -f publish/docker/compose.backend.yml --profile redb up -d
#  OIDC 5002 | mgmt 9090
# or:
docker run -p 5002:5002 -p 9090:9090 ghcr.io/redbase-app/redb-identity-backend:latest
```

### Web BFF only (against an external backend)
```bash
docker run -p 8087:8087 \
  -e Identity__Authority=http://your-backend:5002 \
  -e Identity__BackchannelClient__ClientSecret=<same-as-backend> \
  ghcr.io/redbase-app/redb-identity-web:latest
```

### Standalone archive (no Docker)
```bash
tar -xzf redb-identity-<ver>-linux-x64.tar.gz && cd redb-identity-<ver>-linux-x64
./scripts/start-full.sh          # worker(9090+5002) + dashboard(8085) + BFF(8087)
# or ./scripts/start-backend.sh   # OIDC backend only
```

### Update an existing backend (no redeploy)
```bash
# from redb-identity-modules-<ver>.zip:
cp redb.Identity.Core.Module.tpkg redb.Identity.Http.tpkg context.json  <tsak-worker>/modules/
# Tsak Worker hot-reloads (~15s). OIDC stays on 5002.
```

---

## 🔐 Configuration & secrets

**No secret ships in any artifact.** Supply at deploy time (Tsak 5-layer config; see
`context.json` header for the full pipeline). Env override form: `Tsak__Contexts__identity.core__Override__…`.

Minimum to boot a real backend:
- **Database** (Postgres): `Redb:identity-pg:ConnectionString`
  → `Tsak__Contexts__identity.core__Override__Redb__identity-pg__ConnectionString`
- **Backchannel secret** — the **same** value on both sides so the BFF can talk to the backend:
  - backend: `Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret`
  - BFF: `Identity__BackchannelClient__ClientSecret`
- **Tsak auth**: `Tsak__Auth__Secret`

Federation / LDAP / dynamic-registration / MFA-recovery secrets: see `context.json`.

---

## 🔎 Verify signatures

All images and archives are cosign-signed with the shared redbase-app key
(`publish/keys/cosign.pub`):
```bash
cosign verify --key publish/keys/cosign.pub ghcr.io/redbase-app/redb-identity-backend:<ver>
cosign verify-blob --key publish/keys/cosign.pub \
  --bundle redb-identity-<ver>-linux-x64.tar.gz.bundle redb-identity-<ver>-linux-x64.tar.gz
```

---

## Build it yourself (maintainers)

```powershell
pwsh redb.Identity/publish/build.ps1 -All -TsakVersion 3.3.1
```
See `publish/README.md` (build details) and `publish/HOW_TO_PUBLISH.md` (release procedure).
