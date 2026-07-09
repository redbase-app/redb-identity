#!/usr/bin/env bash
# W6-1: Provisions a locally-trusted TLS certificate for redb.Identity.Web dev.
#
# Two paths, chosen automatically:
#   1. mkcert (preferred) — emits ./certs/identity-web.pfx, loaded by
#      Kestrel via appsettings.Development.json -> Kestrel:Endpoints:Https.
#   2. dotnet dev-certs https --trust (fallback) — uses the ASP.NET Core
#      dev cert; Kestrel picks it up implicitly when no PFX is configured.
#
# Usage:
#   ./redb.Identity/scripts/dev-certs.sh           # default password 'redb-dev'
#   PFX_PASSWORD=secret ./redb.Identity/scripts/dev-certs.sh
#   FORCE=1 ./redb.Identity/scripts/dev-certs.sh   # re-issue PFX

set -euo pipefail

PFX_PASSWORD="${PFX_PASSWORD:-redb-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/../../certs}"
FORCE="${FORCE:-0}"

info() { printf '\033[36m[dev-certs] %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m[dev-certs] %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[dev-certs] %s\033[0m\n' "$*"; }

if command -v mkcert >/dev/null 2>&1; then
    info "mkcert found: $(command -v mkcert)"
    mkdir -p "$OUT_DIR"
    OUT_DIR="$(cd "$OUT_DIR" && pwd)"
    PFX_PATH="$OUT_DIR/identity-web.pfx"

    if [ -f "$PFX_PATH" ] && [ "$FORCE" != "1" ]; then
        ok "PFX already exists: $PFX_PATH (set FORCE=1 to re-issue)"
    else
        info 'Installing mkcert local CA (idempotent)...'
        mkcert -install >/dev/null

        info 'Issuing cert for localhost / 127.0.0.1 / ::1 ...'
        (
            cd "$OUT_DIR"
            mkcert \
                -pkcs12 \
                -p12-file 'identity-web.pfx' \
                localhost 127.0.0.1 ::1
        )

        # mkcert -pkcs12 default password is 'changeit'. Re-export with the
        # configured password via openssl so Kestrel can load it directly.
        if command -v openssl >/dev/null 2>&1; then
            info 'Re-exporting PFX with configured password via openssl...'
            TMP_PEM="$(mktemp)"
            openssl pkcs12 -in "$PFX_PATH" -nodes -passin pass:changeit -out "$TMP_PEM"
            openssl pkcs12 -export -in "$TMP_PEM" -out "$PFX_PATH" -passout "pass:$PFX_PASSWORD"
            rm -f "$TMP_PEM"
        else
            warn "openssl not found — PFX password stays at mkcert default 'changeit'."
            warn "Update Kestrel:Endpoints:Https:Certificate:Password in appsettings.Development.json to match."
            PFX_PASSWORD='changeit'
        fi

        ok "Wrote $PFX_PATH"
    fi

    cat <<EOF

$(ok 'mkcert provisioning done. Kestrel will load this PFX via appsettings.Development.json.')
  Path:     $PFX_PATH
  Password: $PFX_PASSWORD

Next:
  cd redb.Identity/src/redb.Identity.Web
  dotnet run
EOF
    exit 0
fi

warn 'mkcert not found on PATH — falling back to dotnet dev-certs.'
warn 'For a wider-compatibility cert (containers, multi-host names) install mkcert:'
warn '  https://github.com/FiloSottile/mkcert'
echo

info 'Trusting the ASP.NET Core developer certificate...'
dotnet dev-certs https --trust

ok 'ASP.NET Core dev certificate installed and trusted.'
cat <<'EOF'
Kestrel picks it up automatically — no PFX path needed in config.

Next:
  cd redb.Identity/src/redb.Identity.Web
  dotnet run --launch-profile https
EOF
