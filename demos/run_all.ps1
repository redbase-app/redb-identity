#requires -Version 7
<#
  Runs every demo_*.ps1 in this directory in sequence and prints a pass/fail
  summary table. Each demo runs in its own pwsh child process so a hard failure
  in one demo cannot abort the rest. Per-demo stdout is streamed live and also
  captured to demos/_logs/<demo>.log for post-mortem.

  Usage:
    pwsh -File .\run_all.ps1                # run every demo_*.ps1
    pwsh -File .\run_all.ps1 -Only mfa_totp  # run only demos whose name matches
    pwsh -File .\run_all.ps1 -StopOnFail     # bail out on first failure
#>

param(
    [string]$Only = '',
    [switch]$StopOnFail,
    [switch]$IncludeInteractive
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path $here '_logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

# Demos that need a human in the loop (browser approval, etc.). Skipped by default.
$interactive = @('demo_device_code.ps1')

# Canonical execution order:
#   1. Discovery + core grants (fast feedback on server health)
#   2. High-priority security probes: DPoP (RFC 9449), PAR (RFC 9126), logout
#   3. Advanced grants + token management
#   4. Self-service /me + MFA
#   5. Provisioning: account register/verify, email change, SCIM
$ordered = @(
    'demo_discovery_jwks.ps1',
    'demo_discovery_shape.ps1',         # Discovery JSON shape lock + RFC 9449 §5 catalog
    'demo_conformance_discovery_config.ps1', # OpenID Config OP profile — §3 completeness + jwks/alg + PKCE/S256 + cert warnings
    'demo_dcr_lifecycle.ps1',
    'demo_client_credentials.ps1',
    'demo_private_key_jwt.ps1',         # RFC 7523 — private_key_jwt client assertion (DCR + token + introspect + negative)
    'demo_password_ropc.ps1',
    # ── HIGH PRIORITY: complex security contracts ─────────────────────────────
    'demo_dpop.ps1',                    # RFC 9449 — DPoP proofs, jkt binding, replay
    'demo_par.ps1',                     # RFC 9126 — PAR, one-time request_uri
    'demo_par_per_client.ps1',          # RFC 9126 §5 — per-client require_pushed_authorization_requests
    'demo_logout_endsession.ps1',       # OIDC Session + RFC 7009 revocation
    'demo_backchannel_logout.ps1',      # OIDC Back-Channel Logout 1.0 — fan-out + logout_token JWT
    'demo_federation.ps1',              # OIDC federation: discovery + safe public list + 302 probe
    'demo_federation_e2e.ps1',          # provision-on-first-login + link-on-replay end-to-end against navikt/mock-oauth2-server
    'demo_federation_link_unlink.ps1',  # self-service link / unlink via /me/federated-identities + re-link cycle
    'demo_federation_github.ps1',       # GitHub OAuth2-only path (non-OIDC, REST /user + /user/emails) via self-hosted pwsh HttpListener mock
    # ── Grants + token lifecycle ──────────────────────────────────────────────
    'demo_authcode_pkce.ps1',
    'demo_nonce_state_roundtrip.ps1',   # OIDC Core — nonce→id_token verbatim, state echo
    'demo_authz_negative_matrix.ps1',   # RFC 6749 §4.1.2.1 — /authorize error contracts + open-redirect guard
    'demo_auth_extras.ps1',             # RFC 9207 iss + prompt=none + form_post + fragment
    'demo_device_code.ps1',
    'demo_device_code_ci.ps1',          # RFC 8628 non-interactive shape + authorization_pending
    'demo_token_exchange.ps1',
    'demo_refresh_rotation.ps1',
    'demo_introspect_revoke.ps1',
    'demo_jwt.ps1',
    'demo_userinfo.ps1',                # RFC 6750 §3 — GET/POST + 400/401 + WWW-Authenticate challenge on errors
    'demo_claim_probes.ps1',            # OIDC §2/§5.1.1 + RFC 8176 — id_token claim shapes; §5.4 — asserts scope-derived PII is NOT in the id_token
    'demo_claims_parameter.ps1',        # OIDC §5.5 — the `claims` request parameter: userinfo/id_token members, essential/value/values, pinned-sub refusal
    'demo_loopback_redirect.ps1',       # RFC 8252 §7.3 — loopback redirect, port not compared; mostly negatives (localhost, path, scheme, off-box all refused)
    'demo_prompt_max_age.ps1',          # OIDC §3.1.2.1 prompt=login/consent/select_account + max_age (auth_time enforcement)
    'demo_admin_scopes.ps1',            # IdentityScopes granular admin probes (identity:read cross-path GET, identity:audit:read narrow)
    'demo_sessions_admin.ps1',          # admin /sessions list/revoke/all (identity:sessions:write identity:tokens:write + dryRun)
    'demo_groups_roles_claims.ps1',     # OIDC scope→claim: groups (direct + ancestors) + role (per-membership label rotation/removal)
    'demo_application_allowed_groups.ps1', # β — per-application group whitelist (ApplicationProps.AllowedGroups) — gate sign-in at token endpoint with access_denied
    'demo_admin_password_reset.ps1',    # admin-side password reset (no OldPassword) + session revocation
    'demo_claim_definitions.ps1',       # S2 — global claim schema (required/type/regex) + admin CRUD + ClaimSchemaValidator gate
    'demo_claim_definitions_per_app.ps1', # S2.4 — per-app required gate + EmitOnIdToken/AccessToken at token issuance
    'demo_roles_registry.ps1',          # B.3 — first-class Roles registry: org/app audience, direct + group→role, audience-scoped emit
    'demo_role_permissions.ps1',        # B.3 (permission picker) — role↔scope binding union'd into granted scope at token issuance
    'demo_bootstrap_admin_role.ps1',    # B.3 — bootstrap admin user is mirrored into the admin system role (regression on commit 12b2fcaf)
    'demo_sessions_admin_browse.ps1',   # S-track: GET /sessions (no userId) → admin-wide paginated browse; powers /admin/sessions default view
    'demo_webhooks.ps1',                # W1 — outbound webhook subscriptions: HMAC-SHA256 sign, retry, rotate-secret, filter, delete
    'demo_session_lifecycle.ps1',       # S-track: LastAccessedAt + idle/absolute timeouts + lazy/eager expiry + touch hook
    'demo_acr_values.ps1',              # OIDC Core §2 acr claim probe (single-factor=1, MFA=2) + acr_values voluntary contract
    'demo_scim_bulk.ps1',               # RFC 7644 §3.7 Bulk: POST + DELETE mix, failOnErrors early-stop, continue-on-error
    'demo_scim_etag.ps1',               # RFC 7644 §3.14 ETag concurrency: POST emits ETag, PUT If-Match honoured, 412 on stale
    'demo_scim_enterprise.ps1',         # RFC 7643 §4.3 Enterprise User: department/manager/employeeNumber, PATCH by URN, PUT-clears-extension
    'demo_throttle_rfc6585.ps1',        # RFC 6585 §4 + RFC 7231 §7.1.3 — 429 + Retry-After on rate-limit (KeyedThrottle.RejectOnOverflow)
    'demo_jwks_rotation.ps1',           # signing-key lifecycle: admin rotate/retire + live JWKS observability + old-token validation across the grace window
    # ── Self-service + MFA ────────────────────────────────────────────────────
    'demo_me_profile.ps1',
    'demo_me_delete.ps1',                 # self-service DELETE /me — cascade revoke sessions/auths + soft-delete + login immutability + idempotency
    'demo_password_change_negatives.ps1', # H10 password policy gate (wrong-old / weak / history / 401)
    'demo_password_reset.ps1',            # N-4 Session C anonymous forgot/reset + anti-enum + GreenMail intercept
    'demo_me_sessions.ps1',
    'demo_me_email_change.ps1',
    'demo_mfa_totp.ps1',
    'demo_mfa_disable_replace.ps1',       # MFA disable + re-enrol mints a fresh secret
    'demo_mfa_recovery_codes.ps1',
    # ── Provisioning ──────────────────────────────────────────────────────────
    'demo_account_register_verify.ps1',
    'demo_scim.ps1'
)

$demos = $ordered | Where-Object {
    $path = Join-Path $here $_
    if (-not (Test-Path $path)) { return $false }
    if ($Only -ne '' -and $_ -notmatch [regex]::Escape($Only)) { return $false }
    if (-not $IncludeInteractive -and $interactive -contains $_) { return $false }
    return $true
}

if (-not $demos -or $demos.Count -eq 0) {
    Write-Host "No demos matched filter '$Only'." -ForegroundColor Yellow
    exit 1
}

Write-Host "=== running $($demos.Count) demo(s) ===" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]
$totalSw = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($demo in $demos) {
    $demoPath = Join-Path $here $demo
    $logPath = Join-Path $logDir ($demo -replace '\.ps1$', '.log')
    Write-Host ""
    Write-Host "--- $demo ---" -ForegroundColor Cyan

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & pwsh -NoLogo -NoProfile -File $demoPath 2>&1 | Tee-Object -FilePath $logPath
    $sw.Stop()
    $code = $LASTEXITCODE

    $status = if ($code -eq 0) { 'PASS' } else { "FAIL($code)" }
    $color = if ($code -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("--- {0}: {1} in {2:N0} ms ---" -f $demo, $status, $sw.Elapsed.TotalMilliseconds) -ForegroundColor $color

    $results.Add([pscustomobject]@{
        Demo    = $demo
        Status  = $status
        Ms      = [int]$sw.Elapsed.TotalMilliseconds
        LogFile = $logPath
    })

    if ($StopOnFail -and $code -ne 0) {
        Write-Host "StopOnFail set — aborting." -ForegroundColor Yellow
        break
    }
}

$totalSw.Stop()

Write-Host ""
Write-Host "=== summary ===" -ForegroundColor Cyan
$results | Format-Table Demo, Status, Ms -AutoSize | Out-Host

$passed = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$failed = $results.Count - $passed
$line = "{0}/{1} passed ({2} failed) in {3:N0} ms total" -f $passed, $results.Count, $failed, $totalSw.Elapsed.TotalMilliseconds
$lineColor = if ($failed -eq 0) { 'Green' } else { 'Red' }
Write-Host $line -ForegroundColor $lineColor
Write-Host "logs: $logDir" -ForegroundColor DarkGray

if ($failed -gt 0) { exit 1 } else { exit 0 }
