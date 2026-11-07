# Conformance probe — OpenID "Config OP" profile.
# Audits /.well-known/openid-configuration + jwks against OIDC Discovery 1.0 §3 and
# the OpenID conformance-suite Config OP expectations.
#
# HARD FAIL  → real spec violation (throws, demo FAILS): missing REQUIRED field,
#              advertised-but-unbacked signing alg, PKCE/S256 or code response-type absent, etc.
# WARN       → recommended/expected field absent OR a certification-scope decision
#              (collected + printed at end, does NOT fail the demo).
#
# See doc/OPENID_CONFORMANCE_LOCAL_PLAN.md (Track B, F1).
# Usage: pwsh -File demo_conformance_discovery_config.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$timings = [System.Collections.Generic.List[object]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
function Add-Warn([string]$m) { $warnings.Add($m); Write-Host "  ⚠ $m" -ForegroundColor Yellow }

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# ── 1. Fetch discovery ────────────────────────────────────────────────────────
$disc = Measure-Step "1. GET /.well-known/openid-configuration" {
    Invoke-RestMethod "$BASE/.well-known/openid-configuration"
}

# ── 2. REQUIRED fields (OIDC Discovery §3) — hard fail ─────────────────────────
Measure-Step "2. required fields present (OIDC Discovery §3)" {
    $required = @(
        'issuer','authorization_endpoint','token_endpoint','jwks_uri',
        'response_types_supported','subject_types_supported','id_token_signing_alg_values_supported'
    )
    $missing = $required | Where-Object { -not $disc.PSObject.Properties.Name.Contains($_) }
    if ($missing) { throw "missing REQUIRED discovery fields: $($missing -join ', ')" }
    Write-Host "  ✓ all $($required.Count) required fields present" -ForegroundColor Green
} | Out-Null

# ── 3. Core value locks — hard fail ───────────────────────────────────────────
Measure-Step "3. response_types / subject_types / PKCE value locks" {
    if (@($disc.response_types_supported) -notcontains 'code') {
        throw "response_types_supported must contain 'code' (authorization code flow); got [$($disc.response_types_supported -join ', ')]"
    }
    if (@($disc.subject_types_supported) -notcontains 'public') {
        throw "subject_types_supported must contain 'public'; got [$($disc.subject_types_supported -join ', ')]"
    }
    # PKCE is enforced server-side → S256 MUST be advertised (OIDC Core / RFC 7636).
    if (@($disc.code_challenge_methods_supported) -notcontains 'S256') {
        throw "code_challenge_methods_supported must contain 'S256' (PKCE enforced); got [$($disc.code_challenge_methods_supported -join ', ')]"
    }
    if (@($disc.code_challenge_methods_supported) -contains 'plain') {
        Add-Warn "code_challenge_methods_supported advertises 'plain' — Config OP prefers S256-only"
    }
    Write-Host "  ✓ code flow + public subjects + S256 PKCE locked" -ForegroundColor Green
} | Out-Null

# ── 4. JWKS ↔ id_token_signing_alg consistency — hard fail ─────────────────────
Measure-Step "4. jwks_uri reachable & backs advertised id_token algs" {
    $jwks = Invoke-RestMethod $disc.jwks_uri
    if (-not $jwks.keys -or @($jwks.keys).Count -eq 0) { throw "jwks_uri returned no keys" }
    foreach ($k in $jwks.keys) {
        if (-not $k.kty) { throw "a JWK is missing 'kty'" }
        if (-not $k.kid) { throw "a JWK is missing 'kid' (needed for key rollover)" }
    }
    # Every advertised id_token signing alg needs a usable key family in the JWKS.
    $algFamilies = @{ RS='RSA'; PS='RSA'; ES='EC' }
    foreach ($alg in @($disc.id_token_signing_alg_values_supported)) {
        if ($alg -eq 'none') { continue }
        $fam = $algFamilies[$alg.Substring(0,2)]
        if (-not $fam) { continue }
        $match = $jwks.keys | Where-Object { $_.kty -eq $fam }
        if (-not $match) { throw "id_token alg '$alg' advertised but no '$fam' key in JWKS" }
    }
    Write-Host "  ✓ jwks has $((@($jwks.keys)).Count) key(s), all with kty+kid, backing [$($disc.id_token_signing_alg_values_supported -join ', ')]" -ForegroundColor Green
} | Out-Null

# ── 5. Endpoint origin consistency — hard fail ────────────────────────────────
Measure-Step "5. all endpoints share the issuer origin" {
    $issUri = [Uri]($disc.issuer)
    $origin = "{0}://{1}" -f $issUri.Scheme, $issUri.Authority
    $epFields = $disc.PSObject.Properties.Name | Where-Object { $_ -like '*_endpoint' -or $_ -eq 'jwks_uri' }
    $bad = @()
    foreach ($f in $epFields) {
        $v = $disc.$f
        if ($v -is [string] -and $v -notlike "$origin*") { $bad += "$f=$v" }
    }
    if ($bad) { throw "endpoints not under issuer origin '$origin': $($bad -join ', ')" }
    Write-Host "  ✓ every endpoint is under $origin" -ForegroundColor Green
} | Out-Null

# ── 6. RECOMMENDED fields (warn only) ─────────────────────────────────────────
Measure-Step "6. recommended fields (OIDC Discovery §3)" {
    $recommended = @('userinfo_endpoint','registration_endpoint','scopes_supported','claims_supported','response_modes_supported','grant_types_supported')
    foreach ($f in $recommended) {
        if (-not $disc.PSObject.Properties.Name.Contains($f)) { Add-Warn "recommended field '$f' absent" }
    }
    if (@($disc.scopes_supported) -notcontains 'openid') { Add-Warn "scopes_supported does not list 'openid'" }
    Write-Host "  ✓ recommended-field sweep done" -ForegroundColor Green
} | Out-Null

# ── 7. Feature-consistency (warn) — advertise what we actually support ─────────
Measure-Step "7. feature ↔ discovery consistency" {
    # We support acr_values (demo_acr_values) → SHOULD advertise acr_values_supported.
    if (-not $disc.PSObject.Properties.Name.Contains('acr_values_supported')) {
        Add-Warn "acr_values IS supported (demo_acr_values) but 'acr_values_supported' is absent from discovery"
    }
    # claim_types_supported defaults to ['normal']; optional but expected by some RPs.
    if (-not $disc.PSObject.Properties.Name.Contains('claim_types_supported')) {
        Add-Warn "'claim_types_supported' absent (optional; default ['normal'])"
    }
    # userinfo signing alg — only relevant if signed userinfo is offered.
    if (-not $disc.PSObject.Properties.Name.Contains('userinfo_signing_alg_values_supported')) {
        Add-Warn "'userinfo_signing_alg_values_supported' absent (optional unless signed userinfo is offered)"
    }
    # RFC 9207 — we advertise it; assert it is actually true.
    if ($disc.authorization_response_iss_parameter_supported -ne $true) {
        Add-Warn "authorization_response_iss_parameter_supported is not true (RFC 9207)"
    }
    Write-Host "  ✓ feature-consistency sweep done" -ForegroundColor Green
} | Out-Null

# ── 8. issuer hygiene + client-auth scope (warn — cert-scope decisions) ────────
Measure-Step "8. issuer hygiene & token_endpoint_auth_methods scope" {
    if ($disc.issuer.EndsWith('/')) {
        Add-Warn "issuer '$($disc.issuer)' has a TRAILING SLASH — conformance suites form the well-known URL by concatenation and may flag issuer/iss inconsistency. Verify iss claim in tokens matches exactly."
    }
    $authMethods = @($disc.token_endpoint_auth_methods_supported)
    if ($authMethods -notcontains 'client_secret_basic') {
        Add-Warn "token_endpoint_auth_methods_supported lacks 'client_secret_basic' — the Basic OP suite defaults to it. Either add it or certify with client_secret_post."
    }
    if ($authMethods -notcontains 'none') {
        Add-Warn "token_endpoint_auth_methods_supported lacks 'none' — public-client (PKCE, no secret) flows need it for the Basic OP public-client tests."
    }
    Write-Host "  ✓ issuer/auth-scope sweep done" -ForegroundColor Green
} | Out-Null

# ── Summary ───────────────────────────────────────────────────────────────────
$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
Write-Host ""
if ($warnings.Count -gt 0) {
    Write-Host "================ CONFORMANCE WARNINGS ($($warnings.Count)) ================" -ForegroundColor Yellow
    $i = 1; foreach ($w in $warnings) { Write-Host ("  {0}. {1}" -f $i, $w) -ForegroundColor Yellow; $i++ }
    Write-Host "(warnings are recommendations / cert-scope decisions — they do NOT fail this probe)" -ForegroundColor DarkGray
} else {
    Write-Host "No conformance warnings — Config OP discovery is clean." -ForegroundColor Green
}
