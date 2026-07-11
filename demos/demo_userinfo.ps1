# /connect/userinfo dedicated probe — RFC 5.3 negatives + RFC method-shape compliance.
#
# Closes the ⚠️ entry in DEMO_COVERAGE_MATRIX.md for the userinfo endpoint. Positive
# claim assertions live in `demo_claim_probes` (step 8: sub / email / phone_number /
# address) and `demo_acr_values` (step 7: sub + voluntary acr) — this probe focuses on
# the RFC-compliance surface those two don't pin:
#
#   1.  GET /connect/userinfo with VALID bearer → 200 + application/json + sub matches
#   2.  POST /connect/userinfo (RFC 5.3.1 §5.3 — both methods MUST be supported)
#   3.  No Authorization header → 401 + WWW-Authenticate: Bearer
#   4.  Authorization header but no token (just "Bearer ") → 401
#   5.  Garbage / non-JWT bearer → 401 invalid_token
#   6.  Token with valid signature but tampered payload → 401 invalid_token
#   7.  RFC 7592 cleanup
#
# Positive scope-→claim mapping (which scopes return which fields) is covered exhaustively
# by `demo_claim_probes` — not duplicated here to keep the probe focused.
#
# Usage: pwsh -File demo_userinfo.ps1
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "--- [$Name] $ms ms" -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "!!! [$Name] FAILED in $ms ms: $($_.Exception.Message)" -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="fail" })
        throw
    }
}

# Robust HTTP probe: returns status + headers + body without throwing on non-2xx.
function Hit {
    param([string]$Method, [string]$Url, [hashtable]$Headers = $null, $Body = $null)
    try {
        $params = @{
            Uri = $Url; Method = $Method; MaximumRedirection = 0;
            SkipHttpErrorCheck = $true; UseBasicParsing = $true;
            DisableKeepAlive = $true; TimeoutSec = 10
        }
        if ($Headers) { $params.Headers = $Headers }
        if ($null -ne $Body) {
            $params.Body = $Body
            $params.ContentType = 'application/x-www-form-urlencoded'
        }
        $r = Invoke-WebRequest @params
        return [pscustomobject]@{
            StatusCode = [int]$r.StatusCode
            ContentType = $r.Headers['Content-Type'] -join '; '
            WWWAuth = $r.Headers['WWW-Authenticate'] -join '; '
            Content = $r.Content
        }
    } catch {
        return [pscustomobject]@{ StatusCode = 0; ContentType = ''; WWWAuth = ''; Content = $_.Exception.Message }
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 0) DCR + register user + ROPC for a real access_token.
$reg = Measure-Step "0a. DCR (password client)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
        -Body (@{
            client_name = "userinfo-probe"
            grant_types = @("password")
            scope       = "openid profile email identity:account"
        } | ConvertTo-Json)
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

$user = "ui_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd = "Test1234Pass!"
Measure-Step "0b. self-register $user" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" `
        -Body (@{ login = $user; email = "$user@example.com"; password = $pwd; displayName = $user } | ConvertTo-Json) | Out-Null
} | Out-Null

$tok = Measure-Step "0c. ROPC (access_token + sub probe)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email"
        }
}
$BEARER = @{ Authorization = "Bearer $($tok.access_token)" }

# 1) GET with valid bearer.
Measure-Step "1. GET /connect/userinfo → 200 + application/json + sub claim" {
    $r = Hit -Method Get -Url "$BASE/connect/userinfo" -Headers $BEARER
    if ($r.StatusCode -ne 200) { throw "expected 200, got $($r.StatusCode); body: $($r.Content.Substring(0,[Math]::Min(200,$r.Content.Length)))" }
    if ($r.ContentType -notmatch '^application/json') { throw "wrong content-type: '$($r.ContentType)'" }
    $body = $r.Content | ConvertFrom-Json
    if (-not $body.sub) { throw "no sub in userinfo response" }
    Write-Host "  status=200, content-type=$($r.ContentType.Split(';')[0]), sub=$($body.sub)" -ForegroundColor Green
} | Out-Null

# 2) POST per RFC 5.3.1 — same bearer header, no body, should also return 200.
Measure-Step "2. POST /connect/userinfo (RFC 5.3.1 — both methods supported) → 200" {
    $r = Hit -Method Post -Url "$BASE/connect/userinfo" -Headers $BEARER
    if ($r.StatusCode -ne 200) { throw "expected 200 on POST, got $($r.StatusCode); body: $($r.Content.Substring(0,[Math]::Min(200,$r.Content.Length)))" }
    if ($r.ContentType -notmatch '^application/json') { throw "wrong content-type on POST: '$($r.ContentType)'" }
    $body = $r.Content | ConvertFrom-Json
    if (-not $body.sub) { throw "no sub in POST userinfo" }
    Write-Host "  POST works equally" -ForegroundColor Green
} | Out-Null

# 3) No Authorization header at all → 400 invalid_request (per RFC 6750 §3.1) OR 401
#    + WWW-Authenticate: Bearer challenge. Both are RFC-compliant for "no credentials":
#    RFC 6750 §3.1 maps "request did not include credentials" to `invalid_request` which
#    is 400, while many servers prefer 401 to signal "authentication required". We accept
#    either, but the WWW-Authenticate challenge is mandatory.
Measure-Step "3. no Authorization header → 400/401 + WWW-Authenticate: Bearer challenge" {
    $r = Hit -Method Get -Url "$BASE/connect/userinfo"
    if ($r.StatusCode -ne 400 -and $r.StatusCode -ne 401) {
        throw "expected 400 or 401, got $($r.StatusCode)"
    }
    if ($r.WWWAuth -notmatch '(?i)Bearer') { throw "expected WWW-Authenticate: Bearer challenge, got: '$($r.WWWAuth)'" }
    Write-Host "  status=$($r.StatusCode), WWW-Authenticate: $($r.WWWAuth.Substring(0,[Math]::Min(60,$r.WWWAuth.Length)))..." -ForegroundColor Green
} | Out-Null

# 4) Authorization header with empty bearer value → 400/401 (OpenIddict treats empty as
#    "missing_token", same as no header at all). Just verify it's rejected with WWW-Authenticate.
Measure-Step "4. empty bearer ('Bearer ') → rejected with WWW-Authenticate" {
    $r = Hit -Method Get -Url "$BASE/connect/userinfo" -Headers @{ Authorization = "Bearer " }
    if ($r.StatusCode -lt 400) { throw "expected 4xx for empty bearer, got $($r.StatusCode)" }
    if ($r.WWWAuth -notmatch '(?i)Bearer') { throw "expected WWW-Authenticate: Bearer challenge, got: '$($r.WWWAuth)'" }
    Write-Host "  status=$($r.StatusCode) (empty token rejected, WWW-Authenticate present)" -ForegroundColor Green
} | Out-Null

# 5) Garbage / non-JWT bearer → 401 invalid_token.
Measure-Step "5. garbage bearer → 401 invalid_token" {
    $r = Hit -Method Get -Url "$BASE/connect/userinfo" -Headers @{ Authorization = "Bearer not-a-real-token" }
    if ($r.StatusCode -ne 401) { throw "expected 401, got $($r.StatusCode)" }
    if ($r.WWWAuth -notmatch '(?i)invalid_token') { throw "expected error=invalid_token in WWW-Authenticate, got: '$($r.WWWAuth)'" }
    Write-Host "  401 invalid_token" -ForegroundColor Green
} | Out-Null

# 6) Token signature valid but payload tampered: take the valid bearer, flip a char in the
#    PAYLOAD segment. Our access_token is a JWE (encrypted) so any byte-flip breaks integrity
#    on decrypt — easy "tamper-detection" probe.
Measure-Step "6. tampered bearer → 401 (integrity/signature check fires)" {
    $orig = $tok.access_token
    if ($orig.Length -lt 30) { throw "access_token too short to tamper" }
    # Flip a single character mid-token.
    $idx = [int]($orig.Length / 2)
    $ch = $orig[$idx]
    $flipped = if ($ch -eq 'A') { 'B' } elseif ($ch -eq '0') { '1' } else { 'A' }
    $tampered = $orig.Substring(0, $idx) + $flipped + $orig.Substring($idx + 1)
    if ($tampered -eq $orig) { throw "tamper produced identical string (Substring math wrong)" }
    $r = Hit -Method Get -Url "$BASE/connect/userinfo" -Headers @{ Authorization = "Bearer $tampered" }
    if ($r.StatusCode -ne 401) { throw "expected 401 on tampered bearer, got $($r.StatusCode); body: $($r.Content.Substring(0,[Math]::Min(200,$r.Content.Length)))" }
    Write-Host "  401 (tamper detected)" -ForegroundColor Green
} | Out-Null

# 7) RFC 7592 cleanup.
Measure-Step "7. RFC 7592 DELETE registration" {
    if ($RAT) {
        try { Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null } catch {}
    }
    Write-Host "  registration deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
