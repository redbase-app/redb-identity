# Device Authorization Grant (RFC 8628) — non-interactive CI probe.
#   Validates the response shape of /connect/deviceauthorization and the
#   authorization_pending error path of /connect/token, WITHOUT requiring a
#   human to approve the device. demo_device_code.ps1 covers the happy path
#   (which needs a browser); this script is what CI runs.
#
#   1. DCR client with urn:ietf:params:oauth:grant-type:device_code.
#   2. POST /connect/deviceauthorization → assert RFC 8628 §3.2 fields:
#        device_code, user_code, verification_uri, expires_in, interval
#      and SHOULD field verification_uri_complete (non-blocking).
#   3. POST /connect/token (grant=device_code) ONCE — must return
#      `authorization_pending` (RFC 8628 §3.5). Stop after one poll.
#
# Usage: pwsh -File demo_device_code_ci.ps1

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

# 1) DCR — register client with device_code grant.
$reg = Measure-Step "1. DCR /connect/register (device_code)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name = "device-ci-demo"
        grant_types = @("urn:ietf:params:oauth:grant-type:device_code","refresh_token")
        scope       = "openid profile offline_access"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Initiate device-authorization → validate response fields per RFC 8628 §3.2.
$dev = Measure-Step "2. POST /connect/deviceauthorization (response shape)" {
    Invoke-RestMethod -Method Post "$BASE/connect/deviceauthorization" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        scope         = "openid profile offline_access"
      }
}
$dev | Format-List device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval

# Required fields (RFC 8628 §3.2).
$required = @('device_code','user_code','verification_uri','expires_in')
foreach ($f in $required) {
    if (-not $dev.PSObject.Properties.Name.Contains($f) -or [string]::IsNullOrEmpty([string]$dev.$f)) {
        throw "Missing required RFC 8628 §3.2 field: $f"
    }
}
Write-Host "  ✓ required fields present (device_code, user_code, verification_uri, expires_in)" -ForegroundColor Green

# `interval` is OPTIONAL per RFC, defaults to 5 — warn if absent.
if (-not $dev.interval) {
    Write-Host "  ! 'interval' field absent — clients will assume default 5s" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ interval = $($dev.interval)s" -ForegroundColor Green
}

# `verification_uri_complete` is RECOMMENDED — soft-fail with a yellow warning.
if (-not $dev.verification_uri_complete) {
    Write-Host "  ! verification_uri_complete absent (RFC 8628 §3.2 RECOMMENDED for QR-code UX)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ verification_uri_complete present" -ForegroundColor Green
}

# user_code shape — RFC 8628 §6.1 recommends URL-safe alpha set.
if ($dev.user_code -notmatch '^[A-Z0-9-]+$') {
    Write-Host "  ! user_code contains chars outside the recommended A-Z0-9- alphabet: $($dev.user_code)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ user_code uses RFC-recommended alphabet" -ForegroundColor Green
}

# 3) ONE poll at /connect/token — expect authorization_pending (RFC 8628 §3.5).
Measure-Step "3. POST /connect/token (one poll, expect authorization_pending)" {
    try {
        $r = Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "urn:ietf:params:oauth:grant-type:device_code"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            device_code   = $dev.device_code
          }
        # Should NEVER succeed without user approval.
        throw "Token endpoint returned success without device approval — server bug. tokens: $($r | ConvertTo-Json -Compress)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $errBody = $null
        try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
        $errCode = if ($errBody) { $errBody.error } else { $null }
        if ($code -ne 400) {
            throw "Expected HTTP 400, got $code"
        }
        if ($errCode -ne 'authorization_pending') {
            throw "Expected error=authorization_pending (RFC 8628 §3.5), got '$errCode'"
        }
        Write-Host "  ✓ 400 authorization_pending — RFC 8628 §3.5 polling contract honored" -ForegroundColor Green
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
