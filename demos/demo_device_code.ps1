# Device authorization flow (RFC 8628). Requires a user to manually approve
# the device by visiting the verification URI in a browser within the timeout.
#
# Usage: pwsh -File demo_device_code.ps1

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

# 1) Register a client that supports device_code.
$reg = Measure-Step "1. DCR /connect/register (device_code)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name = "device-demo"
        grant_types = @("urn:ietf:params:oauth:grant-type:device_code","refresh_token")
        scope       = "openid profile offline_access"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Initiate the device-authorization request.
$dev = Measure-Step "2. POST /connect/deviceauthorization" {
    Invoke-RestMethod -Method Post "$BASE/connect/deviceauthorization" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        scope         = "openid profile offline_access"
      }
}
$dev | Format-List device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval

Write-Host ""
Write-Host "  ╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "  ║  ACTION REQUIRED — APPROVE THE DEVICE IN A BROWSER         ║" -ForegroundColor Yellow
Write-Host "  ╠════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
Write-Host ("  ║  Open: {0,-52}║" -f $dev.verification_uri)              -ForegroundColor Yellow
Write-Host ("  ║  Code: {0,-52}║" -f $dev.user_code)                     -ForegroundColor Yellow
if ($dev.verification_uri_complete) {
    Write-Host ("  ║  Or one-shot: {0,-45}║" -f $dev.verification_uri_complete) -ForegroundColor Yellow
}
Write-Host "  ╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

# 3) Poll until approved or expired.
$tok = Measure-Step "3. poll /connect/token (grant=device_code)" {
    $deadline = (Get-Date).AddSeconds([int]$dev.expires_in)
    $interval = [int]$dev.interval
    if ($interval -lt 1) { $interval = 5 }
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $r = Invoke-RestMethod -Method Post "$BASE/connect/token" `
              -ContentType "application/x-www-form-urlencoded" `
              -Body @{
                grant_type    = "urn:ietf:params:oauth:grant-type:device_code"
                client_id     = $reg.client_id
                client_secret = $reg.client_secret
                device_code   = $dev.device_code
              }
            return $r
        } catch {
            $errBody = $null
            try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            $code = if ($errBody) { $errBody.error } else { "unknown" }
            switch ($code) {
                "authorization_pending" {
                    Write-Host ("  [{0:N0}] pending — sleep {1}s" -f $attempt, $interval) -ForegroundColor DarkGray
                    Start-Sleep -Seconds $interval
                }
                "slow_down" {
                    $interval += 5
                    Write-Host ("  [{0:N0}] slow_down — interval bumped to {1}s" -f $attempt, $interval) -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $interval
                }
                default {
                    throw "device flow rejected: $code — $($errBody.error_description)"
                }
            }
        }
    }
    throw "device flow timed out after $($dev.expires_in)s"
}
$tok | Format-List access_token, refresh_token, expires_in

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
