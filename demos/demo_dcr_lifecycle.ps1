# DCR full lifecycle (RFC 7591 + RFC 7592):
#   POST /connect/register → GET → PUT → DELETE → confirm 404.
# Usage: pwsh -File demo_dcr_lifecycle.ps1

$BASE = "http://127.0.0.1:5002"
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

# 1) POST /connect/register — issuer mints client_id + registration_access_token (rat).
$reg = Measure-Step "1. POST /connect/register (RFC 7591)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "lifecycle-demo-v1"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("authorization_code","refresh_token")
        scope         = "openid profile email"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret, registration_access_token, registration_client_uri

if (-not $reg.registration_access_token) {
    throw "server did not return registration_access_token — RFC 7592 management not supported"
}
$rat = $reg.registration_access_token
$mgmtUri = if ($reg.registration_client_uri) { $reg.registration_client_uri } else { "$BASE/connect/register/$($reg.client_id)" }
$ratHeader = @{ Authorization = "Bearer $rat" }

# 2) GET — read current registration (RFC 7592).
$cur = Measure-Step "2. GET registration (RFC 7592)" {
    Invoke-RestMethod -Method Get $mgmtUri -Headers $ratHeader
}
Write-Host "  client_name : $($cur.client_name)"
Write-Host "  grants      : $($cur.grant_types -join ', ')"
Write-Host "  scope       : $($cur.scope)"

# 3) PUT — update client_name + scope.
$updated = Measure-Step "3. PUT registration (rename + add offline_access)" {
    $body = @{
        client_id     = $reg.client_id
        client_name   = "lifecycle-demo-v2"
        redirect_uris = @("http://localhost:9999/cb","http://localhost:9999/cb2")
        grant_types   = @("authorization_code","refresh_token")
        scope         = "openid profile email offline_access"
    } | ConvertTo-Json
    Invoke-RestMethod -Method Put $mgmtUri -Headers $ratHeader -ContentType "application/json" -Body $body
}
Write-Host "  client_name : $($updated.client_name) (was: lifecycle-demo-v1)"
Write-Host "  scope       : $($updated.scope)"
Write-Host "  redirects   : $($updated.redirect_uris -join ', ')"

# 4) GET again — verify the update stuck.
$check = Measure-Step "4. GET registration (verify update)" {
    Invoke-RestMethod -Method Get $mgmtUri -Headers $ratHeader
}
if ($check.client_name -ne "lifecycle-demo-v2") {
    Write-Host "  WARNING: name did not persist (got: $($check.client_name))" -ForegroundColor Red
} else {
    Write-Host "  ✓ rename persisted" -ForegroundColor Green
}

# 5) DELETE — remove the client.
Measure-Step "5. DELETE registration" {
    Invoke-WebRequest -Method Delete $mgmtUri -Headers $ratHeader -ErrorAction Stop | Out-Null
} | Out-Null

# 6) GET — expect 401/404 (deleted).
Measure-Step "6. GET after DELETE (expect 401/404)" {
    try {
        $r = Invoke-WebRequest -Method Get $mgmtUri -Headers $ratHeader -ErrorAction Stop
        Write-Host ("  UNEXPECTED success status={0}" -f $r.StatusCode) -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 401,404) {
            Write-Host ("  ✓ gone as expected: {0}" -f $code) -ForegroundColor Green
        } else {
            throw "unexpected status $code"
        }
    }
} | Out-Null

# 7) Try to use the deleted client at /connect/token — should fail.
Measure-Step "7. /connect/token with deleted client (expect failure)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "client_credentials"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
          } -ErrorAction Stop | Out-Null
        Write-Host "  UNEXPECTED success — deleted client got tokens" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host ("  ✓ token request rejected: {0}" -f $code) -ForegroundColor Green
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
