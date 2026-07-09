# Self-service session management — /api/v1/identity/me/sessions.
#   Bearer auth uses identity:account scope (not identity:manage). Caller can only
#   touch their own sessions; sub claim is the source of truth, never the body.
#   Coverage: GET list, DELETE /{id}, DELETE /others, DELETE /current.
# Usage: pwsh -File demo_me_sessions.ps1

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

function Get-Token {
    param([string]$ClientId, [string]$ClientSecret, [string]$User, [string]$Pwd)
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $ClientId
        client_secret = $ClientSecret
        username      = $User
        password      = $Pwd
        scope         = "openid profile email offline_access identity:account"
      }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR with identity:account so /me/sessions is authorized.
$reg = Measure-Step "1. DCR /connect/register (password + identity:account)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "sess-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access identity:account"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "sess_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd = "Test1234Pass!"
Measure-Step "2. account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = "$user@example.com"
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json)
} | Out-Null

# 3) Open THREE sessions by hitting /token three times — each ROPC call mints a
#    fresh session row (different sid claim).
$sessTokens = @()
for ($i = 1; $i -le 3; $i++) {
    $t = Measure-Step "3.$i password grant — open session #$i" {
        Get-Token $reg.client_id $reg.client_secret $user $pwd
    }
    $sessTokens += ,$t
    Start-Sleep -Milliseconds 250  # let `iat` differ for readability in the list
}
$current = $sessTokens[-1]   # we'll pose as "this device" with the last token
$bearer  = @{ Authorization = "Bearer $($current.access_token)" }

# 4) GET /me/sessions — should list at least 3.
$sessions = Measure-Step "4. GET /api/v1/identity/me/sessions" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/sessions" -Headers $bearer
}
$sessions | ConvertTo-Json -Depth 5 | Out-Host

# Detect the array shape — the controller returns either a raw array or
# { items: [...] } depending on the processor; handle both.
$items = if ($sessions -is [System.Array]) { $sessions } `
         elseif ($sessions.items) { $sessions.items } `
         elseif ($sessions.sessions) { $sessions.sessions } `
         else { @($sessions) }
Write-Host "  total sessions listed: $($items.Count)" -ForegroundColor Yellow
if ($items.Count -lt 3) {
    Write-Host "  ! expected ≥3 sessions, got $($items.Count) — server may de-dupe by client_id" -ForegroundColor Yellow
}

# 5) Revoke one specific session by id (pick the first one that is NOT current —
#    we identify "current" heuristically by trying both `id` / `sessionId` keys).
$victim = $items | Where-Object {
    $idVal = if ($_.id) { $_.id } elseif ($_.sessionId) { $_.sessionId } else { $null }
    $idVal -and ($idVal -ne $current.sid)
} | Select-Object -First 1

if ($null -ne $victim) {
    $victimId = if ($victim.id) { $victim.id } else { $victim.sessionId }
    Measure-Step "5. DELETE /api/v1/identity/me/sessions/$victimId (specific)" {
        Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me/sessions/$victimId" -Headers $bearer
    } | Out-Null
} else {
    Write-Host "  (skipping specific-session revoke — couldn't pick a victim id)" -ForegroundColor DarkGray
}

# 6) Revoke /others — kill all sessions except the one the current bearer was issued for.
Measure-Step "6. DELETE /api/v1/identity/me/sessions/others" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me/sessions/others" -Headers $bearer
} | Out-Null

# 7) After /others — list should now contain only the current session.
$after = Measure-Step "7. GET /api/v1/identity/me/sessions (after /others)" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/sessions" -Headers $bearer
}
$afterItems = if ($after -is [System.Array]) { $after } `
              elseif ($after.items) { $after.items } `
              elseif ($after.sessions) { $after.sessions } `
              else { @($after) }
Write-Host "  remaining sessions: $($afterItems.Count)" -ForegroundColor Yellow
if ($afterItems.Count -le 1) {
    Write-Host "  ✓ /others left only the current session" -ForegroundColor Green
} else {
    Write-Host "  ! expected 1 remaining session, got $($afterItems.Count)" -ForegroundColor Yellow
}

# 8) Verify a previously-issued (now-revoked) access_token can no longer hit /me/sessions.
#    sessTokens[0] was killed by /others above.
Measure-Step "8. revoked token rejected (/me/sessions with sessTokens[0])" {
    try {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/sessions" `
          -Headers @{ Authorization = "Bearer $($sessTokens[0].access_token)" } | Out-Null
        Write-Host "  ! revoked token still works — session-revocation NOT enforced on access_token" -ForegroundColor Yellow
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 401, 403) {
            Write-Host "  ✓ rejected: status=$code" -ForegroundColor Green
        } else {
            Write-Host "  ! unexpected status=$code (access_token may live until exp regardless of session)" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 9) DELETE /current — revoke the bearer's own session. Subsequent calls must fail.
#    NOTE: ROPC-issued tokens may not carry a `sid` claim (session binding is per
#    OIDC session/cookie flow). When that's the case the server replies
#    400 sid_unavailable — we accept that as expected and skip step 10.
$sidUnavailable = $false
Measure-Step "9. DELETE /api/v1/identity/me/sessions/current" {
    try {
        Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me/sessions/current" -Headers $bearer | Out-Null
        Write-Host "  ✓ /current revoked" -ForegroundColor Green
    } catch {
        $code = $null; $body = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        # PS 7+: response body lives on $_.ErrorDetails.Message; PS 5 uses GetResponseStream.
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = $_.ErrorDetails.Message }
        if (-not $body) {
            try {
                $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $sr.ReadToEnd()
            } catch {}
        }
        if ($code -eq 400 -and $body -match 'sid_unavailable') {
            Write-Host "  (skipped: ROPC token has no sid claim — sid_unavailable is expected)" -ForegroundColor DarkGray
            $script:sidUnavailable = $true
        } else { throw }
    }
} | Out-Null

if (-not $sidUnavailable) {
    Measure-Step "10. /me/sessions after /current (expect 401/403)" {
        try {
            Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/sessions" -Headers $bearer | Out-Null
            Write-Host "  ! current bearer still works after self-revoke" -ForegroundColor Yellow
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -in 401, 403) {
                Write-Host "  ✓ rejected: status=$code" -ForegroundColor Green
            } else { throw }
        }
    } | Out-Null
}

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
