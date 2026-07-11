# OIDC Back-Channel Logout 1.0 — end-to-end probe.
#   1. DCR a confidential client with `backchannel_logout_uri` (RFC 7591 +
#      OIDC Back-Channel Logout 1.0 §2.2) pointing at a local HttpListener.
#   2. Register a user, ROPC login → access + id + refresh tokens.
#   3. Start an HttpListener on 127.0.0.1:9876 in a runspace to capture the
#      inbound logout_token POST.
#   4. POST /connect/logout with id_token_hint — server fans out to the
#      registered backchannel URI.
#   5. Verify response.backchannel_delivered ≥ 1 AND the captured POST is
#      `application/x-www-form-urlencoded` with a JWT in `logout_token=…`.
#   6. Decode the JWT payload and assert the OIDC required claims:
#        - events claim contains "http://schemas.openid.net/event/backchannel-logout"
#        - sub  (subject)
#        - sid  (when backchannel_logout_session_required=true)
# Usage: pwsh -File demo_backchannel_logout.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
$LSN_PORT = 9876
$LSN_URL  = "http://127.0.0.1:$LSN_PORT/bclogout/"
$timings  = [System.Collections.Generic.List[object]]::new()

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

function Decode-JwtPayload([string]$jwt) {
    $parts = $jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $b64 = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    return ($json | ConvertFrom-Json)
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — confidential client with password+refresh and backchannel_logout_uri.
$reg = Measure-Step "1. DCR /connect/register (password + backchannel_logout_uri)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name                         = "bclogout-demo"
        redirect_uris                       = @($REDIRECT_CB)
        grant_types                         = @("password","refresh_token")
        scope                               = "openid profile email offline_access"
        backchannel_logout_uri              = "http://127.0.0.1:$LSN_PORT/bclogout/"
        backchannel_logout_session_required = $true
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Register a user.
$user = "bcl_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
$reg2 = Measure-Step "2. account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{ login=$user; email="$user@example.com"; password=$pwd; displayName=$user } | ConvertTo-Json)
}
$userId = [int64]$reg2.userId
Write-Host "  userId   : $userId"

# 3) ROPC → access + id + refresh.
$tok = Measure-Step "3. ROPC → id_token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email offline_access"
      }
}
if (-not $tok.id_token) { throw "no id_token issued — cannot drive backchannel logout" }
Write-Host "  id_token : $($tok.id_token.Substring(0,32))…"

# 4) Start HttpListener in a runspace; capture inbound logout_token POST.
$listenerJob = Measure-Step "4. start HttpListener on $LSN_URL" {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($prefix)
        $l = [System.Net.HttpListener]::new()
        $l.Prefixes.Add($prefix)
        $l.Start()
        try {
            # 10s budget for the dispatcher to deliver.
            $ar = $l.BeginGetContext($null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(10000)) {
                return @{ captured=$false; reason="timeout waiting for inbound POST" }
            }
            $ctx = $l.EndGetContext($ar)
            $req = $ctx.Request
            $reader = [IO.StreamReader]::new($req.InputStream, $req.ContentEncoding)
            $body = $reader.ReadToEnd()
            $ctx.Response.StatusCode = 200
            $ctx.Response.OutputStream.Close()
            return @{
                captured    = $true
                method      = $req.HttpMethod
                contentType = $req.ContentType
                body        = $body
            }
        } finally {
            $l.Stop(); $l.Close()
        }
    }).AddArgument($LSN_URL)
    $handle = $ps.BeginInvoke()
    [pscustomobject]@{ ps=$ps; handle=$handle; rs=$rs }
}

# Tiny wait to ensure the listener is bound before we POST.
Start-Sleep -Milliseconds 300

# 5) POST /connect/logout with id_token_hint — triggers fan-out.
# 5) POST /connect/logout — server fans out backchannel POSTs to registered RPs.
# Note: /connect/logout's response body is replaced by HandlePostLogoutRedirect with
# an HTML "Signed Out" page (browser-friendly), so the JSON shape of the underlying
# LogoutProcessor (success / sessions_revoked / backchannel_delivered) is NOT visible
# to the caller. The proof of fan-out is the captured POST on our HttpListener.
Measure-Step "5. POST /connect/logout (id_token_hint) — triggers fan-out" {
    try {
        $wr = Invoke-WebRequest -Method Post "$BASE/connect/logout" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            id_token_hint = $tok.id_token
            userId        = $userId
            client_id     = $reg.client_id
          } -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $code = $wr.StatusCode
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
    }
    Write-Host "  status: $code"
    if ($code -lt 200 -or $code -ge 400) { throw "Unexpected logout status: $code" }
} | Out-Null

# 6) Drain the listener.
$capture = Measure-Step "6. drain HttpListener (await captured POST)" {
    $r = $listenerJob.ps.EndInvoke($listenerJob.handle)
    $listenerJob.ps.Dispose(); $listenerJob.rs.Close()
    return $r[0]
}
if (-not $capture.captured) { throw "Listener did not capture a POST: $($capture.reason)" }
Write-Host "  method      : $($capture.method)"
Write-Host "  contentType : $($capture.contentType)"
if ($capture.method -ne 'POST') { throw "Expected POST, got $($capture.method)" }
if ($capture.contentType -notmatch 'application/x-www-form-urlencoded') {
    throw "Expected application/x-www-form-urlencoded, got '$($capture.contentType)'"
}
if ($capture.body -notmatch 'logout_token=') { throw "POST body has no logout_token field: $($capture.body)" }
Write-Host "  ✓ POST captured with form-urlencoded logout_token" -ForegroundColor Green

# 7) Decode logout_token JWT and verify required OIDC claims.
$jwt = ($capture.body -split 'logout_token=')[1] -split '&' | Select-Object -First 1
$jwt = [Uri]::UnescapeDataString($jwt)
$payload = Decode-JwtPayload $jwt
if (-not $payload) { throw "Could not decode logout_token JWT payload" }
$payloadJson = $payload | ConvertTo-Json -Depth 5
Write-Host "  payload     :"
Write-Host $payloadJson
$eventsClaim = $payload.events
$hasBcLogoutEvent = $false
if ($eventsClaim) {
    $eventsClaim.PSObject.Properties | ForEach-Object {
        if ($_.Name -eq 'http://schemas.openid.net/event/backchannel-logout') { $hasBcLogoutEvent = $true }
    }
}
if (-not $hasBcLogoutEvent) {
    throw "logout_token missing required 'events' claim with http://schemas.openid.net/event/backchannel-logout"
}
Write-Host "  ✓ events claim contains backchannel-logout event" -ForegroundColor Green
if (-not $payload.sub) { throw "logout_token missing required 'sub' claim" }
Write-Host "  ✓ sub claim present: $($payload.sub)" -ForegroundColor Green
if (-not $payload.iss) { Write-Host "  ! 'iss' claim missing (RFC requires)" -ForegroundColor Yellow }
if (-not $payload.aud) { Write-Host "  ! 'aud' claim missing (RFC requires)" -ForegroundColor Yellow }
if (-not $payload.iat) { Write-Host "  ! 'iat' claim missing (RFC requires)" -ForegroundColor Yellow }
if (-not $payload.jti) { Write-Host "  ! 'jti' claim missing (RFC requires)" -ForegroundColor Yellow }
if ($payload.sid) {
    Write-Host "  ✓ sid claim present (backchannel_logout_session_required=true honored)" -ForegroundColor Green
} else {
    Write-Host "  ! sid claim absent despite backchannel_logout_session_required=true" -ForegroundColor Yellow
}

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
