# OIDC Back-Channel Logout 1.0 — end-to-end probe, the way a browser does it.
#   1. DCR a public (PKCE) client with `backchannel_logout_uri` (RFC 7591 + OIDC Back-Channel
#      Logout 1.0 §2.2) pointing at a local HttpListener, backchannel_logout_session_required=true.
#   2. Register a user and sign in at the OP through /login with a cookie jar — that is the OP session.
#   3. authorization_code + PKCE through that session → id_token; note its `sub` and `sid`.
#   4. Start the HttpListener; RP-initiated logout: POST /connect/logout with the session cookie and
#      `id_token_hint` (RP-Initiated Logout 1.0 §2).
#   5. The OP POSTs a logout_token to the RP (§2.4): form-urlencoded, a JWT whose `events` claim names
#      the back-channel logout event, whose `sub` equals the id_token's `sub` and whose `sid` equals
#      the id_token's `sid` — the RP ends exactly the session that ended at the OP.
# The endpoint acts on the browser's own session only: a request without the cookie ends nothing,
# whatever it says about the user, so there is no "userId" to send here.
# Usage: pwsh -File demo_backchannel_logout.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$DCR_IAT = if ($env:IDENTITY_DCR_TOKEN) { $env:IDENTITY_DCR_TOKEN } else { "dev-only-initial-access-token-not-for-production" }
$DCR_AUTH = @{ Authorization = "Bearer $DCR_IAT" }
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

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — public authorization_code client (PKCE) with backchannel_logout_uri.
$reg = Measure-Step "1. DCR /connect/register (authorization_code + PKCE, backchannel_logout_uri)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -Headers $DCR_AUTH `
      -ContentType "application/json" `
      -Body (@{
        client_name                         = "bclogout-demo"
        redirect_uris                       = @($REDIRECT_CB)
        grant_types                         = @("authorization_code")
        response_types                      = @("code")
        token_endpoint_auth_method          = "none"
        scope                               = "openid profile email"
        backchannel_logout_uri              = $LSN_URL
        backchannel_logout_session_required = $true
      } | ConvertTo-Json)
}
$reg | Format-List client_id, backchannel_logout_uri

# 2) Register a user.
$user = "bcl_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "2. account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{ login=$user; email="$user@example.com"; password=$pwd; displayName=$user } | ConvertTo-Json)
} | Out-Null

# 3) Sign in at the OP: the cookie jar is the browser, the cookie is the OP session.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Measure-Step "3. POST /login (cookie jar = the OP session)" {
    try {
        Invoke-WebRequest -Method Post "$BASE/login" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{ username = $user; password = $pwd } `
          -MaximumRedirection 0 -ErrorAction Stop | Out-Null
    } catch {
        # 302 on success surfaces as an exception with -MaximumRedirection 0; that is expected.
        if ($_.Exception.Response.StatusCode.value__ -notin 200,302) { throw }
    }
    if ($session.Cookies.GetCookies("$BASE").Count -lt 1) {
        throw "no session cookie was set by /login"
    }
} | Out-Null

# 4) authorization_code + PKCE through that session.
$pkce = Measure-Step "4. generate PKCE verifier+challenge (S256)" {
    $verifierBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($verifierBytes)
    $verifier = ConvertTo-Base64Url $verifierBytes
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $challenge = ConvertTo-Base64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ verifier=$verifier; challenge=$challenge }
}

$authCode = Measure-Step "5. POST /connect/authorize (session cookie) → code" {
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            response_type         = "code"
            client_id             = $reg.client_id
            redirect_uri          = $REDIRECT_CB
            scope                 = "openid profile email"
            code_challenge        = $pkce.challenge
            code_challenge_method = "S256"
            state                 = "bclogout-demo-state"
            nonce                 = [Guid]::NewGuid().ToString('N')
          } -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        $resp = $_.Exception.Response
    }
    $location = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $location) { throw "no Location header on /connect/authorize response" }
    $q = ([uri]$location).Query.TrimStart('?')
    $kv = @{}
    foreach ($pair in $q.Split('&')) {
        $i = $pair.IndexOf('=')
        if ($i -gt 0) { $kv[$pair.Substring(0,$i)] = [uri]::UnescapeDataString($pair.Substring($i+1)) }
    }
    if (-not $kv.code) { throw "authorize did not return a code (got: $location)" }
    $kv.code
}

$tok = Measure-Step "6. POST /connect/token (authorization_code + PKCE) → id_token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "authorization_code"
        client_id     = $reg.client_id
        code          = $authCode
        redirect_uri  = $REDIRECT_CB
        code_verifier = $pkce.verifier
      }
}
if (-not $tok.id_token) { throw "no id_token issued — cannot drive RP-initiated logout" }
$idClaims = Decode-JwtPayload $tok.id_token
Write-Host "  id_token sub : $($idClaims.sub)"
Write-Host "  id_token sid : $($idClaims.sid)"
if (-not $idClaims.sid) { throw "id_token carries no sid — the OP session is unnamed and back-channel logout cannot target it" }

# 7) Start HttpListener in a runspace; capture the inbound logout_token POST.
$listenerJob = Measure-Step "7. start HttpListener on $LSN_URL" {
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

# 8) RP-initiated logout: the browser (cookie jar) is sent to end_session_endpoint with id_token_hint.
# Note: the response body is the "Signed Out" page (or a redirect), so the JSON shape of the underlying
# LogoutProcessor is not visible here. The proof of fan-out is the captured POST on our HttpListener.
Measure-Step "8. POST /connect/logout (session cookie + id_token_hint) — RP-initiated" {
    $status = 0
    try {
        $wr = Invoke-WebRequest -Method Post "$BASE/connect/logout" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            id_token_hint = $tok.id_token
            client_id     = $reg.client_id
          } -MaximumRedirection 0 -ErrorAction Stop
        $status = $wr.StatusCode
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
    }
    Write-Host "  status: $status"
    if ($status -lt 200 -or $status -ge 400) { throw "Unexpected logout status: $status" }
} | Out-Null

# 9) Drain the listener.
$capture = Measure-Step "9. drain HttpListener (await captured POST)" {
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

# 10) Decode logout_token JWT and verify the OIDC Back-Channel Logout 1.0 §2.4 claims.
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
if ($payload.sub -ne $idClaims.sub) {
    throw "logout_token sub '$($payload.sub)' differs from the id_token sub '$($idClaims.sub)' — the RP cannot match the user"
}
Write-Host "  ✓ sub equals the id_token sub: $($payload.sub)" -ForegroundColor Green
if (-not $payload.sid) { throw "logout_token missing 'sid' although backchannel_logout_session_required=true" }
if ($payload.sid -ne $idClaims.sid) {
    throw "logout_token sid '$($payload.sid)' differs from the id_token sid '$($idClaims.sid)' — the RP would end the wrong session"
}
Write-Host "  ✓ sid equals the id_token sid: $($payload.sid) (the session that ended)" -ForegroundColor Green
if ($payload.aud -ne $reg.client_id) { throw "logout_token aud '$($payload.aud)' is not the RP's client_id" }
Write-Host "  ✓ aud is the RP's client_id" -ForegroundColor Green
if (-not $payload.iss) { Write-Host "  ! 'iss' claim missing (RFC requires)" -ForegroundColor Yellow }
if (-not $payload.iat) { Write-Host "  ! 'iat' claim missing (RFC requires)" -ForegroundColor Yellow }
if (-not $payload.jti) { Write-Host "  ! 'jti' claim missing (RFC requires)" -ForegroundColor Yellow }

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
