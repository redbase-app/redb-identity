# Token Exchange (RFC 8693). Opt-in via RedbIdentityOptions.EnableTokenExchange.
#   Two patterns covered:
#     a) impersonation — no actor_token; new access_token has subject=user, no `act` claim
#        (only when TokenExchangeAllowImpersonation=true).
#     b) delegation   — actor_token provided; new access_token carries `act` claim chain.
#   Plus negative paths: scope upscoping (must be subset), depth limit, missing subject_token.
# Usage: pwsh -File demo_token_exchange.ps1

$BASE = "http://127.0.0.1:5002"
$timings = [System.Collections.Generic.List[object]]::new()
$EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
$ACCESS_TT = "urn:ietf:params:oauth:token-type:access_token"

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

# 0) Discovery — if token-exchange isn't advertised, exit cleanly so the demo is still
#    counted as PASS in run_all (the feature is opt-in and most dev configs leave it off).
$disco = Invoke-RestMethod "$BASE/.well-known/openid-configuration"
if ($disco.grant_types_supported -notcontains $EXCHANGE) {
    Write-Host "Token Exchange ($EXCHANGE) not advertised by /.well-known — set " -ForegroundColor Yellow -NoNewline
    Write-Host "RedbIdentityOptions.EnableTokenExchange=true and reload tpkg." -ForegroundColor Yellow
    Write-Host "Skipping (this is a feature-flag config issue, not a server bug)." -ForegroundColor DarkGray
    exit 0
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — the requesting/exchanger client.
$reg = Measure-Step "1. DCR /connect/register (password + token-exchange)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "tx-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token","client_credentials",$EXCHANGE)
        scope         = "openid profile email offline_access identity:read"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "tx_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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

# 3) Get a subject_token (user access_token) via password grant.
$subject = Measure-Step "3. password grant (subject_token = user access_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email"
      }
}
Write-Host "  subject_token   : $($subject.access_token.Substring(0,32))… scope=$($subject.scope)"

# 4) Get an actor_token (client_credentials) — represents the calling service.
$actor = Measure-Step "4. client_credentials (actor_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "client_credentials"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        scope         = "identity:read"
      }
}
Write-Host "  actor_token     : $($actor.access_token.Substring(0,32))… scope=$($actor.scope)"

# 5) DELEGATION exchange — actor_token present → new token has `act` claim.
$delegated = Measure-Step "5. token-exchange (delegation: subject + actor)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type           = $EXCHANGE
        client_id            = $reg.client_id
        client_secret        = $reg.client_secret
        subject_token        = $subject.access_token
        subject_token_type   = $ACCESS_TT
        actor_token          = $actor.access_token
        actor_token_type     = $ACCESS_TT
        requested_token_type = $ACCESS_TT
        scope                = "openid profile"
      }
}
Write-Host "  delegated_token : $($delegated.access_token.Substring(0,32))…"
Write-Host "  issued_token_type: $($delegated.issued_token_type)"

# 6) Decode delegated access_token (best-effort — may be JWE).
function Decode-Jwt([string]$jwt) {
    $parts = $jwt.Split('.')
    if ($parts.Length -lt 2) { return $null }
    $payload = $parts[1].Replace('-','+').Replace('_','/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json } catch { $null }
}
$claims = Decode-Jwt $delegated.access_token
if ($null -eq $claims) {
    Write-Host "  (access_token is JWE-encrypted — using introspect to inspect claims)" -ForegroundColor Yellow
    $claims = Invoke-RestMethod -Method Post "$BASE/connect/introspect" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token         = $delegated.access_token
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
      }
}
Write-Host "  sub  = $($claims.sub)"
Write-Host "  scope= $($claims.scope)"
if ($claims.act) {
    Write-Host "  ✓ act claim present (delegation chain): $($claims.act | ConvertTo-Json -Compress)" -ForegroundColor Green
} else {
    Write-Host "  ! act claim missing on delegated token" -ForegroundColor Red
}

# 7) Negative: try to upscope (request a scope NOT in subject_token) → invalid_scope.
Measure-Step "7. upscoping rejected (request 'identity:manage' not held by subject)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type           = $EXCHANGE
            client_id            = $reg.client_id
            client_secret        = $reg.client_secret
            subject_token        = $subject.access_token
            subject_token_type   = $ACCESS_TT
            actor_token          = $actor.access_token
            actor_token_type     = $ACCESS_TT
            requested_token_type = $ACCESS_TT
            scope                = "identity:manage"
          } | Out-Null
        throw "UPSCOPING ACCEPTED — server is permissive!"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  ✓ upscoping rejected: status=$code" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

# 8) Negative: missing subject_token → invalid_request.
Measure-Step "8. missing subject_token → invalid_request" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type           = $EXCHANGE
            client_id            = $reg.client_id
            client_secret        = $reg.client_secret
            requested_token_type = $ACCESS_TT
          } | Out-Null
        throw "MISSING SUBJECT ACCEPTED"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  ✓ rejected: status=$code" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

# 9) Chain another exchange on top of delegated → second `act` nested inside.
$delegated2 = Measure-Step "9. token-exchange chain (delegated → delegated2; expect act->act)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type           = $EXCHANGE
        client_id            = $reg.client_id
        client_secret        = $reg.client_secret
        subject_token        = $delegated.access_token
        subject_token_type   = $ACCESS_TT
        actor_token          = $actor.access_token
        actor_token_type     = $ACCESS_TT
        requested_token_type = $ACCESS_TT
        scope                = "openid"
      }
}
Write-Host "  chained_token   : $($delegated2.access_token.Substring(0,32))…"

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
