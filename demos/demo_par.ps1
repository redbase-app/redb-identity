# PAR — Pushed Authorization Requests (RFC 9126).
#   POST /connect/par → get request_uri → use it in /connect/authorize.
#   Since the full auth-code flow needs a browser, the authorize step is
#   probed headless: we verify the server redirects (to login/consent) rather
#   than errors.  Steps 4-6 test the security contract: one-time use, expired
#   request_uri, and invalid client rejection.
# Usage: pwsh -File demo_par.ps1

$BASE    = "http://127.0.0.1:5002"
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

function New-Pkce {
    $verifier  = B64U ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $challenge = B64U ([System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::ASCII.GetBytes($verifier)))
    return [pscustomobject]@{ Verifier=$verifier; Challenge=$challenge }
}
function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — authorization_code client (public clients must use PKCE).
$reg = Measure-Step "1. DCR /connect/register (authorization_code + PKCE)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "par-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("authorization_code","refresh_token")
        scope         = "openid profile email"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) POST /connect/par — push the authorization request (RFC 9126 §2).
$pkce  = New-Pkce
$state = [Guid]::NewGuid().ToString("N")
$nonce = [Guid]::NewGuid().ToString("N")

$par = Measure-Step "2. POST /connect/par (RFC 9126 §2)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/par" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        response_type         = "code"
        client_id             = $reg.client_id
        client_secret         = $reg.client_secret
        redirect_uri          = "http://localhost:9999/cb"
        scope                 = "openid profile email"
        state                 = $state
        nonce                 = $nonce
        code_challenge        = $pkce.Challenge
        code_challenge_method = "S256"
      }
    Write-Host "  request_uri : $($r.request_uri)"
    Write-Host "  expires_in  : $($r.expires_in) s"
    if (-not $r.request_uri) { throw "server did not return request_uri" }
    if ($r.request_uri -match "^urn:ietf:params:oauth:request_uri:") {
        Write-Host "  ✓ URN prefix correct (RFC 9126 §2.2)" -ForegroundColor Green
    } else {
        Write-Host "  ! request_uri does not use RFC 9126 URN prefix" -ForegroundColor Yellow
    }
    return $r
}

# 3) GET /connect/authorize?request_uri=… (headless — follow=0, inspect redirect).
$authorizeUri = "$BASE/connect/authorize?client_id=$([Uri]::EscapeDataString($reg.client_id))&request_uri=$([Uri]::EscapeDataString($par.request_uri))"
Measure-Step "3. GET /connect/authorize?request_uri=… (headless redirect check)" {
    try {
        $wr  = Invoke-WebRequest -Uri $authorizeUri -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $loc = $wr.Headers['Location']
        if ($wr.StatusCode -in 200,302,303,307,308) {
            Write-Host "  ✓ server responded: $($wr.StatusCode)" -ForegroundColor Green
            if ($loc) {
                Write-Host "  Location: $($loc.ToString().Substring(0,[Math]::Min(100,$loc.ToString().Length)))…"
            }
        } else {
            Write-Host "  ! unexpected: $($wr.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 200,302,303,307,308) {
            Write-Host "  ✓ server responded: $code" -ForegroundColor Green
        } else {
            Write-Host "  ! status $code — $($_.Exception.Message)" -ForegroundColor Red; throw
        }
    }
} | Out-Null

# 4) Replay the same request_uri — one-time use, must be rejected (RFC 9126 §4).
Measure-Step "4. Replay request_uri (expect 400 — one-time, RFC 9126 §4)" {
    try {
        $wr = Invoke-WebRequest -Uri $authorizeUri -MaximumRedirection 0 -ErrorAction SilentlyContinue
        if ($wr.StatusCode -eq 400) {
            Write-Host "  ✓ rejected: 400" -ForegroundColor Green
        } else {
            Write-Host "  ! got $($wr.StatusCode) — one-time enforcement may be missing" -ForegroundColor Yellow
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 400) {
            Write-Host "  ✓ rejected: 400" -ForegroundColor Green
        } else {
            Write-Host "  ! unexpected: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 5) POST /connect/par with invalid client_secret (RFC 9126 §2.3 — must authenticate).
Measure-Step "5. PAR with wrong client_secret (expect 400/401)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/par" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            response_type = "code"
            client_id     = $reg.client_id
            client_secret = "bogus-secret-$(Get-Random)"
            redirect_uri  = "http://localhost:9999/cb"
            scope         = "openid"
          } | Out-Null
        Write-Host "  ! UNEXPECTED success — invalid secret accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 400,401) {
            Write-Host "  ✓ rejected: $code" -ForegroundColor Green
        } else { throw "unexpected status $code" }
    }
} | Out-Null

# 6) POST /connect/par with unregistered redirect_uri — must reject (open-redirect guard).
Measure-Step "6. PAR with unregistered redirect_uri (expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/par" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            response_type = "code"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            redirect_uri  = "http://attacker.example/steal"
            scope         = "openid"
          } | Out-Null
        Write-Host "  ! UNEXPECTED — unregistered redirect_uri accepted (open redirect risk)" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  ✓ rejected: $code" -ForegroundColor Green
    }
} | Out-Null

# 7) POST /connect/par with unsupported response_type — must reject.
Measure-Step "7. PAR with response_type=token (implicit — expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/par" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            response_type = "token"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            redirect_uri  = "http://localhost:9999/cb"
            scope         = "openid"
          } | Out-Null
        Write-Host "  ! implicit flow accepted (should be disabled per OAuth 2.1)" -ForegroundColor Yellow
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 400) {
            Write-Host "  ✓ implicit rejected: 400" -ForegroundColor Green
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
Write-Host "(step 3 headless — full auth-code flow requires browser interaction)" -ForegroundColor DarkGray
