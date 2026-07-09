# Authorization-code + PKCE flow without a browser.
#   POST /login (cookie jar) → POST /connect/authorize → token exchange.
# Usage: pwsh -File demo_authcode_pkce.ps1

$BASE = "http://127.0.0.1:5002"
$REDIRECT = "http://localhost:9999/cb"
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

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — authorization_code client with our redirect URI.
$reg = Measure-Step "1. DCR (authorization_code + PKCE)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "pkce-demo"
        redirect_uris = @($REDIRECT)
        grant_types   = @("authorization_code","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}

# 2) Seed the user.
$user = "pkce_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "2. account/register" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
          -ContentType "application/json" `
          -Body (@{
            login       = $user
            email       = "$user@example.com"
            password    = "Test1234Pass!"
            displayName = $user
          } | ConvertTo-Json)
    } catch { Write-Host "  (already exists or non-fatal: $($_.Exception.Message))" -ForegroundColor Yellow }
} | Out-Null

# 3) Generate PKCE pair.
$pkce = Measure-Step "3. generate PKCE verifier+challenge (S256)" {
    $verifierBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($verifierBytes)
    $verifier = ConvertTo-Base64Url $verifierBytes

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $challengeBytes = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))
    $challenge = ConvertTo-Base64Url $challengeBytes
    [pscustomobject]@{ verifier=$verifier; challenge=$challenge }
}
Write-Host "  verifier  : $($pkce.verifier.Substring(0,16))…"
Write-Host "  challenge : $($pkce.challenge.Substring(0,16))…"

# 4) Establish a cookie session via /login.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Measure-Step "4. POST /login (cookie jar)" {
    try {
        Invoke-WebRequest -Method Post "$BASE/login" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{ username = $user; password = "Test1234Pass!" } `
          -MaximumRedirection 0 -ErrorAction Stop | Out-Null
    } catch {
        # 302 redirect on success counts as an exception with -MaximumRedirection 0; that's expected.
        if ($_.Exception.Response.StatusCode.value__ -notin 200,302) { throw }
    }
    if ($session.Cookies.GetCookies("$BASE").Count -lt 1) {
        throw "no session cookie was set by /login"
    }
} | Out-Null

# 5) Drive /connect/authorize with the PKCE challenge.
$code = Measure-Step "5. POST /connect/authorize → extract code" {
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            response_type         = "code"
            client_id             = $reg.client_id
            redirect_uri          = $REDIRECT
            scope                 = "openid profile email offline_access"
            code_challenge        = $pkce.challenge
            code_challenge_method = "S256"
            state                 = "pkce-demo-state"
            nonce                 = [Guid]::NewGuid().ToString('N')
          } -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        $resp = $_.Exception.Response
    }
    $location = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $location) { throw "no Location header on /connect/authorize response" }
    $u = [uri]$location
    $q = $u.Query.TrimStart('?')
    $kv = @{}
    foreach ($pair in $q.Split('&')) {
        $i = $pair.IndexOf('=')
        if ($i -gt 0) { $kv[$pair.Substring(0,$i)] = [uri]::UnescapeDataString($pair.Substring($i+1)) }
    }
    if (-not $kv.code) {
        throw "authorize did not return a code (got: $location)"
    }
    Write-Host "  redirect : $location"
    $kv.code
}

# 6) Exchange code+verifier for tokens.
$tok = Measure-Step "6. POST /connect/token (grant=authorization_code)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "authorization_code"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        redirect_uri  = $REDIRECT
        code          = $code
        code_verifier = $pkce.verifier
      }
}
$tok | Format-List access_token, id_token, refresh_token, expires_in

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
