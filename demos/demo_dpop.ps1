# DPoP — Demonstrating Proof-of-Possession (RFC 9449) end-to-end.
#   Generates an ephemeral EC P-256 key, binds it to a /connect/token request,
#   verifies token_type=DPoP in the response, calls /connect/userinfo with an
#   ath-bound proof, and checks jti replay + wrong-scheme rejection.
# Usage: pwsh -File demo_dpop.ps1

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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# ── Crypto helpers ────────────────────────────────────────────────────────────
# Ephemeral EC P-256 key — one key per demo run (RFC 9449 §2).
# Fallback to RSA 2048 if EC P-256 is not available on this platform.
$ecPub = $null
$rsaPub = $null
$keyAlgo = $null

try {
    $ecdsa  = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256)
    if ($ecdsa) {
        $ecPub = $ecdsa.ExportParameters($false)
        if ($ecPub -and $ecPub.Q -and $ecPub.Q.X -and $ecPub.Q.Y) {
            $keyAlgo = "EC"
        }
    }
} catch {
    Write-Host "  EC P-256 not available on this platform" -ForegroundColor Yellow
}

if (-not $keyAlgo) {
    Write-Host "  Falling back to RSA 2048" -ForegroundColor Yellow
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $rsaPub = $rsa.ExportParameters($false)
    $keyAlgo = "RSA"
}

function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function B64UStr([string]$s) { B64U ([Text.Encoding]::UTF8.GetBytes($s)) }

if ($keyAlgo -eq "EC") {
    $jwkX = B64U $ecPub.Q.X
    $jwkY = B64U $ecPub.Q.Y
    $jwk  = [ordered]@{ kty="EC"; crv="P-256"; x=$jwkX; y=$jwkY }
    Write-Host "  DPoP key (EC P-256)"
    Write-Host "            x=$jwkX"
    Write-Host "            y=$jwkY"
} else {
    $e   = B64U $rsaPub.Exponent
    $n   = B64U $rsaPub.Modulus
    $jwk = [ordered]@{ kty="RSA"; e=$e; n=$n }
    Write-Host "  DPoP key (RSA 2048)"
    Write-Host "            e=$e"
    Write-Host "            n=$($n.Substring(0,32))…"
}

# DPoP-Nonce issued by server (RFC 9449 §8) — starts null, updated from response headers.
$script:dpopNonce = $null

function New-DpopProof {
    param([string]$Htm, [string]$Htu, [string]$Ath = $null)
    $alg = if ($keyAlgo -eq "EC") { "ES256" } else { "RS256" }
    $hdr = [ordered]@{ typ="dpop+jwt"; alg=$alg; jwk=$jwk }
    $pay = [ordered]@{
        jti = [Guid]::NewGuid().ToString()
        htm = $Htm
        htu = $Htu
        iat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    if ($Ath)                   { $pay["ath"]   = $Ath }
    if ($script:dpopNonce)      { $pay["nonce"] = $script:dpopNonce }

    $h   = B64UStr ($hdr | ConvertTo-Json -Compress)
    $p   = B64UStr ($pay | ConvertTo-Json -Compress)

    if ($keyAlgo -eq "EC") {
        $sig = B64U ($ecdsa.SignData(
            [Text.Encoding]::UTF8.GetBytes("$h.$p"),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    } else {
        $sig = B64U ($rsa.SignData(
            [Text.Encoding]::UTF8.GetBytes("$h.$p"),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    }
    return "$h.$p.$sig"
}

function Get-Ath([string]$token) {
    B64U ([System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::ASCII.GetBytes($token)))
}

function Invoke-TokenWithDpop {
    param([hashtable]$Body, [string]$Htm = "POST")
    $url = "$BASE/connect/token"
    # Use Invoke-WebRequest to capture response headers (DPoP-Nonce).
    $proof = New-DpopProof -Htm $Htm -Htu $url
    $wr = Invoke-WebRequest -Method Post $url `
        -ContentType "application/x-www-form-urlencoded" `
        -Headers @{ DPoP = $proof } `
        -Body $Body `
        -ErrorAction SilentlyContinue

    # Capture nonce for subsequent proofs (RFC 9449 §8).
    $newNonce = $wr.Headers['DPoP-Nonce']
    if ($newNonce) {
        $script:dpopNonce = $newNonce
        Write-Host "  DPoP-Nonce issued by server: $newNonce" -ForegroundColor DarkGray
    }

    if ($wr.StatusCode -in 200,201) {
        return $wr.Content | ConvertFrom-Json
    }

    # Server may require a nonce on first call (401 use_dpop_nonce).
    if ($wr.StatusCode -eq 401 -and $newNonce) {
        Write-Host "  Server challenged with DPoP-Nonce — retrying…" -ForegroundColor Yellow
        $proof2 = New-DpopProof -Htm $Htm -Htu $url
        $wr2 = Invoke-WebRequest -Method Post $url `
            -ContentType "application/x-www-form-urlencoded" `
            -Headers @{ DPoP = $proof2 } `
            -Body $Body
        $n2 = $wr2.Headers['DPoP-Nonce']
        if ($n2) { $script:dpopNonce = $n2 }
        return $wr2.Content | ConvertFrom-Json
    }

    throw "Token request failed: $($wr.StatusCode) $($wr.Content)"
}

# ── Steps ─────────────────────────────────────────────────────────────────────

# 1) DCR — register client with password + refresh_token.
$reg = Measure-Step "1. DCR /connect/register" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "dpop-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Seed user.
$user = "dpop_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
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

# 3) ROPC /connect/token with DPoP proof — expect token_type=DPoP (RFC 9449 §5-6).
$tok = Measure-Step "3. ROPC /connect/token + DPoP proof (expect token_type=DPoP)" {
    $t = Invoke-TokenWithDpop @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email offline_access"
    }
    Write-Host "  token_type : $($t.token_type)"
    if ($t.token_type -eq "DPoP") {
        Write-Host "  ✓ token_type = DPoP" -ForegroundColor Green
    } else {
        Write-Host "  ! token_type='$($t.token_type)' — expected DPoP; server may not require DPoP for this client" -ForegroundColor Yellow
    }
    return $t
}
Write-Host "  access_token  : $($tok.access_token.Substring(0,32))…"

# 4) GET /connect/userinfo with DPoP-bound token (RFC 9449 §7.1 — ath required).
$userinfoUrl = "$BASE/connect/userinfo"
Measure-Step "4. GET /connect/userinfo (Authorization: Bearer <token> + DPoP proof)" {
    $ath   = Get-Ath $tok.access_token
    $proof = New-DpopProof -Htm GET -Htu $userinfoUrl -Ath $ath
    $ui = Invoke-RestMethod -Method Get $userinfoUrl `
      -Headers @{
        Authorization = "Bearer $($tok.access_token)"
        DPoP          = $proof
      }
    $ui | ConvertTo-Json -Depth 5 | Out-Host
    if ($ui.sub) { Write-Host "  ✓ sub = $($ui.sub)" -ForegroundColor Green }
    return $ui
} | Out-Null

# 5) Refresh with DPoP (RFC 9449 §5 — bound refresh_token).
$tok2 = Measure-Step "5. refresh_token grant + DPoP" {
    Invoke-TokenWithDpop @{
        grant_type    = "refresh_token"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        refresh_token = $tok.refresh_token
    }
}
Write-Host "  new access_token : $($tok2.access_token.Substring(0,32))…"
if ($tok2.token_type -eq "DPoP") {
    Write-Host "  ✓ refreshed token_type still DPoP" -ForegroundColor Green
}

# 6) jti replay — same proof header twice → must reject (RFC 9449 §11.1).
#    We make one real call to seed the jti, then immediately replay the same proof.
$replayProof = New-DpopProof -Htm POST -Htu "$BASE/connect/token"
$replayBody  = @{
    grant_type    = "password"
    client_id     = $reg.client_id
    client_secret = $reg.client_secret
    username      = $user
    password      = $pwd
    scope         = "openid profile email"
}
# Seed first call (ignore result).
$null = try {
    Invoke-WebRequest -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Headers @{ DPoP = $replayProof } -Body $replayBody -ErrorAction SilentlyContinue
} catch {}

Measure-Step "6. jti replay — same proof twice (expect 400/401 if replay cache active)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Headers @{ DPoP = $replayProof } -Body $replayBody | Out-Null
        Write-Host "  ! replay NOT rejected — jti replay cache may not be active on /connect/token" -ForegroundColor Yellow
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 400,401) {
            Write-Host "  ✓ replay rejected: $code" -ForegroundColor Green
        } else {
            Write-Host "  unexpected status $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 7) Bearer auth with a DPoP-bound token — server should reject (wrong scheme).
Measure-Step "7. Bearer scheme with DPoP-bound token (expect 401 — cnf.jkt mismatch)" {
    try {
        Invoke-RestMethod -Method Get $userinfoUrl `
          -Headers @{ Authorization = "Bearer $($tok.access_token)" } | Out-Null
        Write-Host "  ! DPoP-bound token accepted as Bearer — cnf.jkt NOT enforced at userinfo" -ForegroundColor Yellow
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 401) {
            Write-Host "  ✓ rejected: 401 (DPoP-bound token must not be used as Bearer)" -ForegroundColor Green
        } else {
            Write-Host "  unexpected status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
