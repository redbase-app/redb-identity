# Discovery + JWKS + manual RS256 id_token verification.
# Usage: pwsh -File demo_discovery_jwks.ps1

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

function ConvertFrom-Base64Url([string]$s) {
    $s = $s.Replace('-','+').Replace('_','/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Convert]::FromBase64String($s)
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Discovery
$disc = Measure-Step "1. GET /.well-known/openid-configuration" {
    Invoke-RestMethod "$BASE/.well-known/openid-configuration"
}
Write-Host "  issuer    : $($disc.issuer)"
Write-Host "  jwks_uri  : $($disc.jwks_uri)"
Write-Host "  grants    : $($disc.grant_types_supported -join ', ')"
Write-Host "  scopes    : $($disc.scopes_supported -join ', ')"

# 2) JWKS
$jwks = Measure-Step "2. GET JWKS" {
    Invoke-RestMethod $disc.jwks_uri
}
Write-Host "  keys count: $($jwks.keys.Count)"
$jwks.keys | ForEach-Object { Write-Host "    - kid=$($_.kid) alg=$($_.alg) use=$($_.use) kty=$($_.kty)" }

# 3) Need a real id_token to verify — drive password grant.
$reg = Measure-Step "3. DCR (password grant client)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "discovery-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email"
      } | ConvertTo-Json)
}

$user = "disc_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "4. account/register" {
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

$tok = Measure-Step "5. password grant" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = "Test1234Pass!"
        scope         = "openid profile email"
      }
}

# 4) Verify id_token signature manually
$verify = Measure-Step "6. verify id_token RS256 against JWKS" {
    $parts = $tok.id_token.Split('.')
    if ($parts.Length -lt 3) { throw "id_token is not a JWS (parts=$($parts.Length))" }

    $header = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[0])) | ConvertFrom-Json
    $key = $jwks.keys | Where-Object { $_.kid -eq $header.kid } | Select-Object -First 1
    if (-not $key) { throw "kid $($header.kid) not found in JWKS" }

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rp = New-Object System.Security.Cryptography.RSAParameters
    $rp.Modulus  = ConvertFrom-Base64Url $key.n
    $rp.Exponent = ConvertFrom-Base64Url $key.e
    $rsa.ImportParameters($rp)

    $signed = [Text.Encoding]::ASCII.GetBytes("$($parts[0]).$($parts[1])")
    $sig    = ConvertFrom-Base64Url $parts[2]
    $ok = $rsa.VerifyData(
        $signed, $sig,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    [pscustomobject]@{ kid=$header.kid; alg=$header.alg; valid=$ok }
}
$verify | Format-Table

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
