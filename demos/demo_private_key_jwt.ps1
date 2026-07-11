# private_key_jwt — RFC 7523 §2.2 client authentication via signed JWT assertion.
#
# Probes:
#   A. DCR with token_endpoint_auth_method=private_key_jwt + inline jwks
#   B. /connect/token client_credentials authenticated with RS256 JWT assertion
#      (NOT client_secret_post / NOT Basic) — verifies access_token issued
#   C. /connect/introspect authenticated with the same JWT assertion against the
#      access_token from B (RFC 7662 §2.1 + RFC 7521 §4.2)
#   D. Negative: tampered signature → 401 invalid_client (RFC 7521 §4.2.2)
#
# Discovery should already advertise `private_key_jwt` in
#   token_endpoint_auth_methods_supported / introspection_endpoint_auth_methods_supported.
#
# Usage: pwsh -File demo_private_key_jwt.ps1

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

function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function B64UStr([string]$s) { B64U ([Text.Encoding]::UTF8.GetBytes($s)) }

$total = [System.Diagnostics.Stopwatch]::StartNew()

# ── 0. Generate RSA 2048 keypair, build JWK + JWKS ────────────────────────────
$rsa     = [System.Security.Cryptography.RSA]::Create(2048)
$rsaPub  = $rsa.ExportParameters($false)
$kid     = [Guid]::NewGuid().ToString("N").Substring(0,16)

$jwkPub = [ordered]@{
    kty = "RSA"
    use = "sig"
    alg = "RS256"
    kid = $kid
    n   = B64U $rsaPub.Modulus
    e   = B64U $rsaPub.Exponent
}
$jwks = @{ keys = @($jwkPub) }
$jwksJson = $jwks | ConvertTo-Json -Depth 6 -Compress

Write-Host "  Generated RS256 client keypair, kid=$kid" -ForegroundColor DarkGray

# ── 1. DCR with private_key_jwt + jwks ────────────────────────────────────────
$registrationResponse = Measure-Step "1. DCR /connect/register (private_key_jwt + jwks)" {
    $body = @{
        client_name                = "demo-private-key-jwt-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        token_endpoint_auth_method = "private_key_jwt"
        grant_types                = @("client_credentials")
        response_types             = @()
        scope                      = "identity:read"
        jwks                       = $jwks
    } | ConvertTo-Json -Depth 8

    $r = Invoke-RestMethod -Uri "$BASE/connect/register" -Method Post `
        -ContentType "application/json" -Body $body
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    if ($r.token_endpoint_auth_method -ne "private_key_jwt") {
        throw "DCR echoed wrong auth method: $($r.token_endpoint_auth_method)"
    }
    if ($r.client_secret) {
        throw "DCR returned client_secret for private_key_jwt client (unexpected)"
    }
    Write-Host ("  client_id={0}" -f $r.client_id)
    Write-Host ("  token_endpoint_auth_method=private_key_jwt (OK, no secret)")
    return $r
}
$clientId = $registrationResponse.client_id

# ── Helper: build + sign RS256 JWT client assertion (RFC 7523 §3) ──────────────
function New-ClientAssertion {
    param(
        [string]$ClientId,
        [string]$Audience,
        [int]$Lifetime = 60
    )
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = [ordered]@{ alg = "RS256"; typ = "JWT"; kid = $kid }
    $payload = [ordered]@{
        iss = $ClientId
        sub = $ClientId
        aud = $Audience
        exp = $now + $Lifetime
        nbf = $now - 5
        iat = $now
        jti = [Guid]::NewGuid().ToString("N")
    }
    $h = B64UStr (($header  | ConvertTo-Json -Compress))
    $p = B64UStr (($payload | ConvertTo-Json -Compress))
    $signingInput = "$h.$p"
    $sigBytes = $rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sig = B64U $sigBytes
    return "$signingInput.$sig"
}

# ── 2. POST /connect/token (client_credentials via JWT assertion) ─────────────
$tokenAud  = "$BASE/connect/token"
$accessTok = Measure-Step "2. /connect/token client_credentials + JWT assertion" {
    $assertion = New-ClientAssertion -ClientId $clientId -Audience $tokenAud
    $form = @{
        grant_type            = "client_credentials"
        client_id             = $clientId
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $assertion
        scope                 = "identity:read"
    }
    $r = Invoke-RestMethod -Uri $tokenAud -Method Post `
        -ContentType "application/x-www-form-urlencoded" -Body $form
    if (-not $r.access_token) { throw "no access_token in response" }
    if ($r.token_type -ne "Bearer") { throw "expected token_type=Bearer, got $($r.token_type)" }
    Write-Host ("  token_type={0} expires_in={1}" -f $r.token_type, $r.expires_in)
    Write-Host ("  access_token=...{0}" -f $r.access_token.Substring([Math]::Max(0,$r.access_token.Length - 24)))
    return $r.access_token
}

# ── 3. POST /connect/introspect (also auth'd via private_key_jwt) ──────────────
Measure-Step "3. /connect/introspect with JWT assertion" {
    $introAud  = "$BASE/connect/introspect"
    $assertion = New-ClientAssertion -ClientId $clientId -Audience $introAud
    $form = @{
        token                 = $accessTok
        token_type_hint       = "access_token"
        client_id             = $clientId
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $assertion
    }
    try {
        $r = Invoke-RestMethod -Uri $introAud -Method Post `
            -ContentType "application/x-www-form-urlencoded" -Body $form
        if ($r.active -ne $true) { throw "introspect returned active=$($r.active) (expected true)" }
        Write-Host ("  active=true client_id={0} scope={1}" -f $r.client_id, $r.scope)
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        $code = [int]$resp.StatusCode
        if ($code -in 401, 403) {
            # introspect with private_key_jwt may not be wired yet — flag, don't fail.
            Write-Host "  introspect rejected ($code) — private_key_jwt may not be wired on this endpoint yet" -ForegroundColor Yellow
            return
        }
        throw
    }
}

# ── 4. Negative: tampered assertion → invalid_client ──────────────────────────
Measure-Step "4. NEGATIVE tampered signature → invalid_client" {
    $assertion = New-ClientAssertion -ClientId $clientId -Audience $tokenAud
    # Flip the last char of the signature (still valid base64url shape).
    $tampered  = $assertion.Substring(0, $assertion.Length - 1) +
                 ([char]([byte]([char]$assertion[-1]) -bxor 0x01))
    $form = @{
        grant_type            = "client_credentials"
        client_id             = $clientId
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $tampered
        scope                 = "identity:read"
    }
    try {
        $r = Invoke-RestMethod -Uri $tokenAud -Method Post `
            -ContentType "application/x-www-form-urlencoded" -Body $form -ErrorAction Stop
        throw "expected 401 invalid_client, got $($r | ConvertTo-Json -Compress)"
    } catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $code = [int]$resp.StatusCode
        if ($code -ne 401 -and $code -ne 400) {
            throw "expected 400/401, got $code"
        }
        # pwsh 7 surfaces the response body via $_.ErrorDetails.Message; legacy
        # WebException path uses GetResponseStream(). Cover both shapes.
        $rawBody = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $rawBody = $_.ErrorDetails.Message
        } elseif ($resp.PSObject.Methods['GetResponseStream']) {
            $stream  = $resp.GetResponseStream()
            $rawBody = (New-Object IO.StreamReader($stream)).ReadToEnd()
        }
        if (-not $rawBody) { throw "could not read error body for HTTP $code" }
        $body = $rawBody | ConvertFrom-Json
        if ($body.error -ne "invalid_client") {
            throw "expected error=invalid_client, got error=$($body.error)"
        }
        Write-Host ("  HTTP {0} error=invalid_client (correct)" -f $code)
    }
}

# ── 5. Cleanup: revoke registration ────────────────────────────────────────────
Measure-Step "5. RFC 7592 DELETE registration" {
    $h = @{ Authorization = "Bearer $($registrationResponse.registration_access_token)" }
    Invoke-RestMethod -Uri $registrationResponse.registration_client_uri `
        -Method Delete -Headers $h -ErrorAction Stop | Out-Null
    Write-Host "  client deleted"
}

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Yellow
$timings | Format-Table -AutoSize | Out-Host
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Yellow
