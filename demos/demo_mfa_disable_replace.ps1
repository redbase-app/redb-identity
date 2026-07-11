# Self-service MFA disable + replace flow.
#   /me/mfa setup/confirm (TOTP)            — enroll
#   DELETE /me/mfa/{method}                 — disable that method
#   /me/mfa setup/confirm again             — re-enroll ("replace") with a fresh secret
#
# Probes:
#   1. DCR + register user
#   2. ROPC bearer for /me/mfa
#   3. GET /me/mfa  — initially OFF
#   4. setup → compute TOTP → confirm  → MFA enrolled  (secret = S1)
#   5. GET /me/mfa  — enabled=true
#   6. DELETE /me/mfa/totp without bearer  → 401
#   7. DELETE /me/mfa/totp                 → 200/204
#   8. GET /me/mfa  — back to OFF
#   9. setup → compute TOTP → confirm  → MFA enrolled again  (secret = S2)
#  10. S2 != S1                            — fresh secret on re-enrol
#  11. GET /me/mfa  — enabled=true again
#  12. RFC 7592 cleanup
#
# The TOTP math (Base32 + RFC 6238 HMAC-SHA1) mirrors demo_mfa_totp.ps1 so no
# authenticator app is required.
# Usage: pwsh -File demo_mfa_disable_replace.ps1
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
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

function ConvertFrom-Base32([string]$s) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $s = $s.ToUpperInvariant().TrimEnd('=')
    $bits = New-Object System.Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        $v = $alphabet.IndexOf([string]$c)
        if ($v -lt 0) { throw "invalid base32 char: $c" }
        [void]$bits.Append([Convert]::ToString($v, 2).PadLeft(5, '0'))
    }
    $bitsStr = $bits.ToString()
    $bytes = [System.Collections.Generic.List[byte]]::new()
    for ($i = 0; $i + 8 -le $bitsStr.Length; $i += 8) {
        $bytes.Add([Convert]::ToByte($bitsStr.Substring($i, 8), 2))
    }
    return ,$bytes.ToArray()
}

function Compute-Totp([string]$base32Secret) {
    $key = ConvertFrom-Base32 $base32Secret
    $t = [int64]([Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30))
    $tbytes = [BitConverter]::GetBytes($t)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($tbytes) }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1(,$key)
    $hash = $hmac.ComputeHash($tbytes)
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $code = (([int]$hash[$offset]    -band 0x7F) -shl 24) `
        -bor (([int]$hash[$offset+1] -band 0xFF) -shl 16) `
        -bor (([int]$hash[$offset+2] -band 0xFF) -shl 8) `
        -bor  ([int]$hash[$offset+3] -band 0xFF)
    return ($code % 1000000).ToString("D6")
}

function Enroll-Totp {
    param([hashtable]$Bearer)
    $setup = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/setup" `
        -Headers $Bearer -ContentType "application/json" `
        -Body (@{ method = "totp" } | ConvertTo-Json)
    if (-not $setup.secret_base32) { throw "/me/mfa/setup did not return secret_base32" }
    if (-not $setup.setup_token)   { throw "/me/mfa/setup did not return setup_token" }
    $code = Compute-Totp $setup.secret_base32
    $confirm = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/confirm" `
        -Headers $Bearer -ContentType "application/json" `
        -Body (@{ method = "totp"; code = $code; setup_token = $setup.setup_token } | ConvertTo-Json)
    return [pscustomobject]@{
        Secret  = $setup.secret_base32
        Confirm = $confirm
    }
}

# Multiple shapes possible — accept any "true-ish" enrolled-flag.
function Is-TotpEnabled($mfa) {
    if ($null -eq $mfa) { return $false }
    foreach ($prop in @('totpConfirmed','totpEnabled','enabled')) {
        $v = $mfa.PSObject.Properties[$prop]
        if ($v -and $v.Value -eq $true) { return $true }
    }
    # /me/mfa may also surface a methods[] array.
    if ($mfa.PSObject.Properties['methods']) {
        $methods = $mfa.methods
        if ($methods -and ($methods | Where-Object { $_ -eq 'totp' -or $_.method -eq 'totp' })) { return $true }
    }
    return $false
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — password client for /me/* endpoints.
$reg = Measure-Step "1. DCR (password + identity:account)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name   = "mfa-disable-replace-demo"
            redirect_uris = @($REDIRECT_CB)
            grant_types   = @("password","refresh_token")
            scope         = "openid profile email offline_access identity:account"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register + token.
$user = "mfar_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "2. self-register ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{
            login       = $user
            email       = "$user@example.com"
            password    = $pwd
            displayName = $user
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ user created" -ForegroundColor Green
} | Out-Null

$tok = Measure-Step "3. ROPC token (identity:account)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email offline_access identity:account"
        }
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}
$bearer = @{ Authorization = "Bearer $($tok.access_token)" }

# 4) GET /me/mfa — should be off initially.
$mfa0 = Measure-Step "4. GET /me/mfa (expect OFF)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
    if (Is-TotpEnabled $r) { throw "expected MFA off initially, got: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  ✓ MFA off" -ForegroundColor Green
    return $r
}

# 5) First enrol — secret S1.
$enroll1 = Measure-Step "5. enrol TOTP (setup + confirm) — secret S1" {
    Enroll-Totp -Bearer $bearer
}
Write-Host "  S1 = $($enroll1.Secret.Substring(0, [Math]::Min(8, $enroll1.Secret.Length)))…" -ForegroundColor Yellow

# 6) GET /me/mfa — now enabled.
Measure-Step "6. GET /me/mfa (expect ON)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
    if (-not (Is-TotpEnabled $r)) { throw "expected MFA on after enrol, got: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  ✓ MFA on" -ForegroundColor Green
} | Out-Null

# 7) DELETE /me/mfa/totp WITHOUT bearer — must be 401.
Measure-Step "7. DELETE /me/mfa/totp without bearer (expect 401)" {
    try {
        Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me/mfa/totp" -ErrorAction Stop | Out-Null
        throw "! UNEXPECTED 2xx — unauth DELETE accepted"
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -ne 401) { throw "expected 401, got $code" }
        Write-Host "  ✓ rejected: 401" -ForegroundColor Green
    }
} | Out-Null

# 8) DELETE /me/mfa/totp WITH bearer.
Measure-Step "8. DELETE /me/mfa/totp (disable)" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me/mfa/totp" -Headers $bearer | Out-Null
    Write-Host "  ✓ disabled" -ForegroundColor Green
} | Out-Null

# 9) GET /me/mfa — back to off.
Measure-Step "9. GET /me/mfa (expect OFF again)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
    if (Is-TotpEnabled $r) { throw "expected MFA off after disable, got: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  ✓ MFA off" -ForegroundColor Green
} | Out-Null

# 10) Re-enrol (replace) — secret S2.
$enroll2 = Measure-Step "10. re-enrol TOTP (setup + confirm) — secret S2" {
    Enroll-Totp -Bearer $bearer
}
Write-Host "  S2 = $($enroll2.Secret.Substring(0, [Math]::Min(8, $enroll2.Secret.Length)))…" -ForegroundColor Yellow

# 11) S2 != S1 — server MUST mint a fresh secret on re-enrol.
Measure-Step "11. assert S2 != S1 (fresh secret on replace)" {
    if ($enroll1.Secret -eq $enroll2.Secret) {
        throw "S1 == S2 — re-enrol returned the SAME secret. Disable did not clear the seed, " +
              "or setup reused the cached one. This is a server-side replay risk."
    }
    Write-Host "  ✓ secret changed on replace" -ForegroundColor Green
} | Out-Null

# 12) GET /me/mfa — re-enrolled.
Measure-Step "12. GET /me/mfa (expect ON after replace)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
    if (-not (Is-TotpEnabled $r)) { throw "expected MFA on after re-enrol, got: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  ✓ MFA on (with S2)" -ForegroundColor Green
} | Out-Null

# 13) RFC 7592 cleanup.
Measure-Step "13. RFC 7592 DELETE registration" {
    if (-not $RAT) { Write-Host "  (no RAT → skip)" -ForegroundColor DarkGray; return }
    Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
