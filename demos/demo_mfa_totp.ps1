# MFA TOTP setup + confirm — fully scripted, no authenticator app needed.
#   /me/mfa GET (off) → /setup → compute TOTP locally → /confirm → /me/mfa GET (on).
# Usage: pwsh -File demo_mfa_totp.ps1

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

# Base32 (RFC 4648) decoder.
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

# RFC 6238 TOTP / RFC 4226 HOTP, SHA1, 6 digits, 30 s step.
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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR with identity:account scope so /me/mfa is authorized.
$reg = Measure-Step "1. DCR /connect/register (password + identity:account)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "mfa-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access identity:account"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "mfa_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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

# 3) password grant.
$tok = Measure-Step "3. password grant" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email offline_access identity:account"
      }
}
$bearer = @{ Authorization = "Bearer $($tok.access_token)" }

# 4) GET /me/mfa — should be off initially.
$mfa0 = Measure-Step "4. GET /api/v1/identity/me/mfa (initial)" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
}
$mfa0 | ConvertTo-Json -Depth 5 | Out-Host

# 5) POST /me/mfa/setup — request TOTP enrollment.
$setup = Measure-Step "5. POST /api/v1/identity/me/mfa/setup (totp)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/setup" `
      -Headers $bearer `
      -ContentType "application/json" `
      -Body (@{ method = "totp" } | ConvertTo-Json)
}
Write-Host "  secret_base32 : $($setup.secret_base32)"
Write-Host "  qr_uri        : $($setup.qr_uri)"
Write-Host "  setup_token   : $($setup.setup_token.Substring(0, [Math]::Min(40, $setup.setup_token.Length)))…"

if (-not $setup.secret_base32) { throw "server did not return secret_base32" }
if (-not $setup.setup_token)   { throw "server did not return setup_token" }

# 6) Compute the live TOTP code.
$code = Measure-Step "6. compute TOTP locally (RFC 6238, SHA1, 6 digits, 30 s)" {
    Compute-Totp $setup.secret_base32
}
Write-Host "  code = $code" -ForegroundColor Yellow

# 7) POST /me/mfa/confirm — finalize enrollment.
$confirm = Measure-Step "7. POST /api/v1/identity/me/mfa/confirm" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/confirm" `
      -Headers $bearer `
      -ContentType "application/json" `
      -Body (@{
        method      = "totp"
        code        = $code
        setup_token = $setup.setup_token
      } | ConvertTo-Json)
}
Write-Host "  confirmed     : $($confirm.confirmed)"
if ($confirm.recovery_codes) {
    Write-Host "  recovery_codes:" -ForegroundColor Yellow
    $confirm.recovery_codes | ForEach-Object { Write-Host "    $_" }
}

# 8) GET /me/mfa — should now show enabled=true.
$mfa1 = Measure-Step "8. GET /api/v1/identity/me/mfa (after confirm)" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me/mfa" -Headers $bearer
}
$mfa1 | ConvertTo-Json -Depth 5 | Out-Host

if ($mfa1.enabled -or $mfa1.totpEnabled -or $mfa1.totpConfirmed) {
    Write-Host "  ✓ MFA TOTP enrolled" -ForegroundColor Green
} else {
    Write-Host "  WARNING: /me/mfa does not report enabled=true (shape may differ)" -ForegroundColor Yellow
}

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
