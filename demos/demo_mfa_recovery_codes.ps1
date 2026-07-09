# MFA recovery-codes regeneration — exercises the parallel PBKDF2 hashing path
#   (each batch hashes N codes; perf-tuned with Parallel.For). The flow:
#     enroll TOTP → capture initial recovery codes → POST /me/mfa/recovery-codes →
#     verify previous codes are invalidated (re-using a stale code must fail).
#   Surfaces RECOVERY_REGEN_TIMING in the Worker log when configured.
# Usage: pwsh -File demo_mfa_recovery_codes.ps1

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

# Base32 (RFC 4648) decoder — same helper as demo_mfa_totp.ps1.
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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR.
$reg = Measure-Step "1. DCR /connect/register (password + identity:account)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "rec-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access identity:account"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "rec_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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

# 4) Enroll TOTP (setup → confirm) so the user has a working MFA + initial codes.
$setup = Measure-Step "4. POST /me/mfa/setup (totp)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/setup" `
      -Headers $bearer -ContentType "application/json" `
      -Body (@{ method = "totp" } | ConvertTo-Json)
}
if (-not $setup.secret_base32 -or -not $setup.setup_token) {
    throw "setup did not return secret_base32/setup_token"
}

$code = Compute-Totp $setup.secret_base32
$confirm = Measure-Step "5. POST /me/mfa/confirm (parallel PBKDF2 over recovery codes)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/confirm" `
      -Headers $bearer -ContentType "application/json" `
      -Body (@{
        method      = "totp"
        code        = $code
        setup_token = $setup.setup_token
      } | ConvertTo-Json)
}

$initialCodes = $confirm.recovery_codes
if (-not $initialCodes -or $initialCodes.Count -lt 1) {
    throw "confirm did not return recovery_codes — server config may have RecoveryCodes disabled"
}
Write-Host "  initial recovery codes ($($initialCodes.Count)):" -ForegroundColor Yellow
$initialCodes | ForEach-Object { Write-Host "    $_" }

# 6) Regenerate. This is the headline path: server hashes N new codes via Parallel.For.
$regen = Measure-Step "6. POST /me/mfa/recovery-codes (regenerate — parallel PBKDF2)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/recovery-codes" -Headers $bearer
}

$newCodes = $null
if      ($regen.recovery_codes) { $newCodes = $regen.recovery_codes }
elseif  ($regen.codes)          { $newCodes = $regen.codes }
elseif  ($regen -is [System.Array]) { $newCodes = $regen }
else    { $newCodes = @() }

Write-Host "  regenerated codes ($($newCodes.Count)):" -ForegroundColor Yellow
$newCodes | ForEach-Object { Write-Host "    $_" }

if ($newCodes.Count -lt 1) {
    Write-Host "  ! server returned no codes on regenerate (response shape: $($regen | ConvertTo-Json -Compress))" -ForegroundColor Red
} elseif (-not (Compare-Object $initialCodes $newCodes)) {
    Write-Host "  ! regenerate returned the SAME set of codes — rotation broken" -ForegroundColor Red
} else {
    Write-Host "  ✓ codes rotated (no overlap with previous batch expected)" -ForegroundColor Green
}

# 7) Steady-state x3 to expose the parallel speed-up. With Parallel.For the wall time
#    should NOT scale linearly with code count.
Write-Host ""
Write-Host "=== [7. regenerate steady-state x3] ===" -ForegroundColor Cyan
$ms = @()
for ($i = 1; $i -le 3; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/mfa/recovery-codes" -Headers $bearer | Out-Null
    $sw.Stop()
    $ms += [int]$sw.Elapsed.TotalMilliseconds
    Write-Host ("  iter {0}: {1,5} ms" -f $i, $ms[-1])
}
$avg = [int](($ms | Measure-Object -Average).Average)
Write-Host ("  avg={0} ms  min={1} ms  max={2} ms" -f $avg, ($ms | Measure-Object -Minimum).Minimum, ($ms | Measure-Object -Maximum).Maximum) -ForegroundColor Yellow
$timings.Add([pscustomobject]@{ Step="7. regenerate steady-state x3 (avg)"; Ms=$avg; Status="ok" })

# 8) Confirm a STALE code (from the very first batch) no longer works. This depends
#    on whether the server exposes a recovery-code redemption endpoint. We try the
#    common /api/v1/identity/me/mfa/recovery path; if 404, we just note the absence.
if ($initialCodes.Count -gt 0) {
    $stale = $initialCodes[0]
    Measure-Step "8. redeem stale recovery code (expect rejection)" {
        $endpoints = @(
            "$BASE/api/v1/identity/me/mfa/recovery",
            "$BASE/api/v1/identity/account/mfa/recovery"
        )
        $tried = $false
        foreach ($ep in $endpoints) {
            try {
                Invoke-RestMethod -Method Post $ep -Headers $bearer `
                  -ContentType "application/json" `
                  -Body (@{ code = $stale } | ConvertTo-Json) | Out-Null
                $tried = $true
                Write-Host "  ! stale code accepted at $ep — rotation broken" -ForegroundColor Red
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($code -eq 404) { continue }   # try next endpoint
                $tried = $true
                if ($code -in 400, 401, 403, 409) {
                    Write-Host "  ✓ stale code rejected at $ep status=$code" -ForegroundColor Green
                } else {
                    Write-Host "  ! unexpected status=$code at $ep" -ForegroundColor Yellow
                }
                break
            }
        }
        if (-not $tried) {
            Write-Host "  (no recovery-redeem endpoint found — rotation verified by code-set comparison only)" -ForegroundColor DarkGray
        }
    } | Out-Null
}

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
Write-Host "(check Worker log for parallel PBKDF2 timing — Parallel.For shrinks wall-time vs code count)" -ForegroundColor DarkGray
