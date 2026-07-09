# Per-step timing wrapper. Use:  pwsh -File demo_jwt.ps1
# Each step prints its wall-clock duration; a final table summarises.

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
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "ok" })
        return $result
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "fail" })
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — регистрация клиента
$reg = Measure-Step "1. DCR /connect/register" {
    Invoke-RestMethod -Method Post http://127.0.0.1:5002/connect/register `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "jwt-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret


# 2) Регистрация пользователя (если ещё нет)
Measure-Step "2. account/register" {
    try {
        Invoke-RestMethod -Method Post http://127.0.0.1:5002/api/v1/identity/account/register `
          -ContentType "application/json" `
          -Body (@{
            login       = "testuser2"
            email       = "testuser2@example.com"
            password    = "Test1234Pass!"
            displayName = "Test User 2"
          } | ConvertTo-Json)
    } catch {
        Write-Host "  (already exists or non-fatal: $($_.Exception.Message))" -ForegroundColor Yellow
    }
} | Out-Null


# 3) Password grant → JWT
$tok = Measure-Step "3. password grant /connect/token" {
    Invoke-RestMethod -Method Post http://127.0.0.1:5002/connect/token `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = "testuser2"
        password      = "Test1234Pass!"
        scope         = "openid profile email offline_access"
      }
}
$tok | Format-List access_token, id_token, refresh_token, expires_in


# 4) Декодировать id_token (JWS — читается без ключа)
function Decode-Jwt([string]$jwt) {
  $payload = $jwt.Split('.')[1].Replace('-','+').Replace('_','/')
  $payload += '=' * ((4 - $payload.Length % 4) % 4)
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

Measure-Step "4. decode id_token (local)" {
    Decode-Jwt $tok.id_token | ConvertTo-Json
} | Out-Host


# 5) access_token — JWE-encrypted, claims через /connect/userinfo
Measure-Step "5. /connect/userinfo" {
    Invoke-RestMethod http://127.0.0.1:5002/connect/userinfo `
      -Headers @{ Authorization = "Bearer $($tok.access_token)" } | ConvertTo-Json
} | Out-Host


# 6) Refresh
$refreshed = Measure-Step "6. refresh_token grant" {
    Invoke-RestMethod -Method Post http://127.0.0.1:5002/connect/token `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "refresh_token"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        refresh_token = $tok.refresh_token
      }
}
$refreshed | Format-List access_token, refresh_token, expires_in

$total.Stop()

Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
