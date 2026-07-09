# client_credentials grant — pure machine-to-machine (no user, no browser).
# Usage: pwsh -File demo_client_credentials.ps1

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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Register a client_credentials-only client.
$reg = Measure-Step "1. DCR /connect/register (client_credentials)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name = "cc-demo"
        grant_types = @("client_credentials")
        scope       = "identity:read"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Get an access_token without any user.
$tok = Measure-Step "2. POST /connect/token (grant=client_credentials)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "client_credentials"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        scope         = "identity:read"
      }
}
$tok | Format-List access_token, token_type, expires_in, scope

# 3) Decode JWT header (access_token may be JWE-encrypted; if so we skip).
function Decode-Jwt([string]$jwt) {
  $parts = $jwt.Split('.')
  if ($parts.Length -lt 2) { return $null }
  $payload = $parts[1].Replace('-','+').Replace('_','/')
  switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
  try {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
  } catch { $null }
}

Measure-Step "3. decode access_token (best-effort)" {
    $j = Decode-Jwt $tok.access_token
    if ($null -eq $j) {
        Write-Host "  (access_token is JWE-encrypted; not directly decodable — that's normal)" -ForegroundColor Yellow
    } else {
        $j | ConvertTo-Json -Depth 5
    }
} | Out-Host

# 4) Introspect — works whether the token is JWE or not, because the server holds the key.
$intro = Measure-Step "4. POST /connect/introspect" {
    Invoke-RestMethod -Method Post "$BASE/connect/introspect" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token         = $tok.access_token
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
      }
}
$intro | ConvertTo-Json -Depth 5 | Out-Host

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
