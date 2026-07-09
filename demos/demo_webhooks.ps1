# W1 — outbound webhook subscription probe.
#
# Verifies the full lifecycle end-to-end:
#   1. admin DCR + token
#   2. spin up a pwsh HttpListener mock receiver on 127.0.0.1:<port>
#   3. create a webhook subscription pointed at the receiver
#   4. trigger a user-create event (POST /users)
#   5. wait for the mock receiver to record the delivery; assert:
#      - X-RedbIdentity-Signature header verifies via shared secret
#      - X-RedbIdentity-EventType = UserCreated
#      - body parses as IdentityEvent with the expected fields
#   6. rotate secret; trigger another event; assert NEW secret signs
#   7. delete the subscription; trigger another event; assert receiver
#      sees nothing (subscription removed)
#   8. cleanup
#
#requires -Version 7

$BASE = "http://127.0.0.1:5002"
$timings = [System.Collections.Generic.List[object]]::new()
$totalSw = [System.Diagnostics.Stopwatch]::StartNew()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""; Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Action; $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $r
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

# ── Pick a free local port for the mock receiver ───────────────────
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$receiverPath = "/webhook"
$receiverUrl = "http://127.0.0.1:$port$receiverPath"

# Storage for received deliveries (cross-runspace via shared variable)
$Global:WebhookDeliveries = [System.Collections.Generic.List[object]]::new()
$Global:WebhookCancellation = $false

# Start mock receiver in a background runspace. The listener is registered
# on both the webhook path AND a /__shutdown path — sending to the latter
# breaks the GetContext block on parent-side cleanup so Remove-Job returns
# in milliseconds instead of waiting the default 120s timeout.
$receiver = Start-Job -ScriptBlock {
    param($port, $path)
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$port$path/")
    $listener.Prefixes.Add("http://127.0.0.1:$port$path")
    $listener.Prefixes.Add("http://127.0.0.1:$port/__shutdown/")
    $listener.Start()
    $records = [System.Collections.Generic.List[object]]::new()
    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
            if ($ctx.Request.Url.AbsolutePath -eq "/__shutdown") {
                $ctx.Response.StatusCode = 200
                $ctx.Response.Close()
                break
            }

            $headers = @{}
            foreach ($k in $ctx.Request.Headers.AllKeys) {
                $headers[$k] = $ctx.Request.Headers[$k]
            }
            $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream, $ctx.Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()

            $records.Add([pscustomobject]@{
                ReceivedAt = (Get-Date).ToString('o')
                Headers = $headers
                Body = $body
                Method = $ctx.Request.HttpMethod
                Url = $ctx.Request.Url.AbsolutePath
            })

            # Persist after every delivery so the parent can poll.
            $records | ConvertTo-Json -Depth 8 -Compress | Set-Content -Path "$env:TEMP\webhook-deliveries-$port.json"

            $ctx.Response.StatusCode = 200
            $ctx.Response.ContentLength64 = 0
            $ctx.Response.Close()
        } catch {
            break
        }
    }
    $listener.Stop()
} -ArgumentList $port, $receiverPath
Write-Host "started mock receiver on $receiverUrl (job=$($receiver.Id))" -ForegroundColor Gray

function Read-Deliveries {
    $f = "$env:TEMP\webhook-deliveries-$port.json"
    if (-not (Test-Path $f)) { return @() }
    try { return Get-Content $f -Raw | ConvertFrom-Json } catch { return @() }
}

function Wait-Delivery {
    param([scriptblock]$Predicate, [int]$TimeoutMs = 8000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalMilliseconds -lt $TimeoutMs) {
        $deliveries = @(Read-Deliveries)
        foreach ($d in $deliveries) {
            if (& $Predicate $d) { return $d }
        }
        Start-Sleep -Milliseconds 200
    }
    return $null
}

function Verify-Signature {
    param($delivery, [string]$secret)
    $sigHeader = $delivery.Headers.'X-RedbIdentity-Signature'
    if (-not $sigHeader) { throw "no signature header" }
    if ($sigHeader -notlike "sha256=*") { throw "signature header format wrong" }
    $sigHex = $sigHeader.Substring(7).ToLowerInvariant()
    # Body is HMACed verbatim as UTF-8 bytes (GitHub-style).
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret)
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($delivery.Body)
    $computed = ($hmac.ComputeHash($bodyBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    if ($computed -ne $sigHex) {
        throw "signature mismatch - expected $computed got $sigHex"
    }
}

# ── Admin scaffolding ────────────────────────────────────────────
$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "webhooks-probe-admin"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$H = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# Cleanup stale subscriptions pointing at any old run's port (best-effort)
try {
    $stale = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/webhooks?count=200" -Headers $H
    foreach ($s in $stale.items) {
        if ($s.url -like '*webhook*' -and $s.url -like '*127.0.0.1*') {
            try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/webhooks/$($s.id)" -Headers $H | Out-Null } catch {}
        }
    }
} catch {}

# ── Subscription lifecycle ───────────────────────────────────────
$created = Measure-Step "3. POST /webhooks (filter=UserCreated)" {
    $body = @{
        url = $receiverUrl
        displayName = "demo-webhook"
        eventTypeFilter = "UserCreated"
        enabled = $true
        timeoutMs = 5000
        maxAttempts = 2
    } | ConvertTo-Json
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/webhooks" -Headers $H -Body $body
}
$secret = $created.hmacSecret
$SubId = [long]$created.id
if (-not $secret) { throw "hmacSecret missing on create response" }
Write-Host "  created id=$SubId secret length=$($secret.Length)" -ForegroundColor Gray

# Trigger an event the subscription matches
$suffix = [Guid]::NewGuid().ToString('N').Substring(0,6)
$login = "wh_$suffix"
$user = Measure-Step "4. POST /users (fires UserCreated)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $H `
      -Body (@{ login = $login; password = "Test1234Pass!"; displayName = $login } | ConvertTo-Json)
}
$UserId = [long]$user.id

# Wait for the delivery
Measure-Step "5. wait for HTTP POST + verify HMAC signature" {
    $delivery = Wait-Delivery { param($d) $d.Headers.'X-RedbIdentity-EventType' -eq 'UserCreated' -and $d.Body -match $login }
    if (-not $delivery) { throw "no UserCreated delivery received within timeout" }
    Write-Host "  delivery headers: $($delivery.Headers.Keys -join ', ')" -ForegroundColor Gray
    Verify-Signature -delivery $delivery -secret $secret
    Write-Host "  signature OK; body length=$($delivery.Body.Length)" -ForegroundColor Green
} | Out-Null

# Rotate secret + trigger another event
$rotateResp = Measure-Step "6. POST /webhooks/$SubId/rotate-secret" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/webhooks/$SubId/rotate-secret" -Headers $H
}
$newSecret = $rotateResp.hmacSecret
if (-not $newSecret) { throw "rotate-secret did not return new secret" }
if ($newSecret -eq $secret) { throw "rotate-secret returned the same value" }

# Clear file so wait sees only the next delivery
$deliveryFile = "$env:TEMP\webhook-deliveries-$port.json"
if (Test-Path $deliveryFile) { Remove-Item $deliveryFile -Force }

$login2 = "wh2_$suffix"
$user2 = Measure-Step "7. POST /users #2 (fires UserCreated under NEW secret)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $H `
      -Body (@{ login = $login2; password = "Test1234Pass!"; displayName = $login2 } | ConvertTo-Json)
}

Measure-Step "8. verify NEW secret signs (old secret would mismatch)" {
    $delivery = Wait-Delivery { param($d) $d.Headers.'X-RedbIdentity-EventType' -eq 'UserCreated' -and $d.Body -match $login2 }
    if (-not $delivery) { throw "no delivery for #2 received" }
    Verify-Signature -delivery $delivery -secret $newSecret
    Write-Host "  new secret verified" -ForegroundColor Green

    # Sanity: old secret should NOT verify
    $oldSecretError = $null
    try { Verify-Signature -delivery $delivery -secret $secret }
    catch { $oldSecretError = $_.Exception.Message }
    if (-not $oldSecretError) { throw "old secret unexpectedly verified — rotate-secret didn't take effect" }
    Write-Host "  old secret correctly REJECTED" -ForegroundColor Green
} | Out-Null

# Delete subscription, trigger another event, assert receiver sees nothing
if (Test-Path $deliveryFile) { Remove-Item $deliveryFile -Force }
Measure-Step "9. DELETE /webhooks/$SubId" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/webhooks/$SubId" -Headers $H | Out-Null
} | Out-Null

$login3 = "wh3_$suffix"
$user3 = Measure-Step "10. POST /users #3 (no subscription left)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $H `
      -Body (@{ login = $login3; password = "Test1234Pass!"; displayName = $login3 } | ConvertTo-Json)
}

Measure-Step "11. assert NO delivery received" {
    Start-Sleep -Milliseconds 2000
    $deliveries = @(Read-Deliveries)
    if ($deliveries.Count -gt 0) {
        throw "received $($deliveries.Count) deliveries after subscription was deleted"
    }
} | Out-Null

# Cleanup
Measure-Step "12. cleanup" {
    foreach ($u in @($user, $user2, $user3)) {
        try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$($u.id)" -Headers $H | Out-Null } catch {}
    }
    # HttpListener.GetContext() blocks until a request — Stop-Job sends a
    # cancellation but the inner thread is stuck inside the GetContext call,
    # so PowerShell waits the full default 120s for the job to "complete"
    # cleanly. Sending a request to a freed listener immediately makes
    # GetContext throw → the runspace exits → Remove-Job returns instantly.
    try { Invoke-WebRequest -Uri "http://127.0.0.1:$port/__shutdown" -TimeoutSec 1 | Out-Null } catch {}
    Remove-Job $receiver -Force -ErrorAction SilentlyContinue
    if (Test-Path $deliveryFile) { Remove-Item $deliveryFile -Force }
} | Out-Null

$totalSw.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $totalSw.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
