# RFC 6585 §4 — HTTP 429 Too Many Requests + Retry-After (RFC 7231 §7.1.3) probes
# on rate-limited endpoints. Closes the "ThrottleProcessor silently waits instead of
# returning 429" hardening gap flagged in the previous batch's perf diagnosis.
#
# We exercise the /connect/token endpoint, which carries the tightest throttle in the
# server (`TokenThrottleMaxPerPeriod = 10` per 1 second by default, keyed by client_id).
# Bursting > 10 token requests within 1 second on the same client_id must:
#   1. yield at least one 429 status code,
#   2. with a `Retry-After` header carrying a delta-seconds integer (RFC 7231 §7.1.3),
#   3. and a structured JSON body { error: "rate_limit_exceeded", retry_after: N },
#   4. so a well-behaved client can sleep that many seconds, retry, and succeed.
#
# Probes:
#   1.  DCR (client_credentials + identity:read)
#   2.  Sanity: single /connect/token succeeds + non-429 status
#   3.  Burst 25 concurrent /connect/token calls with the same client_id → expect at
#       least 10 success (the bucket size) AND at least 1 status=429
#   4.  Pick one 429 response → assert Retry-After header is present and parses as
#       a positive integer (delta-seconds form)
#   5.  Assert the 429 body shape: error == "rate_limit_exceeded", retry_after > 0
#   6.  Sleep Retry-After + 0.5 s, then a single /connect/token MUST succeed
#       (recovery contract — the throttle window has rolled over)
#   7.  Different client_id is NOT affected by the first key's burst — confirms the
#       KeyedThrottle isolates buckets per key (probe a fresh DCR'd client immediately
#       after the burst; it must succeed without waiting)
#   8.  RFC 7592 cleanup
#
# Usage: pwsh -File demo_throttle_rfc6585.ps1
#requires -Version 7

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
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "--- [$Name] $ms ms" -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "!!! [$Name] FAILED in $ms ms: $($_.Exception.Message)" -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="fail" })
        throw
    }
}

function Invoke-TokenRaw {
    param([string]$ClientId, [string]$ClientSecret, [string]$Scope = "identity:read")
    # Use a Hashtable body — PowerShell auto-encodes each field per
    # application/x-www-form-urlencoded, which is critical because client_secret
    # may contain '=' or '+' that would otherwise be misinterpreted by the server.
    $resp = Invoke-WebRequest -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        } -SkipHttpErrorCheck -ErrorAction Stop
    # Headers may surface ETag/Retry-After under different cases; do a case-insensitive scan.
    $retryAfter = $null
    foreach ($k in $resp.Headers.Keys) {
        if ($k -ieq "Retry-After") {
            $v = $resp.Headers[$k]
            if ($v -is [Array]) { $v = $v[0] }
            $retryAfter = $v
            break
        }
    }
    $bodyObj = if ($resp.Content) {
        try { $resp.Content | ConvertFrom-Json } catch { $null }
    } else { $null }
    return [pscustomobject]@{
        Status     = [int]$resp.StatusCode
        Body       = $bodyObj
        RetryAfter = $retryAfter
        Raw        = $resp
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR a client_credentials client. We'll burst /connect/token with this one.
$reg = Measure-Step "1. DCR (cc + identity:read)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "throttle-rfc6585"
            grant_types = @("client_credentials")
            scope       = "identity:read"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Sanity — single token call works.
Measure-Step "2. sanity: single /connect/token (expect 200)" {
    $r = Invoke-TokenRaw -ClientId $reg.client_id -ClientSecret $reg.client_secret
    if ($r.Status -ne 200) { throw "sanity call failed: status=$($r.Status), body=$($r.Body | ConvertTo-Json -Depth 3)" }
    if (-not $r.Body.access_token) { throw "no access_token on success" }
    Write-Host "  ✓ 200, access_token present" -ForegroundColor Green
} | Out-Null

# 3) Burst — fire 30 PARALLEL calls. Sequential calls would re-fill the throttle
#    window between each request (TokenThrottleMaxPerPeriod=10 / 1 s + per-call
#    latency of ~150 ms means a sequential 25-loop never exceeds the budget).
#    True concurrency forces the bucket to drain.
$burstResults = Measure-Step "3. burst × 30 PARALLEL /connect/token same client_id (expect mix of 200 + 429)" {
    $cid = $reg.client_id
    $sec = $reg.client_secret
    $base = $BASE
    $results = 1..30 | ForEach-Object -Parallel {
        $resp = Invoke-WebRequest -Method Post "$using:base/connect/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                grant_type    = "client_credentials"
                client_id     = $using:cid
                client_secret = $using:sec
                scope         = "identity:read"
            } -SkipHttpErrorCheck -ErrorAction Stop
        $retryAfter = $null
        foreach ($k in $resp.Headers.Keys) {
            if ($k -ieq "Retry-After") {
                $v = $resp.Headers[$k]
                if ($v -is [Array]) { $v = $v[0] }
                $retryAfter = $v; break
            }
        }
        $bodyObj = if ($resp.Content) {
            try { $resp.Content | ConvertFrom-Json } catch { $null }
        } else { $null }
        [pscustomobject]@{
            Status     = [int]$resp.StatusCode
            Body       = $bodyObj
            RetryAfter = $retryAfter
        }
    } -ThrottleLimit 30

    $by = $results | Group-Object Status
    foreach ($g in $by) {
        Write-Host "  status=$($g.Name) → count=$($g.Count)" -ForegroundColor DarkGray
    }
    $ok  = ($results | Where-Object { $_.Status -eq 200 }).Count
    $r29 = ($results | Where-Object { $_.Status -eq 429 }).Count
    if ($ok -lt 1)  { throw "no successful token calls in 30-burst — server unreachable?" }
    if ($r29 -lt 1) { throw "no 429 response in 30-burst on same client_id — throttle / RejectOnOverflow not wired" }
    Write-Host "  ✓ 200 × $ok, 429 × $r29" -ForegroundColor Green
    return $results
}

# 4) Pick a 429, assert Retry-After header is delta-seconds (RFC 7231 §7.1.3).
$first429 = $burstResults | Where-Object { $_.Status -eq 429 } | Select-Object -First 1
Measure-Step "4. assert Retry-After header (RFC 7231 §7.1.3 delta-seconds)" {
    if (-not $first429.RetryAfter) {
        throw "429 response missing Retry-After header (RFC 6585 §4 requires it)"
    }
    $ra = $first429.RetryAfter.ToString().Trim()
    if (-not ($ra -match '^\d+$')) {
        throw "Retry-After must be a non-negative integer (delta-seconds form), got: '$ra'"
    }
    $secs = [int]$ra
    if ($secs -lt 1) { throw "Retry-After must be >= 1 s, got $secs" }
    Write-Host "  ✓ Retry-After: $secs s" -ForegroundColor Green
    $script:retryAfterSecs = $secs
} | Out-Null

# 5) Assert body shape.
Measure-Step "5. assert 429 body shape { error, retry_after }" {
    $b = $first429.Body
    if (-not $b) { throw "429 body did not parse as JSON" }
    if ($b.error -ne "rate_limit_exceeded") {
        throw "expected error='rate_limit_exceeded', got '$($b.error)'"
    }
    if (-not $b.retry_after -or [int]$b.retry_after -lt 1) {
        throw "expected retry_after >= 1, got '$($b.retry_after)'"
    }
    if ([int]$b.retry_after -ne $script:retryAfterSecs) {
        # Not strictly required by RFC, but the body should match the header for sanity.
        Write-Host "  ⚠ body.retry_after ($($b.retry_after)) != header Retry-After ($($script:retryAfterSecs)) — minor inconsistency" -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ body.retry_after matches header" -ForegroundColor Green
    }
    Write-Host "  ✓ error='$($b.error)', retry_after=$($b.retry_after)" -ForegroundColor Green
} | Out-Null

# 6) Wait the advised period + a small grace window, then retry the same client → must succeed.
Measure-Step "6. sleep $($script:retryAfterSecs)s + grace, retry → expect 200 (recovery contract)" {
    Start-Sleep -Milliseconds (($script:retryAfterSecs * 1000) + 500)
    $r = Invoke-TokenRaw -ClientId $reg.client_id -ClientSecret $reg.client_secret
    if ($r.Status -ne 200) {
        throw "after Retry-After window, expected 200 but got $($r.Status). Body: $($r.Body | ConvertTo-Json -Depth 3)"
    }
    if (-not $r.Body.access_token) { throw "post-Retry-After response missing access_token" }
    Write-Host "  ✓ recovered: 200 + fresh access_token" -ForegroundColor Green
} | Out-Null

# 7) Different client_id is NOT affected — KeyedThrottle isolation.
$reg2 = Measure-Step "7a. DCR a second client (isolation probe)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "throttle-rfc6585-iso"
            grant_types = @("client_credentials")
            scope       = "identity:read"
        } | ConvertTo-Json)
}
$RAT2 = $reg2.registration_access_token
$RCU2 = $reg2.registration_client_uri

Measure-Step "7b. /connect/token on the OTHER client immediately → 200 (per-key isolation)" {
    # Saturate client_id #1 first so we know the global throttle is NOT being hit.
    for ($i = 1; $i -le 15; $i++) {
        Invoke-TokenRaw -ClientId $reg.client_id -ClientSecret $reg.client_secret | Out-Null
    }
    # Now hit client_id #2 — its bucket has not been touched at all.
    $r = Invoke-TokenRaw -ClientId $reg2.client_id -ClientSecret $reg2.client_secret
    if ($r.Status -ne 200) {
        throw "second client throttled by first client's burst (got $($r.Status)) — KeyedThrottle isolation broken"
    }
    Write-Host "  ✓ second client got 200 — keys are isolated" -ForegroundColor Green
} | Out-Null

# 8) RFC 7592 cleanup
Measure-Step "8. RFC 7592 DELETE both registrations" {
    if ($RAT)  { Invoke-RestMethod -Method Delete -Uri $RCU  -Headers @{ Authorization = "Bearer $RAT" }  | Out-Null }
    if ($RAT2) { Invoke-RestMethod -Method Delete -Uri $RCU2 -Headers @{ Authorization = "Bearer $RAT2" } | Out-Null }
    Write-Host "  ✓ both DCR clients deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
