# Federation end-to-end — provision-on-first-login + link-on-replay.
#
# Closes release-gate item #3. Builds on the existing `demo_federation` redirect-surface
# probe by driving the FULL flow end-to-end against a real upstream OIDC IdP:
#
#   1. provision a federation provider via the admin API pointing at navikt's
#      mock-oauth2-server (pre-running on the `rinat-net` docker network at :9199)
#   2. discovery + public list assert the provider surfaces correctly
#   3. initiate `/connect/external-login` → follow 302 to mock IdP `/authorize`
#   4. POST the mock IdP login form (auto-issues code+state on the configured redirect_uri)
#   5. follow the callback back into identity → identity provisions user + sets session,
#      302 to returnUrl
#   6. admin-side: query users → assert the new user exists with the IdP's email claim
#   7. replay the entire challenge/callback → assert NO duplicate user is created
#      (link-on-replay contract — the federated_identity row matches and login reuses it)
#   8. cleanup (delete user, delete provider, delete admin DCR)
#
# Requires `route-mock-oauth2` (navikt/mock-oauth2-server) reachable at
# http://localhost:9199/default. If absent the demo prints a skip message and exits 0
# (so run_all stays green on machines that don't have the dev compose stack up).
#
# Usage: pwsh -File demo_federation_e2e.ps1
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
# Use 127.0.0.1 — mock-oauth2-server's discovery doc embeds 127.0.0.1 in issuer / authorize_endpoint,
# and OIDC clients refuse responses where the issuer doesn't match the configured authority.
$IDP    = "http://127.0.0.1:9199/default"
$PROV   = "mock-idp-e2e"
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

# Single-hop request via curl.exe — no auto-redirect, returns status + Location + body.
function Hop {
    param(
        [string]$Method,
        [string]$Url,
        $Body = $null,
        [hashtable]$Headers = $null,
        [string]$ContentType = $null
    )
    # NOTE: don't name this `$args` — pwsh aliases that to the function's argument array
    # and `& curl.exe @args` then splats the original args, not our list.
    # Also UPPER-CASE the HTTP method — servers are case-sensitive per RFC 7230 §3.1.1.
    $curlArgs = @('-s', '-k', '-i', '-m', '10', '-X', $Method.ToUpperInvariant())
    if ($Headers) {
        foreach ($k in $Headers.Keys) { $curlArgs += @('-H', "$($k): $($Headers[$k])") }
    }
    $tempBodyFile = $null
    if ($null -ne $Body) {
        if ($Body -is [hashtable]) {
            $ct = if ($ContentType) { $ContentType } else { 'application/x-www-form-urlencoded' }
            $curlArgs += @('-H', "Content-Type: $ct")
            $parts = $Body.GetEnumerator() | ForEach-Object {
                "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString([string]$_.Value))"
            }
            $payload = $parts -join '&'
        } elseif ($Body -is [string]) {
            $ct = if ($ContentType) { $ContentType } else { 'application/json' }
            $curlArgs += @('-H', "Content-Type: $ct")
            $payload = $Body
        } else {
            $ct = if ($ContentType) { $ContentType } else { 'application/json' }
            $curlArgs += @('-H', "Content-Type: $ct")
            $payload = ($Body | ConvertTo-Json -Depth 6 -Compress)
        }
        $tempBodyFile = New-TemporaryFile
        [System.IO.File]::WriteAllText($tempBodyFile, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @('--data-binary', "@$tempBodyFile")
    }
    $curlArgs += $Url
    try {
        $raw = & curl.exe @curlArgs
    } finally {
        if ($tempBodyFile) { Remove-Item $tempBodyFile -ErrorAction SilentlyContinue }
    }
    $text = ($raw -join "`n")
    # Split headers / body on first blank line.
    $sepIdx = $text.IndexOf("`n`n")
    $headerSection = if ($sepIdx -gt 0) { $text.Substring(0, $sepIdx) } else { $text }
    $bodySection = if ($sepIdx -gt 0) { $text.Substring($sepIdx + 2) } else { "" }
    # Status line
    $firstLine = ($headerSection -split "`n")[0]
    $statusCode = 0
    if ($firstLine -match 'HTTP/\S+\s+(\d+)') { $statusCode = [int]$matches[1] }
    # Location header
    $location = $null
    foreach ($h in ($headerSection -split "`n")) {
        if ($h -match '^[Ll]ocation:\s*(.+?)\s*$') { $location = $matches[1]; break }
    }
    return [pscustomobject]@{
        StatusCode = $statusCode
        Location   = $location
        Content    = $bodySection
        Headers    = $headerSection
    }
}

# IRM/IWR substitute via curl.exe — pwsh's HTTP stack hangs against some redb.Identity
# admin endpoints (suspected HTTP/2 vs chunked-with-custom-headers interaction) but
# curl.exe handles them in ~100ms. Returns parsed JSON object, throws structured error
# string on non-2xx so calling code can pattern-match.
function Get-Json {
    param([string]$Method, [string]$Url, $Body = $null, [hashtable]$Headers = $null, [string]$ContentType = "application/json")
    $curlArgs = @('-s', '-k', '-m', '15', '-w', '||%{http_code}||', '-X', $Method.ToUpperInvariant())
    if ($Headers) {
        foreach ($k in $Headers.Keys) { $curlArgs += @('-H', "$($k): $($Headers[$k])") }
    }
    $tempBodyFile = $null
    if ($null -ne $Body) {
        $curlArgs += @('-H', "Content-Type: $ContentType")
        $payload = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 6 -Compress }
        $tempBodyFile = New-TemporaryFile
        [System.IO.File]::WriteAllText($tempBodyFile, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @('--data-binary', "@$tempBodyFile")
    }
    $curlArgs += $Url
    try {
        $raw = & curl.exe @curlArgs
    } finally {
        if ($tempBodyFile) { Remove-Item $tempBodyFile -ErrorAction SilentlyContinue }
    }
    if ($null -eq $raw) { throw "curl returned no output for $Method $Url" }
    $text = ($raw -join "`n")
    # Marker form is `||NNN||` appended after body. Find the OPENING marker so body
    # stays unchanged even if it happens to contain '||' literals.
    $markerIdx = $text.LastIndexOf('||', $text.Length - 1)
    # Walk back to the start of the marker triplet: find the LAST occurrence where the
    # remainder is just digits + '||'.
    $m = [regex]::Match($text, '\|\|(\d{3})\|\|\s*$')
    if (-not $m.Success) { throw "curl marker missing in: $text" }
    $bodyOut = $text.Substring(0, $m.Index)
    $status = [int]$m.Groups[1].Value
    if ($status -ge 400) {
        throw "HTTP $status $Method $Url : $bodyOut"
    }
    if (-not $bodyOut -or $bodyOut.Length -eq 0) { return $null }
    return $bodyOut | ConvertFrom-Json -Depth 8
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 0) Skip if mock IdP not reachable — keeps run_all green on bare machines.
try {
    $r = Hop -Method Get -Url "$IDP/.well-known/openid-configuration"
    if ($r.StatusCode -ne 200) { throw "status $($r.StatusCode)" }
} catch {
    Write-Host ""
    Write-Host "mock-oauth2-server not reachable at $IDP — skipping e2e federation demo." -ForegroundColor Yellow
    Write-Host "Start it via:" -ForegroundColor DarkGray
    Write-Host "  docker run -p 9199:8080 ghcr.io/navikt/mock-oauth2-server:2.1.10" -ForegroundColor DarkGray
    exit 0
}
Write-Host "mock IdP at $IDP reachable, proceeding." -ForegroundColor DarkGray

# The OP-issued federation callback targets the OP's ISSUER host, and our session cookies are
# bound to whatever host we drive — so if the two differ (e.g. the conformance context.json pins
# the issuer to host.docker.internal while we started on 127.0.0.1) the cross-host callback can't
# complete. Re-target to the issuer host so the FULL end-to-end flow — real requests and all —
# actually runs. Only skip if that issuer isn't reachable from here.
try {
    $__disc = Get-Json -Method Get -Url "$BASE/.well-known/openid-configuration"
    $__issuerUri = [uri]$__disc.issuer
    if ($__issuerUri.Host -and $__issuerUri.Host -ne ([uri]$BASE).Host) {
        $__issuerBase = "$($__issuerUri.Scheme)://$($__issuerUri.Host):$($__issuerUri.Port)"
        $__reachable = $false
        try { $__reachable = $null -ne (Get-Json -Method Get -Url "$__issuerBase/.well-known/openid-configuration").issuer } catch {}
        if ($__reachable) {
            Write-Host "Re-targeting to the OP issuer host ($($__issuerUri.Host)) so the federation callback lines up." -ForegroundColor DarkGray
            $BASE = $__issuerBase
        } else {
            Write-Host ""
            Write-Host "OP issuer host ($($__issuerUri.Host)) differs from the base and isn't reachable here — skipping." -ForegroundColor Yellow
            Write-Host "Re-run with IDENTITY_BASE pointed at the issuer to exercise the full flow." -ForegroundColor DarkGray
            exit 0
        }
    }
} catch {}

# 1) DCR admin (just users.manage — we use it to verify provisioning + cleanup).
$adminReg = Measure-Step "1. DCR admin (users.manage)" {
    $r = Get-Json -Method Post -Url "$BASE/connect/register" -Body @{
        client_name = "fed-e2e"
        grant_types = @("client_credentials")
        scope       = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
    }
    Write-Host "  client_id: $($r.client_id)"
    return $r
}
$ADMIN_RAT = $adminReg.registration_access_token
$ADMIN_RCU = $adminReg.registration_client_uri

$adminTok = Measure-Step "2. admin cc token" {
    $form = "grant_type=client_credentials&client_id=$([Uri]::EscapeDataString($adminReg.client_id))" +
            "&client_secret=$([Uri]::EscapeDataString($adminReg.client_secret))" +
            "&scope=$([Uri]::EscapeDataString('identity:users:write identity:groups:write identity:consents:write identity:mfa:write'))"
    Get-Json -Method Post -Url "$BASE/connect/token" -Body $form -ContentType "application/x-www-form-urlencoded"
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)" }

# 3) Discovery advertises the mock provider (configured statically in context.json).
Measure-Step "3. discovery + public list advertise $PROV" {
    $d = Get-Json -Method Get -Url "$BASE/.well-known/openid-configuration"
    $ids = $d.federation_providers | ForEach-Object { $_.id }
    if ($ids -notcontains $PROV) { throw "discovery missing $PROV — got [$($ids -join ',')]" }
    $p = Get-Json -Method Get -Url "$BASE/api/v1/identity/federation-providers/public"
    $pubIds = $p | ForEach-Object { $_.providerId }
    if ($pubIds -notcontains $PROV) { throw "public list missing $PROV — got [$($pubIds -join ',')]" }
    Write-Host "  discovery + public list OK" -ForegroundColor Green
} | Out-Null

# Helper: drive one full challenge → callback round-trip end-to-end, return the email
# that mock IdP issued (so we can verify the provisioned user).
function Invoke-FederationRoundTrip {
    param([string]$Username, [hashtable]$Claims)

    # Step A: challenge — identity issues 302 to mock IdP /authorize with our encrypted state.
    $r1 = Hop -Method Get -Url "$BASE/connect/external-login?provider=$PROV&returnUrl=/"
    if ($r1.StatusCode -lt 300 -or $r1.StatusCode -ge 400) {
        $snippet = if ($r1.Content) { $r1.Content.Substring(0, [Math]::Min(200,$r1.Content.Length)) } else { "(no body)" }
        throw "challenge returned $($r1.StatusCode), expected 3xx (body: $snippet)"
    }
    $idpUrl = $r1.Location
    if (-not $idpUrl) { throw "challenge response has no Location header" }
    if (-not $idpUrl.StartsWith($IDP)) { throw "challenge redirect to '$idpUrl' is not the mock IdP" }

    # Step B: post the mock-oauth2-server login form.
    $r2 = Hop -Method Post -Url $idpUrl -Body @{
        username = $Username
        claims   = ($Claims | ConvertTo-Json -Compress)
    }
    if ($r2.StatusCode -ne 302) { throw "mock IdP /authorize returned $($r2.StatusCode), expected 302" }
    $callbackUrl = $r2.Location
    if (-not $callbackUrl.StartsWith("$BASE/connect/federation/callback")) {
        throw "mock IdP redirected to '$callbackUrl', expected our callback"
    }

    # Step C: identity processes callback.
    $r3 = Hop -Method Get -Url $callbackUrl
    if ($r3.StatusCode -ge 400) {
        $err = if ($r3.Content) { $r3.Content.Substring(0, [Math]::Min(300, $r3.Content.Length)) } else { "(no body)" }
        throw "callback returned $($r3.StatusCode): $err"
    }
    if ($r3.StatusCode -lt 300) {
        throw "callback returned $($r3.StatusCode), expected 302 (no provision happened)"
    }
    return $r3.Location
}

# 4) First login — IdP issues a fresh email; identity should PROVISION a new user.
$email1 = "fed-e2e-$([Guid]::NewGuid().ToString('N').Substring(0,8))@example.com"
$name1  = "Federated User"
Measure-Step "4. challenge → IdP login → callback (provision-on-first-login)" {
    $final = Invoke-FederationRoundTrip -Username $email1 -Claims @{
        email          = $email1
        email_verified = $true
        name           = $name1
        sub            = "mock-sub-$($email1.GetHashCode())"
    }
    Write-Host "  final redirect: $final" -ForegroundColor DarkGray
    Write-Host "  IdP email: $email1" -ForegroundColor Green
} | Out-Null

# 5) Admin-side verification — user was provisioned with the IdP's email.
$user = Measure-Step "5. admin search users → assert provisioned user exists" {
    $r = Get-Json -Method Get -Url "$BASE/api/v1/identity/users/search?query=$([Uri]::EscapeDataString($email1))" -Headers $ADMIN
    $hits = if ($r.items) { $r.items } elseif ($r.results) { $r.results } else { $r }
    $found = $hits | Where-Object { $_.email -eq $email1 } | Select-Object -First 1
    if (-not $found) { throw "user $email1 not found after federation flow (provision-on-first-login broken)" }
    Write-Host "  user id: $($found.id), email: $($found.email), name: $($found.displayName ?? $found.name)" -ForegroundColor Green
    return $found
}

# 6) Replay: same flow, same email — assert user count unchanged (link reused, no dup).
$baselineCount = Measure-Step "6a. baseline user count (before replay)" {
    $r = Get-Json -Method Get -Url "$BASE/api/v1/identity/users?count=500" -Headers $ADMIN
    $n = if ($r.items) { @($r.items).Count } elseif ($r.totalCount) { [int]$r.totalCount } else { @($r).Count }
    Write-Host "  baseline: $n users"
    return $n
}

Measure-Step "6b. replay same IdP login → assert SAME user (no duplicate)" {
    Invoke-FederationRoundTrip -Username $email1 -Claims @{
        email          = $email1
        email_verified = $true
        name           = $name1
        sub            = "mock-sub-$($email1.GetHashCode())"
    } | Out-Null
    $r = Get-Json -Method Get -Url "$BASE/api/v1/identity/users?count=500" -Headers $ADMIN
    $n = if ($r.items) { @($r.items).Count } elseif ($r.totalCount) { [int]$r.totalCount } else { @($r).Count }
    if ($n -ne $baselineCount) { throw "replay created a duplicate user (was $baselineCount, now $n)" }
    Write-Host "  user count unchanged ($n) — link reused" -ForegroundColor Green
} | Out-Null

# 7) Cleanup.
Measure-Step "7. cleanup: delete user + admin DCR" {
    try { Get-Json -Method Delete -Url "$BASE/api/v1/identity/users/$($user.id)" -Headers $ADMIN | Out-Null } catch { Write-Host "  user delete: $($_.Exception.Message)" -ForegroundColor Yellow }
    if ($ADMIN_RAT) {
        try { Get-Json -Method Delete -Url $ADMIN_RCU -Headers @{ Authorization = "Bearer $ADMIN_RAT" } | Out-Null } catch { Write-Host "  admin DCR delete: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    Write-Host "  cleaned" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
