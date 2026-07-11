# GitHub OAuth2-only federation end-to-end against a self-hosted mock.
#
# Closes the last ❌ in the federation matrix section. The standard mock-oauth2-server
# in our docker compose is OIDC-only — it issues id_tokens and exposes a discovery
# document. GitHub OAuth2 has neither: no discovery, no id_token, no /userinfo (the
# profile + emails come from the REST API at /user and /user/emails). Our
# GitHubFederatedAuthProvider implements that flow against github.com endpoints; this
# demo points it at a local pwsh-hosted HttpListener that emulates each one.
#
# Flow:
#   1. Spin up the mock GitHub on http://127.0.0.1:9201 inside this script (background
#      pwsh job). It serves:
#         GET  /login/oauth/authorize  — 302 redirect to redirect_uri with code+state
#         POST /login/oauth/access_token — form body, returns {access_token, token_type, scope}
#         GET  /user                   — Bearer auth, returns {id, login, name, email}
#         GET  /user/emails            — Bearer auth, returns [{email, primary, verified, visibility}]
#   2. /.well-known/openid-configuration → assert mock-github-e2e in federation_providers
#   3. GET /connect/external-login?provider=mock-github-e2e&returnUrl=/ → 302 to mock
#   4. Follow the mock's auto-issued code → identity callback
#   5. identity provisions the user from the GitHub-shaped claims
#   6. Admin search confirms the new user with github-supplied email + display name
#   7. Cleanup
#
# Skips with exit=0 when the mock IdP port is already taken or the demo can't bind.
# Skips when redb.Identity doesn't advertise the mock-github-e2e provider yet (e.g.
# operator removed it for production).
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$PROV = "mock-github-e2e"
$MOCK_PORT = 9201
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

# curl-based helpers (pwsh IRM hangs against some identity admin endpoints — same issue
# as in demo_federation_e2e). Single-hop, no auto-redirect.
function Hop {
    param([string]$Method, [string]$Url, $Body = $null, [hashtable]$Headers = $null, [string]$ContentType = $null)
    $curlArgs = @('-s', '-k', '-i', '-m', '15', '-X', $Method.ToUpperInvariant())
    if ($Headers) { foreach ($k in $Headers.Keys) { $curlArgs += @('-H', "$($k): $($Headers[$k])") } }
    $tempBodyFile = $null
    if ($null -ne $Body) {
        if ($Body -is [hashtable]) {
            $ct = if ($ContentType) { $ContentType } else { 'application/x-www-form-urlencoded' }
            $curlArgs += @('-H', "Content-Type: $ct")
            $parts = $Body.GetEnumerator() | ForEach-Object {
                "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString([string]$_.Value))"
            }
            $payload = $parts -join '&'
        } else {
            $ct = if ($ContentType) { $ContentType } else { 'application/json' }
            $curlArgs += @('-H', "Content-Type: $ct")
            $payload = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 6 -Compress }
        }
        $tempBodyFile = New-TemporaryFile
        [System.IO.File]::WriteAllText($tempBodyFile, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @('--data-binary', "@$tempBodyFile")
    }
    $curlArgs += $Url
    try { $raw = & curl.exe @curlArgs } finally { if ($tempBodyFile) { Remove-Item $tempBodyFile -ErrorAction SilentlyContinue } }
    $text = ($raw -join "`n")
    $sepIdx = $text.IndexOf("`n`n")
    $headerSection = if ($sepIdx -gt 0) { $text.Substring(0, $sepIdx) } else { $text }
    $bodySection = if ($sepIdx -gt 0) { $text.Substring($sepIdx + 2) } else { "" }
    $statusCode = 0
    $firstLine = ($headerSection -split "`n")[0]
    if ($firstLine -match 'HTTP/\S+\s+(\d+)') { $statusCode = [int]$matches[1] }
    $location = $null
    foreach ($h in ($headerSection -split "`n")) {
        if ($h -match '^[Ll]ocation:\s*(.+?)\s*$') { $location = $matches[1]; break }
    }
    return [pscustomobject]@{ StatusCode = $statusCode; Location = $location; Content = $bodySection }
}

function Get-Json {
    param([string]$Method, [string]$Url, $Body = $null, [hashtable]$Headers = $null, [string]$ContentType = "application/json")
    $curlArgs = @('-s', '-k', '-m', '15', '-w', '||%{http_code}||', '-X', $Method.ToUpperInvariant())
    if ($Headers) { foreach ($k in $Headers.Keys) { $curlArgs += @('-H', "$($k): $($Headers[$k])") } }
    $tempBodyFile = $null
    if ($null -ne $Body) {
        $curlArgs += @('-H', "Content-Type: $ContentType")
        $payload = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 6 -Compress }
        $tempBodyFile = New-TemporaryFile
        [System.IO.File]::WriteAllText($tempBodyFile, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @('--data-binary', "@$tempBodyFile")
    }
    $curlArgs += $Url
    try { $raw = & curl.exe @curlArgs } finally { if ($tempBodyFile) { Remove-Item $tempBodyFile -ErrorAction SilentlyContinue } }
    if ($null -eq $raw) { throw "curl returned no output for $Method $Url" }
    $text = ($raw -join "`n")
    $m = [regex]::Match($text, '\|\|(\d{3})\|\|\s*$')
    if (-not $m.Success) { throw "curl marker missing in: $text" }
    $bodyOut = $text.Substring(0, $m.Index)
    $status = [int]$m.Groups[1].Value
    if ($status -ge 400) { throw "HTTP $status $Method $Url : $bodyOut" }
    if (-not $bodyOut -or $bodyOut.Length -eq 0) { return $null }
    return $bodyOut | ConvertFrom-Json -Depth 8
}

# --- mock GitHub HttpListener job -------------------------------------------------
# We script the mock as a single scriptblock that runs in a background pwsh job. The
# parent process tells the mock what user shape to issue via env vars before triggering
# /authorize, and the job listens until $stop signal (env GH_MOCK_STOP).

# Both `id` (external_id used by federation to match the federated_identity row) and
# `email` are randomised per run so re-runs in run_all don't pick up the existing link
# from a previous run and short-circuit to "log in as existing user" — which would
# leave search-by-new-email empty.
$rnd = [Guid]::NewGuid().ToString('N').Substring(0,6)
$mockUser = @{
    id    = [int](Get-Random -Minimum 1000000 -Maximum 99999999)
    login = "octofake-$rnd"
    name  = "Octofake Fakerton"
    email = "octofake-$rnd@example.com"
}

$mockJob = Start-Job -Name "demo-mock-github" -ArgumentList $MOCK_PORT, $mockUser -ScriptBlock {
    param([int]$Port, [hashtable]$User)
    Add-Type -AssemblyName System.Net.HttpListener

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    try { $listener.Start() } catch { Write-Output "MOCK_BIND_FAILED: $($_.Exception.Message)"; return }

    # In-memory store of authorization codes -> user shape (one-shot exchange).
    $codes = [System.Collections.Concurrent.ConcurrentDictionary[string,hashtable]]::new()
    $accessTokens = [System.Collections.Concurrent.ConcurrentDictionary[string,hashtable]]::new()

    Write-Output "MOCK_READY"

    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
        } catch { break }
        try {
            $req = $ctx.Request
            $res = $ctx.Response
            $path = $req.Url.AbsolutePath
            $method = $req.HttpMethod.ToUpperInvariant()

            switch -Regex ("$method $path") {
                # GET /__shutdown — sentinel used by the demo's finally{} block to break the
                # blocking GetContext() loop cleanly so Stop-Job doesn't wait the default
                # 2-minute timeout before force-killing.
                '^GET /__shutdown$' {
                    $res.StatusCode = 200
                    $res.OutputStream.Close()
                    $listener.Stop()
                    break
                }

                # GET /login/oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...
                '^GET /login/oauth/authorize$' {
                    $q = [System.Web.HttpUtility]::ParseQueryString($req.Url.Query)
                    $redirect = $q["redirect_uri"]
                    $state = $q["state"]
                    if (-not $redirect) { $res.StatusCode = 400; $res.OutputStream.Close(); break }
                    $code = [Guid]::NewGuid().ToString("N")
                    $null = $codes.TryAdd($code, $User)
                    $sep = if ($redirect -match '\?') { '&' } else { '?' }
                    $loc = "$redirect$($sep)code=$([Uri]::EscapeDataString($code))&state=$([Uri]::EscapeDataString($state))"
                    $res.StatusCode = 302
                    $res.Headers["Location"] = $loc
                    $res.OutputStream.Close()
                    break
                }

                # POST /login/oauth/access_token  (form-encoded: code, client_id, client_secret, redirect_uri, code_verifier?)
                '^POST /login/oauth/access_token$' {
                    $sr = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $body = $sr.ReadToEnd()
                    $form = [System.Web.HttpUtility]::ParseQueryString($body)
                    $code = $form["code"]
                    $found = $null
                    if ($code -and $codes.TryRemove($code, [ref]$found)) {
                        $tok = "gha_" + [Guid]::NewGuid().ToString("N")
                        $null = $accessTokens.TryAdd($tok, $found)
                        $json = "{`"access_token`":`"$tok`",`"token_type`":`"bearer`",`"scope`":`"read:user user:email`"}"
                        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                        $res.StatusCode = 200
                        $res.ContentType = "application/json"
                        $res.OutputStream.Write($bytes, 0, $bytes.Length)
                    } else {
                        $bytes = [Text.Encoding]::UTF8.GetBytes('{"error":"bad_verification_code"}')
                        # GitHub returns 200 + error JSON (NOT 400). We mirror that to exercise the
                        # provider's explicit IsSuccessStatusCode + token == null check.
                        $res.StatusCode = 200
                        $res.ContentType = "application/json"
                        $res.OutputStream.Write($bytes, 0, $bytes.Length)
                    }
                    $res.OutputStream.Close()
                    break
                }

                # GET /user  (Bearer auth → profile shape)
                '^GET /user$' {
                    $auth = $req.Headers["Authorization"]
                    $tok = if ($auth -match '^Bearer\s+(.+)$') { $matches[1] } else { $null }
                    $u = $null
                    if ($tok -and $accessTokens.TryGetValue($tok, [ref]$u)) {
                        $json = ([pscustomobject]@{
                            id = $u.id; login = $u.login; name = $u.name; email = $u.email
                        } | ConvertTo-Json -Compress)
                        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                        $res.StatusCode = 200
                        $res.ContentType = "application/vnd.github+json"
                        $res.OutputStream.Write($bytes, 0, $bytes.Length)
                    } else { $res.StatusCode = 401 }
                    $res.OutputStream.Close()
                    break
                }

                # GET /user/emails  (Bearer auth → email array; only used when profile.email is private)
                '^GET /user/emails$' {
                    $auth = $req.Headers["Authorization"]
                    $tok = if ($auth -match '^Bearer\s+(.+)$') { $matches[1] } else { $null }
                    $u = $null
                    if ($tok -and $accessTokens.TryGetValue($tok, [ref]$u)) {
                        $json = (@(@{
                            email = $u.email; primary = $true; verified = $true; visibility = "public"
                        }) | ConvertTo-Json -Compress)
                        # GitHub returns an array — ensure root is `[...]` not `{...}`.
                        if ($json -notmatch '^\[') { $json = "[$json]" }
                        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                        $res.StatusCode = 200
                        $res.ContentType = "application/vnd.github+json"
                        $res.OutputStream.Write($bytes, 0, $bytes.Length)
                    } else { $res.StatusCode = 401 }
                    $res.OutputStream.Close()
                    break
                }

                default {
                    $res.StatusCode = 404
                    $res.OutputStream.Close()
                }
            }
        } catch {
            try { $ctx.Response.StatusCode = 500; $ctx.Response.OutputStream.Close() } catch {}
        }
    }
}

# Wait for MOCK_READY (or MOCK_BIND_FAILED).
$ready = $false
$boundFailed = $false
for ($i = 0; $i -lt 30 -and -not $ready -and -not $boundFailed; $i++) {
    Start-Sleep -Milliseconds 200
    $out = Receive-Job $mockJob -Keep | Out-String
    if ($out -match 'MOCK_BIND_FAILED') { $boundFailed = $true }
    if ($out -match 'MOCK_READY') { $ready = $true }
}

if ($boundFailed -or -not $ready) {
    Write-Host "Mock GitHub failed to bind on port $MOCK_PORT — likely port already in use. Skipping." -ForegroundColor Yellow
    Stop-Job $mockJob -ErrorAction SilentlyContinue
    Remove-Job $mockJob -ErrorAction SilentlyContinue
    exit 0
}

Write-Host "mock GitHub running on http://127.0.0.1:$MOCK_PORT" -ForegroundColor DarkGray

try {
    $total = [System.Diagnostics.Stopwatch]::StartNew()

    # 0) Discovery must advertise mock-github-e2e — operator may have removed it for prod.
    $advertised = Measure-Step "0. discovery advertises $PROV" {
        $d = Get-Json -Method Get -Url "$BASE/.well-known/openid-configuration"
        $ids = $d.federation_providers | ForEach-Object { $_.id }
        if ($ids -notcontains $PROV) {
            Write-Host "  $PROV not in federation_providers — skipping (operator removed it). ids: [$($ids -join ',')]" -ForegroundColor Yellow
            return $false
        }
        Write-Host "  $PROV advertised" -ForegroundColor Green
        return $true
    }
    if (-not $advertised) { exit 0 }

    # The OP-issued federation callback targets the OP's ISSUER host; our cookies are bound to
    # whatever host we drive. If they differ (e.g. the conformance context.json pins the issuer to
    # host.docker.internal while we started on 127.0.0.1), re-target to the issuer so the FULL
    # end-to-end flow — real requests and all — actually runs. Only skip if it isn't reachable.
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
            exit 0
        }
    }

    # 1) DCR admin client for verification.
    $adminReg = Measure-Step "1. DCR admin client (users.manage)" {
        Get-Json -Method Post -Url "$BASE/connect/register" -Body @{
            client_name = "fed-github-e2e"
            grant_types = @("client_credentials")
            scope       = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
        }
    }
    $A_RAT = $adminReg.registration_access_token
    $A_RCU = $adminReg.registration_client_uri

    $adminTok = Measure-Step "2. admin cc token" {
        $form = "grant_type=client_credentials&client_id=$([Uri]::EscapeDataString($adminReg.client_id))" +
                "&client_secret=$([Uri]::EscapeDataString($adminReg.client_secret))" +
                "&scope=$([Uri]::EscapeDataString('identity:users:write identity:groups:write identity:consents:write identity:mfa:write'))"
        Get-Json -Method Post -Url "$BASE/connect/token" -Body $form -ContentType "application/x-www-form-urlencoded"
    }
    $ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)" }

    # 2) Initiate the GitHub-style challenge.
    $r1 = Measure-Step "3. GET /connect/external-login?provider=$PROV → 302 to mock /authorize" {
        $r = Hop -Method Get -Url "$BASE/connect/external-login?provider=$PROV&returnUrl=/"
        if ($r.StatusCode -lt 300 -or $r.StatusCode -ge 400) { throw "challenge status $($r.StatusCode)" }
        if (-not $r.Location.StartsWith("http://127.0.0.1:$MOCK_PORT")) {
            throw "challenge redirect to '$($r.Location)' is not our mock"
        }
        Write-Host "  302 → $($r.Location.Substring(0,[Math]::Min(140,$r.Location.Length)))..." -ForegroundColor Green
        return $r
    }

    # 3) Follow the mock's /authorize — it returns 302 to our callback with code+state.
    $r2 = Measure-Step "4. mock /authorize → 302 callback with code+state" {
        $r = Hop -Method Get -Url $r1.Location
        if ($r.StatusCode -ne 302) { throw "mock authorize returned $($r.StatusCode)" }
        if (-not $r.Location.StartsWith("$BASE/connect/federation/callback")) {
            throw "mock didn't redirect to our callback, got: $($r.Location)"
        }
        return $r
    }

    # 4) Hit the callback → identity exchanges code, fetches /user + /user/emails, provisions.
    $r3 = Measure-Step "5. GET /connect/federation/callback → identity provisions user" {
        $r = Hop -Method Get -Url $r2.Location
        if ($r.StatusCode -ge 400) {
            $err = if ($r.Content) { $r.Content.Substring(0, [Math]::Min(300, $r.Content.Length)) } else { "(no body)" }
            throw "callback status $($r.StatusCode): $err"
        }
        Write-Host "  callback status=$($r.StatusCode), location=$($r.Location)" -ForegroundColor Green
        return $r
    }

    # 5) Admin-side: verify user was provisioned with the mock-supplied email.
    Measure-Step "6. admin search users by email → provisioned user found" {
        $r = Get-Json -Method Get -Url "$BASE/api/v1/identity/users/search?query=$([Uri]::EscapeDataString($mockUser.email))" -Headers $ADMIN
        $hits = if ($r.items) { $r.items } else { $r }
        $found = @($hits | Where-Object { $_.email -eq $mockUser.email })
        if ($found.Count -eq 0) {
            throw "user with email $($mockUser.email) not found in admin search (GitHub flow didn't provision)"
        }
        Write-Host "  user id=$($found[0].id), email=$($found[0].email), name=$($found[0].displayName ?? $found[0].name)" -ForegroundColor Green
    } | Out-Null

    Measure-Step "7. cleanup: DELETE admin DCR" {
        if ($A_RAT) {
            try { Get-Json -Method Delete -Url $A_RCU -Headers @{ Authorization = "Bearer $A_RAT" } | Out-Null } catch {}
        }
    } | Out-Null

    $total.Stop()
    Write-Host ""
    Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
    $timings | Format-Table -AutoSize Step, Ms, Status
    Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
}
finally {
    # Always tear down the mock so subsequent runs (and run_all) can re-bind the port.
    # The listener loop is parked in a blocking HttpListener.GetContext() call. Stop-Job
    # sends a runspace-close signal that DOES NOT interrupt that native syscall —
    # PowerShell waits 2 min for the loop to notice and then force-terminates, which is
    # what made the demo report ~120 s wall-clock when the actual asserts finished in
    # ~1.5 s. Unblock GetContext() first by hitting any URL on the mock — the loop
    # exits its current iteration, IsListening flips to false on Stop-Job, and the
    # next-iteration check exits cleanly.
    try {
        # Best-effort wake-up. 1 s timeout so a dead/already-stopped mock doesn't add
        # any extra delay. We don't care about the response.
        Invoke-WebRequest -Uri "http://127.0.0.1:$MOCK_PORT/__shutdown" `
            -Method Get -TimeoutSec 1 -UseBasicParsing -SkipHttpErrorCheck -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    Stop-Job $mockJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $mockJob -Force -ErrorAction SilentlyContinue | Out-Null
}
