# RFC 8252 §7.3 — loopback redirect URI, port not compared.
#
# A native / CLI app (az login, gh auth login, any desktop OAuth client) cannot know its callback
# port before it starts: it asks the OS for an ephemeral one, so the port is different on every run
# and cannot be registered ahead of time. §7.3 requires the authorization server to compare
# everything about a loopback redirect EXCEPT the port.
#
# That is a deliberate hole in redirect_uri matching, so most of this probe is NEGATIVE. The
# widening must be exactly one port wide and not one inch more:
#
#   §7.3   registered http://127.0.0.1:P/cb  →  http://127.0.0.1:<any>/cb   ACCEPTED
#   §7.3   the same for the IPv6 literal [::1]
#   §8.3   "localhost" is a NAME, not the loopback literal — it resolves, and a poisoned resolver
#          points it elsewhere. It must NOT be wildcarded.
#          path / query / scheme changes must NOT be wildcarded
#          a client with no registered loopback URI must NOT gain one
#   6749   §4.1.2.1 — and every rejection must be reported by the OP itself, NEVER redirected to
#          the URI it just refused to trust. A rejected redirect that still redirects is the whole
#          attack.
#
# Usage: pwsh -File demo_loopback_redirect.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true

$script:Failures = 0
function Assert([string]$What, [bool]$Ok, [string]$Detail = "") {
    if ($Ok) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { $script:Failures++; Write-Host "  FAIL  $What  $Detail" -ForegroundColor Red }
}
function ConvertTo-Base64Url([byte[]]$b) {
    [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function New-Pkce {
    $vb = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($vb)
    $v = ConvertTo-Base64Url $vb
    $c = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::ASCII.GetBytes($v)))
    [pscustomobject]@{ Verifier = $v; Challenge = $c }
}
function New-Client([string[]]$RedirectUris) {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
        client_name                = "loopback-demo"
        redirect_uris              = $RedirectUris
        grant_types                = @("authorization_code")
        response_types             = @("code")
        token_endpoint_auth_method = "none"   # public client — the native-app shape (RFC 8252 §8.4)
    } | ConvertTo-Json)
}

# A logged-in browser session; every probe below reuses it, so a rejection can only come from
# redirect_uri validation and not from a missing session.
#
# Driven through HttpClient rather than Invoke-WebRequest: a successful loopback authorize answers
# 302 with an http:// Location (that is the point of RFC 8252 — the native app listens on plain http
# on the loopback interface), and Invoke-WebRequest refuses to hand back an https→http redirect at
# all. That is a limitation of the PowerShell client, not of the server, and it would silently turn
# the PASS case into an exception.
$user = "lb_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" -Body (@{
    login = $user; email = "$user@example.com"; password = "Test1234Pass!"; displayName = $user
} | ConvertTo-Json) | Out-Null

Add-Type -AssemblyName System.Net.Http
$cookies = New-Object System.Net.CookieContainer
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false          # the 302 IS the result we inspect
$handler.CookieContainer = $cookies
$handler.ServerCertificateCustomValidationCallback = `
    [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
$http = New-Object System.Net.Http.HttpClient($handler)

function Send-Form([string]$Url, [hashtable]$Form) {
    $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
    foreach ($k in $Form.Keys) {
        $pairs.Add([System.Collections.Generic.KeyValuePair[string, string]]::new($k, [string]$Form[$k]))
    }
    # ::new(), not New-Object — New-Object unrolls the list into varargs and silently fails to
    # construct the content, which would send every request with an empty body and make every probe
    # below "pass" for the wrong reason.
    $content = [System.Net.Http.FormUrlEncodedContent]::new($pairs)
    $http.PostAsync($Url, $content).GetAwaiter().GetResult()
}

$login = Send-Form "$BASE/login" @{ username = $user; password = "Test1234Pass!" }
if ([int]$login.StatusCode -notin 200, 302) { throw "login failed: $([int]$login.StatusCode)" }

# Returns { code, error, location, status } — `location` matters as much as `error`: a refused
# redirect_uri must never appear in a Location header.
function Invoke-Authorize([string]$ClientId, [string]$RedirectUri, $Pkce) {
    $resp = Send-Form "$BASE/connect/authorize" @{
        response_type         = "code"
        client_id             = $ClientId
        redirect_uri          = $RedirectUri
        scope                 = "openid"
        state                 = "st-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
        nonce                 = [Guid]::NewGuid().ToString('N')
        code_challenge        = $Pkce.Challenge
        code_challenge_method = "S256"
    }
    $loc = if ($resp.Headers.Location) { $resp.Headers.Location.ToString() } else { $null }

    $kv = @{}
    if ($loc -and $loc.Contains('?')) {
        foreach ($pair in $loc.Substring($loc.IndexOf('?') + 1).Split('&')) {
            $i = $pair.IndexOf('=')
            if ($i -gt 0) { $kv[$pair.Substring(0, $i)] = [uri]::UnescapeDataString($pair.Substring($i + 1)) }
        }
    }
    [pscustomobject]@{
        code = $kv.code; error = $kv.error; location = $loc; status = [int]$resp.StatusCode
    }
}

# ── 1. THE POSITIVE: a registered loopback URI, called back on a different port ────────────────
Write-Host "`n=== [1] registered http://127.0.0.1:8080/cb -> called back on :54321 ===" -ForegroundColor Cyan
$c = New-Client @("http://127.0.0.1:8080/cb")
$pkce = New-Pkce
$a = Invoke-Authorize $c.client_id "http://127.0.0.1:54321/cb" $pkce
Assert "a code is issued on a port that was never registered (RFC 8252 §7.3)" ($null -ne $a.code) `
    "error=$($a.error) status=$($a.status)"

# And the code must actually redeem — validation happens again at the token endpoint, against the
# very same URI. A rule applied at authorize but not at /token would just move the failure.
if ($a.code) {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type = "authorization_code"; client_id = $c.client_id
        redirect_uri = "http://127.0.0.1:54321/cb"; code = $a.code; code_verifier = $pkce.Verifier
    }
    Assert "the code redeems at /connect/token with that same ephemeral-port URI" ($null -ne $t.access_token)
}

# ── 2. the IPv6 loopback literal, same rule ───────────────────────────────────────────────────
Write-Host "`n=== [2] IPv6 loopback [::1] ===" -ForegroundColor Cyan
$c6 = New-Client @("http://[::1]:8080/cb")
$a = Invoke-Authorize $c6.client_id "http://[::1]:9999/cb" (New-Pkce)
Assert "[::1] gets the same port wildcard as 127.0.0.1" ($null -ne $a.code) "error=$($a.error)"

# ══ NEGATIVES ══ everything below MUST be refused ═════════════════════════════════════════════

# ── 3. §8.3 "localhost" is a name, not the loopback literal ────────────────────────────────────
# It goes through resolution. A hosts-file entry or a poisoned resolver points it at a machine that
# is not the loopback interface — and port-wildcarding it would hand that machine every callback.
Write-Host "`n=== [3] localhost must NOT be port-wildcarded (§8.3) ===" -ForegroundColor Cyan
$cl = New-Client @("http://localhost:8080/cb")
$a = Invoke-Authorize $cl.client_id "http://localhost:9999/cb" (New-Pkce)
Assert "localhost on another port is REJECTED — it is a name, not 127.0.0.1" ($null -eq $a.code) `
    "code was issued: $($a.code)"
Assert "...and the refused URI is NOT in a Location header (RFC 6749 §4.1.2.1)" `
    ($a.location -notlike '*localhost:9999*') "location=$($a.location)"

# ── 4. the port, and ONLY the port ────────────────────────────────────────────────────────────
Write-Host "`n=== [4] path / query / scheme are still compared exactly ===" -ForegroundColor Cyan
$a = Invoke-Authorize $c.client_id "http://127.0.0.1:54321/evil" (New-Pkce)
Assert "a different PATH is rejected" ($null -eq $a.code) "code=$($a.code)"

$a = Invoke-Authorize $c.client_id "http://127.0.0.1:54321/cb?next=https://evil.example" (New-Pkce)
Assert "an added QUERY is rejected" ($null -eq $a.code) "code=$($a.code)"

$a = Invoke-Authorize $c.client_id "https://127.0.0.1:54321/cb" (New-Pkce)
Assert "a different SCHEME is rejected" ($null -eq $a.code) "code=$($a.code)"

$a = Invoke-Authorize $c.client_id "http://user:pass@127.0.0.1:54321/cb" (New-Pkce)
Assert "userinfo in the URI is rejected" ($null -eq $a.code) "code=$($a.code)"

# ── 5. a client with no loopback registration gains nothing ────────────────────────────────────
# This is the containment property: the widening is not "loopback is allowed", it is "a client that
# ALREADY registered a loopback URI may vary its port".
Write-Host "`n=== [5] a web client cannot be talked into a loopback callback ===" -ForegroundColor Cyan
$cw = New-Client @("https://app.example.com/cb")
$a = Invoke-Authorize $cw.client_id "http://127.0.0.1:54321/cb" (New-Pkce)
Assert "a client registered only at https://app.example.com/cb is REJECTED for 127.0.0.1" `
    ($null -eq $a.code) "code=$($a.code)"
Assert "...and no Location points at 127.0.0.1 either" `
    ($a.location -notlike '*127.0.0.1:54321*') "location=$($a.location)"

# ── 6. a loopback client cannot reach out to the internet ──────────────────────────────────────
Write-Host "`n=== [6] a loopback client cannot redirect off-box ===" -ForegroundColor Cyan
$a = Invoke-Authorize $c.client_id "https://evil.example.com/cb" (New-Pkce)
Assert "an external URI is rejected for a loopback-registered client" ($null -eq $a.code) "code=$($a.code)"
Assert "...and the error is shown by the OP, not redirected to evil.example.com" `
    ($a.location -notlike '*evil.example.com*') "location=$($a.location)"

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "OK - RFC 8252 7.3 loopback: accepted where the spec says, refused everywhere else" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL($script:Failures) - see above" -ForegroundColor Red
exit 1
