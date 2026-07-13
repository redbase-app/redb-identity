# OIDC Core 1.0 §5.5 — the `claims` request parameter.
#
# Scopes are coarse: an RP that needs `name` alone would otherwise have to request the whole
# `profile` scope and receive twelve claims it never asked for. §5.5 lets the RP name exactly the
# claims it needs and say WHERE it wants them — from UserInfo, or embedded in the id_token.
#
# This probe asserts the spec, not our implementation's convenience:
#   §5.5    claims_parameter_supported must be advertised in discovery
#   §5.5    `userinfo` member  → the claim is served from /connect/userinfo
#   §5.5    `id_token` member  → the claim is embedded in the id_token
#   §5.5.1  `value` constraint → a value we cannot match means the claim is OMITTED, not faked
#   §5.5.1  `sub` pinned to another user → the request MUST fail
#   §5.1    JSON types survive: email_verified is a boolean, updated_at a number
#   RFC6749 a malformed `claims` value is a client error → invalid_request
#
# A failure here is a server bug to fix, not a status code to widen.
#
# Usage: pwsh -File demo_claims_parameter.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }

$script:Failures = 0
function Assert([string]$What, [bool]$Ok, [string]$Detail = "") {
    if ($Ok) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { $script:Failures++; Write-Host "  FAIL  $What  $Detail" -ForegroundColor Red }
}
function Decode-Jwt([string]$jwt) {
    $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

# ── 0. Discovery must advertise the capability ────────────────────────────────────────────────
Write-Host "`n=== [0] discovery ===" -ForegroundColor Cyan
$disc = Invoke-RestMethod "$BASE/.well-known/openid-configuration"
Assert "claims_parameter_supported = true (OIDC Discovery §3)" ($disc.claims_parameter_supported -eq $true) `
    "got: $($disc.claims_parameter_supported)"

# ── 1. A client and a user with real profile data ─────────────────────────────────────────────
Write-Host "`n=== [1] DCR + user ===" -ForegroundColor Cyan
$reg = Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
    client_name   = "claims-param-demo"
    redirect_uris = @($REDIRECT)
    grant_types   = @("authorization_code")
    response_types = @("code")
    scope         = "openid profile email"
} | ConvertTo-Json)

$user = "clm_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pass = "Test1234Pass!"
Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" -Body (@{
    login = $user; email = "$user@example.com"; password = $pass; displayName = $user
} | ConvertTo-Json) | Out-Null
Write-Host "  client=$($reg.client_id)  user=$user"

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
try {
    Invoke-WebRequest -Method Post "$BASE/login" -WebSession $session `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ username = $user; password = $pass } -MaximumRedirection 0 -ErrorAction Stop | Out-Null
} catch { if ($_.Exception.Response.StatusCode.value__ -notin 200, 302) { throw } }

# Drives /connect/authorize and returns the code, the OAuth error, and the raw Location — the
# last one matters because a login_required can legitimately land on the local /login page rather
# than on the client's redirect_uri (OIDC §5.5.1 / §3.1.2.6).
function Invoke-Authorize([string]$Scope, [string]$ClaimsJson, [string]$Prompt) {
    $body = @{
        response_type = "code"; client_id = $reg.client_id; redirect_uri = $REDIRECT
        scope = $Scope; state = "s-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
        nonce = [Guid]::NewGuid().ToString('N')
    }
    if ($ClaimsJson) { $body.claims = $ClaimsJson }
    if ($Prompt) { $body.prompt = $Prompt }

    # We follow no redirects — the 302 IS the result we are inspecting. PowerShell still reports
    # "maximum redirection exceeded" as a non-terminating error in that case; the response object
    # is returned regardless, so silence the notice rather than the response.
    $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" -WebSession $session `
        -ContentType "application/x-www-form-urlencoded" -Body $body `
        -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    if (-not $resp) { throw "no response from /connect/authorize" }

    $location = $resp.Headers["Location"]
    if ($location -is [array]) { $location = $location[0] }

    $kv = @{}
    if ($location -and $location.Contains('?')) {
        foreach ($pair in $location.Substring($location.IndexOf('?') + 1).Split('&')) {
            $i = $pair.IndexOf('=')
            if ($i -gt 0) { $kv[$pair.Substring(0, $i)] = [uri]::UnescapeDataString($pair.Substring($i + 1)) }
        }
    }
    [pscustomobject]@{
        code = $kv.code; error = $kv.error
        status = [int]$resp.StatusCode; location = $location
    }
}

function Get-Tokens([string]$Code) {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type = "authorization_code"; client_id = $reg.client_id
        client_secret = $reg.client_secret; redirect_uri = $REDIRECT; code = $Code
    }
}
function Get-UserInfo([string]$AccessToken) {
    Invoke-RestMethod "$BASE/connect/userinfo" -Headers @{ Authorization = "Bearer $AccessToken" }
}

# ── 2. BASELINE: scope=openid alone must NOT leak profile data ────────────────────────────────
# Establishes that whatever we see in step 3 was granted by the `claims` parameter and nothing else.
Write-Host "`n=== [2] baseline: scope=openid, no claims parameter ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" $null
if (-not $a.code) { Write-Host "  cannot continue: authorize returned no code ($($a.error))" -ForegroundColor Red; exit 1 }
$ui = Get-UserInfo (Get-Tokens $a.code).access_token
Assert "userinfo returns sub" ($null -ne $ui.sub)
Assert "userinfo does NOT return name (no profile scope, no claims parameter)" ($null -eq $ui.name) `
    "leaked: $($ui.name)"

# ── 3. §5.5 userinfo member — `name` as an essential claim, WITHOUT the profile scope ──────────
# This is exactly what the OIDF suite's oidcc-claims-essential test asks for.
Write-Host "`n=== [3] claims={userinfo:{name:{essential:true}}}, scope=openid ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" '{"userinfo":{"name":{"essential":true}}}'
Assert "authorize accepted the claims parameter" ($null -ne $a.code) "error: $($a.error)"
if ($a.code) {
    $t = Get-Tokens $a.code
    $ui = Get-UserInfo $t.access_token
    Assert "userinfo NOW returns name (OIDCC-5.5 / OIDCC-5.5.1)" ($ui.name -eq $user) "got: $($ui.name)"

    $idt = Decode-Jwt $t.id_token
    Assert "name did NOT leak into the id_token (it was requested for userinfo only)" ($null -eq $idt.name) `
        "id_token.name = $($idt.name)"
}

# ── 4. §5.5 id_token member — delivery channel is the RP's choice ──────────────────────────────
Write-Host "`n=== [4] claims={id_token:{email:null}}, scope=openid ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" '{"id_token":{"email":null}}'
Assert "authorize accepted a voluntary (null) claim request" ($null -ne $a.code) "error: $($a.error)"
if ($a.code) {
    $idt = Decode-Jwt (Get-Tokens $a.code).id_token
    Assert "id_token NOW carries email" ($idt.email -eq "$user@example.com") "got: $($idt.email)"
}

# ── 5. §5.1 JSON types must not depend on how the claim was requested ──────────────────────────
Write-Host "`n=== [5] JSON types: email_verified boolean, updated_at number ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" '{"userinfo":{"email_verified":null,"updated_at":null}}'
if ($a.code) {
    $raw = Invoke-WebRequest "$BASE/connect/userinfo" `
        -Headers @{ Authorization = "Bearer $((Get-Tokens $a.code).access_token)" }
    $json = $raw.Content
    Assert "email_verified is a JSON boolean, not a string (§5.1)" `
        ($json -match '"email_verified"\s*:\s*(true|false)') "body: $json"
    Assert "updated_at is a JSON number, not a string (§5.1)" `
        ($json -match '"updated_at"\s*:\s*[0-9]+') "body: $json"
}

# ── 6. §5.5.1 `value` we cannot match → the claim is OMITTED, never faked ──────────────────────
Write-Host "`n=== [6] claims={userinfo:{name:{value:'somebody-else'}}} ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" '{"userinfo":{"name":{"value":"somebody-else"}}}'
if ($a.code) {
    $ui = Get-UserInfo (Get-Tokens $a.code).access_token
    Assert "name omitted — we will not answer a value request with a different value (§5.5.1)" `
        ($null -eq $ui.name) "got: $($ui.name)"
}

# ── 7. §5.5.1 `sub` pinned to another End-User ─────────────────────────────────────────────────
# The MUST: "The Authorization Server MUST NOT reply with an ID Token or Access Token for a
# different user, even if they have an active session." The spec also permits the End-User to be
# "Authenticated as a result of the request" — so sending them to /login to sign in as the
# requested sub is the correct, useful answer, and NOT a failure.
$otherSub = '00000000-0000-0000-0000-000000000000'
Write-Host "`n=== [7] claims={id_token:{sub:{value:'$otherSub'}}} ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" "{`"id_token`":{`"sub`":{`"value`":`"$otherSub`"}}}"
Assert "no code issued for a different user (§5.5.1 MUST)" ($null -eq $a.code) "code=$($a.code)"
Assert "End-User is sent to /login to authenticate as the requested sub" `
    ($a.location -like '*/login*') "location=$($a.location)"

# ── 7b. …but under prompt=none the error MUST go back to the RP, never a login form (§3.1.2.6) ──
Write-Host "`n=== [7b] the same, with prompt=none ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" "{`"id_token`":{`"sub`":{`"value`":`"$otherSub`"}}}" "none"
Assert "no code issued" ($null -eq $a.code) "code=$($a.code)"
Assert "login_required returned to the client's redirect_uri, no interactive UI (§3.1.2.6)" `
    ($a.error -eq 'login_required' -and $a.location -like "$REDIRECT*") `
    "error=$($a.error) location=$($a.location)"

# ── 8. RFC 6749 — a malformed `claims` value is a client error, not something to swallow ───────
Write-Host "`n=== [8] claims=<not JSON> ===" -ForegroundColor Cyan
$a = Invoke-Authorize "openid" 'this-is-not-json'
Assert "rejected with invalid_request" ($a.error -eq 'invalid_request') "error=$($a.error) code=$($a.code)"

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "OK — OIDC Core §5.5 claims parameter: all assertions passed" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL($script:Failures) — see above" -ForegroundColor Red
exit 1
