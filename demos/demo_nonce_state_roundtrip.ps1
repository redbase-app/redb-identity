# Conformance probe — nonce / state round-trip (OIDC Core §3.1.2.1, §3.1.3.7, §15.5.2).
#   • state sent to /authorize MUST be echoed verbatim in the redirect.
#   • nonce sent to /authorize MUST appear verbatim as the `nonce` claim in the id_token.
#   • when NO nonce is sent (allowed for code flow), the id_token MUST NOT carry a nonce.
# Usage: pwsh -File demo_nonce_state_roundtrip.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
$REDIRECT = $REDIRECT_CB
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""; Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Action; $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" }); return $r
    } catch {
        $sw.Stop(); Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" }); throw
    }
}
function ConvertTo-Base64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
function New-Pkce {
    $vb = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($vb)
    $v = ConvertTo-Base64Url $vb
    $c = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($v)))
    [pscustomobject]@{ verifier=$v; challenge=$c }
}
function Decode-Jwt([string]$jwt) {
    $p = $jwt.Split('.')[1].Replace('-','+').Replace('_','/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}
# Drive /login then /connect/authorize, return the parsed redirect query (hashtable) + raw location.
function Invoke-Authorize {
    param($Session, $ClientId, $Pkce, [hashtable]$Extra)
    $body = @{
        response_type = "code"; client_id = $ClientId; redirect_uri = $REDIRECT
        scope = "openid profile offline_access"; code_challenge = $Pkce.challenge; code_challenge_method = "S256"
    }
    foreach ($k in $Extra.Keys) { $body[$k] = $Extra[$k] }
    $resp = $null
    try { $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body $body -MaximumRedirection 0 -ErrorAction Stop }
    catch { $resp = $_.Exception.Response }
    $location = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $location) { throw "no Location header on /connect/authorize" }
    $u = [uri]$location; $kv = @{}
    foreach ($pair in $u.Query.TrimStart('?').Split('&')) { $i = $pair.IndexOf('='); if ($i -gt 0) { $kv[$pair.Substring(0,$i)] = [uri]::UnescapeDataString($pair.Substring($i+1)) } }
    [pscustomobject]@{ location=$location; q=$kv }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

$reg = Measure-Step "1. DCR (authorization_code)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
        client_name="nonce-state-demo"; redirect_uris=@($REDIRECT)
        grant_types=@("authorization_code","refresh_token"); scope="openid profile offline_access"
    } | ConvertTo-Json)
}

$user = "ns_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "2. account/register + login" {
    try { Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" -Body (@{login=$user;email="$user@example.com";password="Test1234Pass!";displayName=$user} | ConvertTo-Json) | Out-Null } catch {}
    $script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    try { Invoke-WebRequest -Method Post "$BASE/login" -WebSession $script:session -ContentType "application/x-www-form-urlencoded" -Body @{ username=$user; password="Test1234Pass!" } -MaximumRedirection 0 -ErrorAction Stop | Out-Null } catch {}
    if ($script:session.Cookies.GetCookies("$BASE").Count -lt 1) { throw "no session cookie from /login" }
} | Out-Null

# ── Case A: state + nonce present → both must round-trip ───────────────────────
$stateA = "state-" + [Guid]::NewGuid().ToString('N')
$nonceA = "nonce-" + [Guid]::NewGuid().ToString('N')
Measure-Step "3. state echo (verbatim) in redirect" {
    $pk = New-Pkce; $script:pkA = $pk
    $r = Invoke-Authorize -Session $script:session -ClientId $reg.client_id -Pkce $pk -Extra @{ state=$stateA; nonce=$nonceA }
    if (-not $r.q.code) { throw "authorize did not return a code (loc=$($r.location))" }
    if ($r.q.state -ne $stateA) { throw "state NOT echoed verbatim: sent '$stateA', got '$($r.q.state)'" }
    $script:codeA = $r.q.code
    Write-Host "  ✓ state echoed verbatim; code present" -ForegroundColor Green
} | Out-Null

Measure-Step "4. nonce round-trips into id_token" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type="authorization_code"; client_id=$reg.client_id; client_secret=$reg.client_secret
        redirect_uri=$REDIRECT; code=$script:codeA; code_verifier=$script:pkA.verifier
    }
    if (-not $tok.id_token) { throw "no id_token returned" }
    $id = Decode-Jwt $tok.id_token
    if ($id.nonce -ne $nonceA) { throw "nonce NOT round-tripped: sent '$nonceA', id_token.nonce='$($id.nonce)'" }
    Write-Host "  ✓ id_token.nonce == sent nonce" -ForegroundColor Green
} | Out-Null

# ── Case B: no nonce → id_token MUST NOT carry a nonce ─────────────────────────
Measure-Step "5. no-nonce request → id_token has no nonce claim" {
    $pk = New-Pkce
    $stateB = "state-" + [Guid]::NewGuid().ToString('N')
    $r = Invoke-Authorize -Session $script:session -ClientId $reg.client_id -Pkce $pk -Extra @{ state=$stateB }
    if (-not $r.q.code) { throw "authorize (no nonce) did not return a code (loc=$($r.location))" }
    if ($r.q.state -ne $stateB) { throw "state NOT echoed on no-nonce request" }
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type="authorization_code"; client_id=$reg.client_id; client_secret=$reg.client_secret
        redirect_uri=$REDIRECT; code=$r.q.code; code_verifier=$pk.verifier
    }
    $id = Decode-Jwt $tok.id_token
    $hasNonce = $id.PSObject.Properties.Name -contains 'nonce' -and -not [string]::IsNullOrEmpty($id.nonce)
    if ($hasNonce) { throw "id_token carries a nonce ('$($id.nonce)') though none was requested" }
    Write-Host "  ✓ no nonce requested → no nonce claim" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""; Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
