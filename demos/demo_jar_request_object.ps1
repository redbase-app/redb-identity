# JAR — JWT-Secured Authorization Request (RFC 9101, Z7).
#   The client sends the authorization parameters as a SIGNED JWT in `request`,
#   instead of as plain query parameters. The server verifies the signature
#   against the client's registered key before it trusts anything inside.
#
#   This is an RFC-compliance probe. It asserts the server:
#     * advertises JAR in discovery (request_parameter_supported, alg values);
#     * accepts a validly signed request object (redirects to login, not error);
#     * takes parameters from INSIDE the JWT over the outside (§6.1);
#     * rejects an UNSIGNED object (alg:none) — the whole point of JAR;
#     * rejects an object signed by the WRONG key.
#
#   The client registers an inline JWKS (its public key) via DCR; the demo signs
#   with the matching private key. No browser needed — a signed request object is
#   accepted headlessly, and the 302 to /login IS the success signal.
# Usage: pwsh -File demo_jar_request_object.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }

$fail = 0
function Assert([string]$What, [bool]$Cond, [string]$Detail = "") {
    if ($Cond) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { Write-Host "  FAIL  $What  $Detail" -ForegroundColor Red; $script:fail++ }
}
function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function B64UStr([string]$s) { B64U ([Text.Encoding]::UTF8.GetBytes($s)) }

# Drives /connect/authorize headless (no redirect following) and returns the
# OAuth error, or $null when the request was accepted.
#
# The error surfaces two ways, both of which we must read:
#   * as error=... on a 302 Location, when the redirect_uri is trusted;
#   * as a direct 4xx JSON body {"error":...}, when it is NOT — which is exactly
#     what a bad request object triggers (OIDC 3.1.2.6: never redirect an error
#     to an unverified redirect_uri). A signed-but-rejected object has no trusted
#     redirect_uri, so the server answers straight to the caller.
function Invoke-Authorize([hashtable]$Form) {
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
            -ContentType 'application/x-www-form-urlencoded' -Body $Form `
            -MaximumRedirection 0 -ErrorAction Stop
        $loc = $resp.Headers.Location
    } catch {
        $r = $_.Exception.Response
        $loc = $r.Headers.Location
        if (-not $loc) {
            # Direct (non-redirect) response — read the OAuth error from the JSON body.
            try {
                $body = $_.ErrorDetails.Message
                if (-not $body -and $r) {
                    $stream = $r.GetResponseStream()
                    $body = [IO.StreamReader]::new($stream).ReadToEnd()
                }
                $json = $body | ConvertFrom-Json
                if ($json.error) { return [string]$json.error }
            } catch { }
        }
        $loc = [string]$loc
    }
    if ($loc -match 'error=([^&]+)') { return [Uri]::UnescapeDataString($Matches[1]) }
    return $null   # redirected to login/consent, no error → accepted
}

# ── 0. discovery advertises JAR ────────────────────────────────────────────────
Write-Host "`n=== [0] discovery ===" -ForegroundColor Cyan
$disco = Invoke-RestMethod "$BASE/.well-known/openid-configuration"
# RFC 9101 §4: the request object's `aud` MUST be the OP's issuer identifier — which is not
# necessarily the base URL we dial (a conformance profile issues host.docker.internal). Take it
# from discovery so aud matches whatever the server actually calls itself.
$ISSUER = $disco.issuer.TrimEnd('/')
Assert "request_parameter_supported = true" ($disco.request_parameter_supported -eq $true)
Assert "request_object_signing_alg_values_supported advertises RS256" `
    ($disco.request_object_signing_alg_values_supported -contains 'RS256')

# ── 1. RSA keypair + inline JWKS ───────────────────────────────────────────────
Write-Host "`n=== [1] RSA key + DCR with inline JWKS ===" -ForegroundColor Cyan
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$p   = $rsa.ExportParameters($false)   # public only
$kid = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$jwk = [ordered]@{ kty='RSA'; use='sig'; alg='RS256'; kid=$kid; n=(B64U $p.Modulus); e=(B64U $p.Exponent) }
$jwks = @{ keys = @($jwk) }

$reg = Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType 'application/json' -Body (@{
    client_name                = "jar-demo"
    redirect_uris              = @($REDIRECT)
    grant_types                = @('authorization_code')
    response_types             = @('code')
    scope                      = "openid profile email"
    token_endpoint_auth_method = "private_key_jwt"
    jwks                       = $jwks
} | ConvertTo-Json -Depth 8)
$cid = $reg.client_id
Assert "client registered with inline JWKS" (-not [string]::IsNullOrEmpty($cid))

# Signs a request object (RS256) for this client with the matching private key.
function New-RequestObject([hashtable]$Claims, [string]$Alg = 'RS256', [System.Security.Cryptography.RSA]$Key = $rsa) {
    $now = [DateTimeOffset]::UtcNow
    $payload = @{
        iss=$cid; aud=$ISSUER; client_id=$cid
        iat=$now.ToUnixTimeSeconds(); exp=$now.AddMinutes(5).ToUnixTimeSeconds()
    }
    foreach ($k in $Claims.Keys) { $payload[$k] = $Claims[$k] }
    $header = @{ alg=$Alg; typ='JWT'; kid=$kid }
    $h = B64UStr ($header  | ConvertTo-Json -Compress)
    $b = B64UStr ($payload | ConvertTo-Json -Compress)
    $signingInput = [Text.Encoding]::ASCII.GetBytes("$h.$b")
    $sig = $Key.SignData($signingInput,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    "$h.$b." + (B64U $sig)
}

# ── 2. a validly signed request object is accepted ─────────────────────────────
Write-Host "`n=== [2] signed request object → accepted ===" -ForegroundColor Cyan
$ro = New-RequestObject @{ response_type='code'; scope='openid profile'; redirect_uri=$REDIRECT; state='s1' }
$err = Invoke-Authorize @{ client_id=$cid; request=$ro }
Assert "authorize accepted the signed request object (no OAuth error)" ($null -eq $err) "error: $err"

# ── 3. parameters inside the JWT win over the outside (§6.1) ────────────────────
Write-Host "`n=== [3] inner parameters override outer (6.1) ===" -ForegroundColor Cyan
# Outer scope is garbage; the signed scope is valid. If the server honoured the
# outer value the request would fail on the unknown scope — acceptance proves the
# inner (signed) parameters are the ones used.
$ro3 = New-RequestObject @{ response_type='code'; scope='openid'; redirect_uri=$REDIRECT; state='s3' }
$err = Invoke-Authorize @{ client_id=$cid; request=$ro3; scope='this-scope-does-not-exist' }
Assert "signed parameters are authoritative, outer ignored" ($null -eq $err) "error: $err"

# ── 3b. request_uri (by reference) — the server fetches the signed object ───────
Write-Host "`n=== [3b] request_uri (by reference) → fetched + accepted ===" -ForegroundColor Cyan
# Host the signed request object on a throwaway HTTP listener; hand the server its URL.
# The server fetches it (SSRF-guarded; dev profile allows loopback) and validates it.
$roUri = New-RequestObject @{ response_type='code'; scope='openid profile'; redirect_uri=$REDIRECT; state='s3b' }
$listener = [System.Net.HttpListener]::new()
$port = 39217
$listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Start()
$serveJob = Start-ThreadJob -ScriptBlock {
    param($l, $jwt)
    $ctx = $l.GetContext()
    $bytes = [Text.Encoding]::ASCII.GetBytes($jwt)
    $ctx.Response.ContentType = 'application/oauth-authz-req+jwt'
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
} -ArgumentList $listener, $roUri
try {
    $err = Invoke-Authorize @{ client_id=$cid; request_uri="http://127.0.0.1:$port/ro" }
    Assert "authorize fetched and accepted the request_uri object" ($null -eq $err) "error: $err"
} finally {
    $serveJob | Wait-Job -Timeout 5 | Out-Null
    $serveJob | Remove-Job -Force -EA SilentlyContinue
    $listener.Stop(); $listener.Close()
}
# NB: the SSRF guard (refusing a request_uri that resolves to an internal address) is NOT probed
# here — this dev profile sets RequestUriAllowPrivateNetworkTargets=true so the loopback listener
# above is reachable, which by definition disables the guard. It is covered by the unit test
# ValidateRequestObjectHandlerTests.Request_uri_to_internal_target_is_refused (default options).

# ── 4. unsigned request object (alg:none) is rejected ──────────────────────────
Write-Host "`n=== [4] alg:none → rejected ===" -ForegroundColor Cyan
$h = B64UStr (@{ alg='none'; typ='JWT' } | ConvertTo-Json -Compress)
$b = B64UStr (@{ iss=$cid; client_id=$cid; response_type='code'; scope='openid'; redirect_uri=$REDIRECT } | ConvertTo-Json -Compress)
$noneRo = "$h.$b."
$err = Invoke-Authorize @{ client_id=$cid; request=$noneRo }
Assert "unsigned request object rejected with invalid_request_object" ($err -eq 'invalid_request_object') "got: $err"

# ── 5. wrong-key signature is rejected ─────────────────────────────────────────
Write-Host "`n=== [5] wrong key → rejected ===" -ForegroundColor Cyan
$attacker = [System.Security.Cryptography.RSA]::Create(2048)
$ro5 = New-RequestObject -Key $attacker @{ response_type='code'; scope='openid'; redirect_uri=$REDIRECT; state='s5' }
$err = Invoke-Authorize @{ client_id=$cid; request=$ro5 }
Assert "request object signed by the wrong key rejected" ($err -eq 'invalid_request_object') "got: $err"

Write-Host ""
if ($fail -eq 0) { Write-Host "OK - JAR (RFC 9101): all assertions passed" -ForegroundColor Green; exit 0 }
else { Write-Host "FAILED - $fail JAR assertion(s) failed" -ForegroundColor Red; exit 1 }
