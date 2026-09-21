# WS-Trust facade — Issue, Validate, Cancel and Renew over the wire, against a running server.
#
# Usage: pwsh -File demo_soap_facade.ps1
#        pwsh -File demo_soap_facade.ps1 -Sts http://localhost:5021/sts -Http https://localhost:5002
#
# No tool to install: SOAP is ordinary HTTP with an XML body, so the envelopes below are written out in
# full and posted as they are. That is deliberate — everything a WS-Trust client sends is visible here,
# and the output stands on its own.
#
# The one thing worth watching is the fourth column of this demo: a client registered over HTTP getting a
# token over SOAP, and that same token being accepted back on HTTP. One issuer, one client registry, one
# token store — the facade is a transport, not a second identity server.

param(
    [string]$Sts  = $(if ($env:IDENTITY_STS)  { $env:IDENTITY_STS }  else { "http://localhost:5021/sts" }),
    [string]$Http = $(if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://localhost:5002" })
)

$ErrorActionPreference = 'Stop'
$DCR_IAT = if ($env:IDENTITY_DCR_TOKEN) { $env:IDENTITY_DCR_TOKEN } else { "dev-only-initial-access-token-not-for-production" }
$DCR_AUTH = @{ Authorization = "Bearer $DCR_IAT" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true

$trust  = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
$wsse   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

$total  = [System.Diagnostics.Stopwatch]::StartNew()
$step   = 0
$failed = 0

function Say([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color }

# Shortens the long opaque strings — tokens, secrets — so the shape of a message stays visible. Nothing
# that matters is hidden: a 3 KB JWT tells the reader nothing except how long it is.
function Compact([string]$text) {
    if (-not $text) { return $text }
    return [regex]::Replace($text, '([A-Za-z0-9\-_\.\+/=]{48,})', {
        param($m) $m.Groups[1].Value.Substring(0, 24) + '…(' + $m.Groups[1].Value.Length + ' chars)'
    })
}

function Step([string]$action, [string]$what) {
    $script:step++
    Write-Host ""
    Write-Host ("  {0}. {1}" -f $script:step, $action) -NoNewline -ForegroundColor White
    Write-Host ("   {0}" -f $what) -ForegroundColor DarkGray
}

function Expect([bool]$condition, [string]$message) {
    if (-not $condition) {
        Write-Host "     !! $message" -ForegroundColor Red
        $script:failed++
    }
}

# Wraps a request body in a SOAP 1.1 envelope with a WS-Security UsernameToken — which is how a WS-Trust
# caller presents its client credentials. Omitting the credentials is a supported call too: step 8 needs
# to see what an anonymous request gets.
function Envelope([string]$body, [string]$user, [string]$secret) {
    $security = ""
    if ($user) {
        $security = @"
  <soap:Header>
    <wsse:Security xmlns:wsse="$wsse">
      <wsse:UsernameToken>
        <wsse:Username>$user</wsse:Username>
        <wsse:Password>$secret</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
"@
    }

    return @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
$security
  <soap:Body>
$body
  </soap:Body>
</soap:Envelope>
"@
}

# Posts one WS-Trust request and shows both directions. Returns @{ Xml; Fault; Reason; Ms }.
function Sts {
    param(
        [string]$Action,           # Issue | Validate | Cancel | Renew
        [string]$Body,             # the wst:RequestSecurityToken element
        [string]$User   = $script:clientId,
        [string]$Secret = $script:clientSecret,
        [switch]$Anonymous
    )

    if ($Anonymous) { $User = ""; $Secret = "" }

    $envelope = Envelope $Body $User $Secret
    $soapAction = "$trust/RST/$Action"

    Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
    Say ("SOAPAction  " + $soapAction)
    Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
    Say (Compact (($Body.Trim()) -replace "`r?`n\s*", " "))
    if ($User) {
        Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
        Say ("UsernameToken  " + $User + " / " + ("*" * 8))
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # A SOAP 1.1 fault arrives with HTTP 500 and a body that is the whole point of the exchange, so the
    # error status is asked not to throw. Catching it instead does not work here: PowerShell disposes the
    # response content while building its own error record, and the only thing left, ErrorDetails.Message,
    # has had the markup stripped out of it — a perfectly good fault envelope reduced to bare text.
    $resp = Invoke-WebRequest -Method Post $Sts -ContentType "text/xml; charset=utf-8" `
        -Headers @{ SOAPAction = "`"$soapAction`"" } -Body $envelope -SkipHttpErrorCheck
    $xml = $resp.Content
    $sw.Stop()

    $doc = [xml]$xml
    $fault  = $doc.Envelope.Body.Fault
    $reason = if ($fault) { $fault.faultstring } else { "" }
    $code   = if ($fault) { $fault.faultcode }   else { "" }

    if ($fault) {
        Write-Host "     <- " -NoNewline -ForegroundColor Yellow
        Say ("soap:Fault  " + $code) 'Yellow'
        Write-Host "        " -NoNewline
        Say $reason 'Yellow'
    } else {
        Write-Host "     <- " -NoNewline -ForegroundColor Green
        Say (Compact ($doc.Envelope.Body.InnerXml))
    }

    Write-Host ("        {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor DarkGray

    return @{ Xml = $xml; Doc = $doc; Fault = $code; Reason = $reason; Ms = $sw.Elapsed.TotalMilliseconds }
}

# Digs the JWT out of the wsse:BinarySecurityToken the RSTR carries.
function Read-Token($call) {
    $node = $call.Doc.SelectSingleNode("//*[local-name()='BinarySecurityToken']")
    if (-not $node) { return "" }
    try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($node.InnerText.Trim())) }
    catch { return $node.InnerText.Trim() }
}

function Read-Status($call) {
    $node = $call.Doc.SelectSingleNode("//*[local-name()='Status']/*[local-name()='Code']")
    if (-not $node) { return "" }
    return $node.InnerText
}

$issueBody = @"
    <wst:RequestSecurityToken xmlns:wst="$trust"
                              xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
                              xmlns:wsa="http://www.w3.org/2005/08/addressing">
      <wst:RequestType>$trust/Issue</wst:RequestType>
      <wsp:AppliesTo>
        <wsa:EndpointReference><wsa:Address>{0}</wsa:Address></wsa:EndpointReference>
      </wsp:AppliesTo>
    </wst:RequestSecurityToken>
"@

$targetBody = @"
    <wst:RequestSecurityToken xmlns:wst="$trust" xmlns:wsse="$wsse">
      <wst:RequestType>$trust/{0}</wst:RequestType>
      <wst:{0}Target>
        <wsse:BinarySecurityToken>{1}</wsse:BinarySecurityToken>
      </wst:{0}Target>
    </wst:RequestSecurityToken>
"@

Write-Host ""
Write-Host "  redb.Identity - the WS-Trust facade, over the wire" -ForegroundColor Cyan
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("  STS    {0}" -f $Sts) -ForegroundColor DarkGray
Write-Host ("  HTTP   {0}   (used to register a demo client, and once at the end)" -f $Http) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ->  what the client sends       <-  what the server answers" -ForegroundColor DarkGray

# ── 1. The contract ───────────────────────────────────────────
# GET on the same address serves the WSDL, with soap:address rewritten to the URL it was fetched from.
# This is what a WCF or CXF developer starts from, so an STS that answers only POST is one they cannot
# use at all.
Step "GET ?wsdl" "the contract, the way a client generator fetches it"
$wsdlOk = $false
try {
    $wsdl = Invoke-WebRequest -Method Get ($Sts + "?wsdl")
    $wsdlOk = $wsdl.StatusCode -eq 200
    $addr = ([xml]$wsdl.Content).SelectSingleNode("//*[local-name()='address']").location
    Write-Host "     <- " -NoNewline -ForegroundColor Green
    Say ("SecurityTokenService, 4 operations; soap:address -> " + $addr)
} catch {
    Write-Host "     <- " -NoNewline -ForegroundColor Red
    Say $_.Exception.Message 'Red'
}
Expect $wsdlOk "the WSDL was not served - is the identity.soap module loaded?"

# ── 2. A client, registered over HTTP ─────────────────────────
# The claim of the whole facade in one step: this client is created through the HTTP transport and used
# through the SOAP one.
#
# Granular scopes on purpose: the master identity:manage is deliberately not obtainable through dynamic
# registration, and the granular branch is the interesting one anyway.
$scope = "identity:users:read"
Step "POST /connect/register" "HTTP, not SOAP - register a throwaway client"
Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
Say (@{ client_name = "soap-demo"; grant_types = @("client_credentials"); scope = $scope } | ConvertTo-Json -Compress)
$reg = Invoke-RestMethod -Method Post "$Http/connect/register" -Headers $DCR_AUTH -ContentType "application/json" -Body (@{
    client_name = "soap-demo"
    grant_types = @("client_credentials")
    scope       = $scope
} | ConvertTo-Json)
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("client_id  " + $reg.client_id)

$clientId     = $reg.client_id
$clientSecret = $reg.client_secret

# ── 3. Issue ──────────────────────────────────────────────────
# The RSTR carries our ordinary JWT as a wsse:BinarySecurityToken. No second token format enters the
# system, which is why introspection and revocation below work on it without knowing where it came from.
Step "RST/Issue" "a token for the client above, now over SOAP"
$issued = Sts -Action "Issue" -Body ($issueBody -f $scope)
$token = Read-Token $issued
Expect ([bool]$token) "no token in the RequestSecurityTokenResponse"
# Three segments is a signed JWT, five is an encrypted one (JWE). This server encrypts access tokens by
# default, so both are correct answers here and only «neither» would mean something went wrong.
Expect ($token.Split('.').Count -in 3, 5) "the issued token is neither a signed nor an encrypted JWT"
Expect ($issued.Xml -match 'Lifetime') "no Lifetime - a client that caches tokens cannot know when to stop"

# ── 4. Validate ───────────────────────────────────────────────
# WS-Trust answers "is this good" with a status code, not with our introspection document: the caller
# asked a yes-or-no question and gets a yes-or-no answer.
Step "RST/Validate" "is that token real to this server?"
$valid = Sts -Action "Validate" -Body ($targetBody -f "Validate", $token)
Expect ((Read-Status $valid) -like "*status/valid") "the token we just minted does not validate"

# ── 5. Cancel ─────────────────────────────────────────────────
# RFC 7009: a well-formed revocation always succeeds. WS-Trust says so with an empty element rather than
# a payload.
Step "RST/Cancel" "revoke it"
$cancelled = Sts -Action "Cancel" -Body ($targetBody -f "Cancel", $token)
Expect ($cancelled.Xml -match 'RequestedTokenCancelled') "the cancellation was not acknowledged"

# ── 6. ...and it is dead ──────────────────────────────────────
# A revocation nobody can observe is not a revocation. This is the half that proves it.
Step "RST/Validate" "the same token, after cancellation"
$after = Sts -Action "Validate" -Body ($targetBody -f "Validate", $token)
Expect (-not ((Read-Status $after) -like "*status/valid")) "a cancelled token still validates"

# ── 7. A refusal ──────────────────────────────────────────────
# An OAuth error must arrive as a soap:Fault, not as a successful response carrying an error document -
# a client told the call succeeded has no reason to look inside it, and generated WS-Trust clients branch
# on the fault code.
Step "RST/Issue" "same client, wrong secret"
$refused = Sts -Action "Issue" -Body ($issueBody -f $scope) -Secret "not-the-secret"
Expect ($refused.Fault -eq "wst:FailedAuthentication") "expected wst:FailedAuthentication, got '$($refused.Fault)'"
Expect ($refused.Xml -notmatch 'BinarySecurityToken') "a wrong secret produced a token"

# ── 8. No credentials at all ──────────────────────────────────
Step "RST/Issue" "no UsernameToken in the envelope"
$anon = Sts -Action "Issue" -Body ($issueBody -f $scope) -Anonymous
Expect ([bool]$anon.Fault) "an anonymous request was not refused"
Expect ($anon.Xml -notmatch 'BinarySecurityToken') "an anonymous request produced a token"

# ── 9. A malformed request ────────────────────────────────────
# The caller's mistake has to be told in the caller's vocabulary. Answered as soap:Server it would read
# as "we broke", and they would wait for us to fix what is theirs to fix.
Step "RST/Issue" "a body that is not a RequestSecurityToken"
$junk = Sts -Action "Issue" -Body "    <NotAnRst/>"
Expect ($junk.Fault -eq "wst:InvalidRequest") "expected wst:InvalidRequest, got '$($junk.Fault)'"

# ── 10. One token, two transports ─────────────────────────────
# The acceptance criterion of the facade: a token minted over SOAP is the same object HTTP accepts. Not a
# translated copy - the same issuer, the same signature, the same entry in the same token store.
Step "SOAP + HTTP" "a token issued over SOAP, spent over HTTP"
$fresh = Sts -Action "Issue" -Body ($issueBody -f $scope)
$freshToken = Read-Token $fresh

$httpOk = $true
try { Invoke-RestMethod -Method Get "$Http/api/v1/identity/users?offset=0&count=3" -Headers @{ Authorization = "Bearer $freshToken" } | Out-Null }
catch { $httpOk = $false }
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("HTTP GET /api/v1/identity/users  ->  " + $(if ($httpOk) { "admitted" } else { "REFUSED" }))
Expect $httpOk "a token issued over SOAP was refused over HTTP"

# ...and the other direction of the same claim: a read-only token is refused a write on HTTP too, so the
# facade did not become a second place where permissions are decided.
$httpRefused = $false
try {
    Invoke-RestMethod -Method Post "$Http/api/v1/identity/users" -Headers @{ Authorization = "Bearer $freshToken" } `
        -ContentType "application/json" -Body (@{ login = "soap-demo-should-not-exist" } | ConvertTo-Json) | Out-Null
} catch { $httpRefused = $true }
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("HTTP POST /api/v1/identity/users  ->  " + $(if ($httpRefused) { "REFUSED (as it must be)" } else { "ADMITTED" }))
Expect $httpRefused "a read-only token created a user"

$total.Stop()
Write-Host ""
if ($failed -gt 0) {
    Write-Host ("  WS-Trust facade demo: FAILED ({0} checks) in {1:N0} ms" -f $failed, $total.Elapsed.TotalMilliseconds) -ForegroundColor Red
    exit 1
}
Write-Host "  Every call above is one round trip: client -> facade -> direct-vm -> Core -> back." -ForegroundColor DarkGray
Write-Host "  Four operations, one address: WS-Trust names the operation with the Action, not the URL." -ForegroundColor DarkGray
Write-Host ("  WS-Trust facade demo: all steps passed in {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Green
exit 0
