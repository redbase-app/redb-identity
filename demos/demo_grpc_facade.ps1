# gRPC facade — the protocol surface and the management surface, over the wire, against a running server.
#
# Usage: pwsh -File demo_grpc_facade.ps1
#        pwsh -File demo_grpc_facade.ps1 -Grpc localhost:5011 -Http https://localhost:5002
#
# Calls are made with grpcurl — the standard tool, one binary, no build step. Everything it sends and
# receives is printed as JSON, so the output stands on its own: no C# to read, no container to start.
#
#   winget install fullstorydev.grpcurl
#
# We do not serve gRPC reflection, so grpcurl is pointed at the published .proto files in the repository —
# which is what a consumer would do anyway.

param(
    [string]$Grpc = $(if ($env:IDENTITY_GRPC) { $env:IDENTITY_GRPC } else { "localhost:5011" }),
    [string]$Http = $(if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://localhost:5002" })
)

$ErrorActionPreference = 'Stop'
$DCR_IAT = if ($env:IDENTITY_DCR_TOKEN) { $env:IDENTITY_DCR_TOKEN } else { "dev-only-initial-access-token-not-for-production" }
$DCR_AUTH = @{ Authorization = "Bearer $DCR_IAT" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true

$here      = Split-Path -Parent $MyInvocation.MyCommand.Path
$contracts = Join-Path (Split-Path -Parent $here) "src\redb.Identity.Contracts\Protos"
$demoProto = Join-Path $here "grpc"

$total  = [System.Diagnostics.Stopwatch]::StartNew()
$step   = 0
$failed = 0

function Say([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color }

# Shortens the long opaque strings — access tokens, secrets — so the shape of a reply stays visible.
# Nothing is hidden that matters: a 3 KB JWE tells the reader nothing except how long it is.
function Compact([string]$text) {
    if (-not $text) { return $text }
    return [regex]::Replace($text, '"([A-Za-z0-9\-_\.\+/=]{48,})"', {
        param($m) '"' + $m.Groups[1].Value.Substring(0, 24) + '…" (' + $m.Groups[1].Value.Length + ' chars)'
    })
}

function Step([string]$address, [string]$what) {
    $script:step++
    Write-Host ""
    Write-Host ("  {0}. {1}" -f $script:step, $address) -NoNewline -ForegroundColor White
    Write-Host ("   {0}" -f $what) -ForegroundColor DarkGray
}

# Runs grpcurl and shows both directions. Returns @{ Ok; Json; Err; Ms }.
function Grpc {
    param(
        [string]$Address,          # package.Service/Method
        [string]$Proto,            # .proto file name
        [string]$ProtoPath,        # -import-path
        $Body = @{},
        [string[]]$Headers = @()
    )

    $json = $Body | ConvertTo-Json -Compress -Depth 10

    Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
    Say (Compact $json)
    foreach ($h in $Headers) {
        Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
        Say ("metadata  " + ($h -replace '(Bearer\s+\S{16})\S+', '$1...'))
    }

    $cmd = @('-plaintext', '-import-path', $ProtoPath, '-proto', $Proto)
    foreach ($h in $Headers) { $cmd += @('-H', $h) }
    $cmd += @('-d', $json, $Grpc, $Address)

    $sw  = [System.Diagnostics.Stopwatch]::StartNew()
    $out = & grpcurl @cmd 2>&1
    $sw.Stop()
    $ok  = $LASTEXITCODE -eq 0

    $stdout = ($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    $stderr = ($out | Where-Object { $_ -is  [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() }) -join "`n"

    if ($ok) {
        Write-Host "     <- " -NoNewline -ForegroundColor Green
        Say (Compact ($stdout -replace "`n", "`n        "))
    } else {
        Write-Host "     <- " -NoNewline -ForegroundColor Yellow
        Say ((($stderr, $stdout | Where-Object { $_ }) -join "`n") -replace "`n", "`n        ") 'Yellow'
    }

    Write-Host ("        {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor DarkGray

    return @{ Ok = $ok; Json = $stdout; Err = $stderr; Ms = $sw.Elapsed.TotalMilliseconds }
}

function Read-AccessToken($call) {
    if (-not $call.Ok) { return "" }
    $j = $call.Json | ConvertFrom-Json
    if ($j.PSObject.Properties.Name -contains "accessToken") { return $j.accessToken }
    if ($j.PSObject.Properties.Name -contains "access_token") { return $j.access_token }
    return ""
}

function Expect([bool]$condition, [string]$message) {
    if (-not $condition) {
        Write-Host "     !! $message" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host ""
Write-Host "  redb.Identity - the gRPC facade, over the wire" -ForegroundColor Cyan
Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("  gRPC   {0}" -f $Grpc) -ForegroundColor DarkGray
Write-Host ("  HTTP   {0}   (used once, to register a demo client)" -f $Http) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ->  what the client sends       <-  what the server answers" -ForegroundColor DarkGray

if (-not (Get-Command grpcurl -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "  grpcurl is not on PATH. Install it:  winget install fullstorydev.grpcurl" -ForegroundColor Red
    exit 1
}

# ── 1. Is anything serving? ───────────────────────────────────
# The standard health address, what Kubernetes and Envoy probe. Its schema is gRPC's own, not ours, so it
# sits in demos/grpc/health.proto rather than in the published contract.
Step "grpc.health.v1.Health/Check" "is the listener serving?"
$health = Grpc -Address "grpc.health.v1.Health/Check" -Proto "health.proto" -ProtoPath $demoProto
Expect ($health.Ok -and $health.Json -match 'SERVING') "health check did not report SERVING"

# ── 2. Discovery ──────────────────────────────────────────────
# Passed through from Core untouched. Look at the endpoints it advertises: they are HTTP addresses,
# because those are the real ones. The facade does not rewrite them into gRPC addresses that do not exist.
Step "identity.v1.Identity/Discovery" "the OIDC document, straight from Core"
$discovery = Grpc -Address "identity.v1.Identity/Discovery" -Proto "identity.v1.proto" -ProtoPath $contracts
Expect ($discovery.Ok -and $discovery.Json -match '"issuer"') "discovery returned no issuer"

# ── 3. A client, registered over HTTP ─────────────────────────
# The claim of the whole facade in one step: this client is created through the HTTP transport and used
# through the gRPC one. One issuer, one client registry, one token store.
#
# Granular scopes on purpose: the master identity:manage is deliberately not obtainable through dynamic
# registration, and the granular branch is the interesting one anyway - it is the scope table that both
# transports share.
$scope = "identity:users:read identity:users:write"
Step "POST /connect/register" "HTTP, not gRPC - register a throwaway client"
Write-Host "     -> " -NoNewline -ForegroundColor DarkGray
Say (@{ client_name = "grpc-demo"; grant_types = @("client_credentials"); scope = $scope } | ConvertTo-Json -Compress)
$reg = Invoke-RestMethod -Method Post "$Http/connect/register" -Headers $DCR_AUTH -ContentType "application/json" -Body (@{
    client_name = "grpc-demo"
    grant_types = @("client_credentials")
    scope       = $scope
} | ConvertTo-Json)
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("client_id  " + $reg.client_id)

# ── 4. A token, over gRPC ─────────────────────────────────────
Step "identity.v1.Identity/Token" "the client above, now over gRPC"
$tokenCall = Grpc -Address "identity.v1.Identity/Token" -Proto "identity.v1.proto" -ProtoPath $contracts -Body @{
    grant_type    = "client_credentials"
    client_id     = $reg.client_id
    client_secret = $reg.client_secret
    scope         = $scope
}
Expect $tokenCall.Ok "token call failed"
# grpcurl prints protobuf JSON, where declared fields carry their JSON names (accessToken), while Struct
# keys keep whatever the server put there — which is why Discovery above shows snake_case. Read either.
$token = Read-AccessToken $tokenCall
Expect ([bool]$token) "no access_token in the reply"

# ── 5. Introspection ──────────────────────────────────────────
Step "identity.v1.Identity/Introspect" "is that token real to this server?"
$intro = Grpc -Address "identity.v1.Identity/Introspect" -Proto "identity.v1.proto" -ProtoPath $contracts -Body @{
    token         = $token
    client_id     = $reg.client_id
    client_secret = $reg.client_secret
}
Expect ($intro.Ok -and $intro.Json -match '"active":\s*true') "the token we just minted introspects as inactive"

# ── 6. A refusal ──────────────────────────────────────────────
# An OAuth error must arrive as a gRPC *status*, not as a successful call carrying an error document - no
# generated client inspects the body of an OK reply. The machine-readable code travels in a trailer,
# because the protocol discards the payload of a non-OK reply.
Step "identity.v1.Identity/Token" "same client, wrong secret"
$refused = Grpc -Address "identity.v1.Identity/Token" -Proto "identity.v1.proto" -ProtoPath $contracts -Body @{
    grant_type    = "client_credentials"
    client_id     = $reg.client_id
    client_secret = "not-the-secret"
}
Expect (-not $refused.Ok) "a wrong secret produced a token"
Expect ($refused.Err -match 'Unauthenticated') "expected Unauthenticated"

# ── 7. The management gate, from outside ──────────────────────
Step "identity.management.v1.Users/List" "an admin operation with no credentials at all"
$noAuth = Grpc -Address "identity.management.v1.Users/List" -Proto "identity.management.v1.proto" -ProtoPath $contracts -Body @{
    arguments = @{ offset = 0; count = 1 }
}
Expect (-not $noAuth.Ok) "an admin operation ran without credentials"
Expect ($noAuth.Err -match 'Unauthenticated') "expected Unauthenticated"

# ── 8. ...and with the token ──────────────────────────────────
# A gate that only ever refuses is not a gate, it is an outage. This is the other half.
Step "identity.management.v1.Users/List" "the same call, carrying the token"
$admitted = Grpc -Address "identity.management.v1.Users/List" -Proto "identity.management.v1.proto" -ProtoPath $contracts `
    -Body @{ arguments = @{ offset = 0; count = 3 } } -Headers @("authorization: Bearer $token")
Expect $admitted.Ok "the admin token was refused"

# ── 9. One token, two transports, one verdict ─────────────────
# The acceptance criterion of the facade, in both directions: the write-scoped client is admitted on both,
# and a read-only client is refused the write on both.
Step "HTTP + gRPC" "the same token, the same operation, on both transports"
$httpOk = $true
try { Invoke-RestMethod -Method Get "$Http/api/v1/identity/users?offset=0&count=3" -Headers @{ Authorization = "Bearer $token" } | Out-Null }
catch { $httpOk = $false }
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("HTTP GET /api/v1/identity/users  ->  " + $(if ($httpOk) { "admitted" } else { "REFUSED" }))
Expect $httpOk "the same token was admitted over gRPC and refused over HTTP"

$narrow = Invoke-RestMethod -Method Post "$Http/connect/register" -Headers $DCR_AUTH -ContentType "application/json" -Body (@{
    client_name = "grpc-demo-narrow"
    grant_types = @("client_credentials")
    scope       = "identity:users:read"
} | ConvertTo-Json)

$narrowTokenCall = Grpc -Address "identity.v1.Identity/Token" -Proto "identity.v1.proto" -ProtoPath $contracts -Body @{
    grant_type    = "client_credentials"
    client_id     = $narrow.client_id
    client_secret = $narrow.client_secret
    scope         = "identity:users:read"
}
$narrowToken = Read-AccessToken $narrowTokenCall

Step "identity.management.v1.Users/Create" "a read-only token attempting a write"
$narrowGrpc = Grpc -Address "identity.management.v1.Users/Create" -Proto "identity.management.v1.proto" -ProtoPath $contracts `
    -Body @{ arguments = @{ login = "grpc-demo-should-not-exist" } } -Headers @("authorization: Bearer $narrowToken")
Expect (-not $narrowGrpc.Ok) "a read-only token created a user over gRPC"

$httpRefused = $false
try {
    Invoke-RestMethod -Method Post "$Http/api/v1/identity/users" -Headers @{ Authorization = "Bearer $narrowToken" } `
        -ContentType "application/json" -Body (@{ login = "grpc-demo-should-not-exist" } | ConvertTo-Json) | Out-Null
} catch { $httpRefused = $true }
Write-Host "     <- " -NoNewline -ForegroundColor Green
Say ("HTTP POST /api/v1/identity/users  ->  " + $(if ($httpRefused) { "REFUSED (as it must be)" } else { "ADMITTED" }))
Expect $httpRefused "a read-only token created a user over HTTP"

$total.Stop()
Write-Host ""
if ($failed -gt 0) {
    Write-Host ("  gRPC facade demo: FAILED ({0} checks) in {1:N0} ms" -f $failed, $total.Elapsed.TotalMilliseconds) -ForegroundColor Red
    exit 1
}
Write-Host "  Every call above is one round trip: client -> facade -> direct-vm -> Core -> back." -ForegroundColor DarkGray
Write-Host ("  gRPC facade demo: all steps passed in {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Green
exit 0
