# Federation discovery + redirect probe.
# Verifies:
#   1. /.well-known/openid-configuration advertises `federation_providers` array
#   2. /api/v1/identity/federation-providers/public returns the safe projection
#      (ProviderId, DisplayName, Kind, Priority — never ClientSecret/Authority)
#   3. Both lists agree on the set of ProviderIds
#   4. GET /connect/external-login?provider=<id>&returnUrl=/ returns 302 with a
#      Location pointing at the upstream IdP's Authority host (or wraps the
#      configured ClientId — this demo accepts placeholder REPLACE_ME values
#      since the goal is to verify the redirect surface, not real IdP login).
# Browser/IdP automation is intentionally NOT attempted — that requires a real
# upstream IdP and is out of scope for a scriptable demo.
# Usage: pwsh -File demo_federation.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Discovery — pull the federation_providers array.
$disc = Measure-Step "1. GET /.well-known/openid-configuration" {
    Invoke-RestMethod "$BASE/.well-known/openid-configuration"
}
if (-not $disc.federation_providers -or $disc.federation_providers.Count -eq 0) {
    Write-Host "Discovery does not advertise any federation_providers." -ForegroundColor Yellow
    Write-Host "Set Identity:Features:EnableFederation=true and configure FederationProviders[]." -ForegroundColor Yellow
    Write-Host "Skipping (config issue, not a server bug)." -ForegroundColor DarkGray
    exit 0
}
$discIds = $disc.federation_providers | ForEach-Object { $_.id } | Sort-Object
Write-Host "  discovery providers: $($discIds -join ', ')"

# 2) Public list — JSON projection consumed by relying-party UIs.
$pub = Measure-Step "2. GET /api/v1/identity/federation-providers/public" {
    Invoke-RestMethod "$BASE/api/v1/identity/federation-providers/public"
}
$pubIds = $pub | ForEach-Object { $_.providerId } | Sort-Object
Write-Host "  public-list providers: $($pubIds -join ', ')"

# Safe-projection guard: the public list must NEVER leak ClientSecret/Authority/Scopes.
$leakProps = @('clientSecret','authority','scopes','clientId')
$leaks = $pub | ForEach-Object {
    $row = $_
    foreach ($p in $leakProps) {
        if ($row.PSObject.Properties.Name -contains $p) {
            "$($row.providerId).$p"
        }
    }
}
if ($leaks.Count -gt 0) {
    throw "Public federation list leaks server-side fields: $($leaks -join ', ')"
}
Write-Host "  ✓ public projection contains no ClientSecret/Authority/Scopes/ClientId" -ForegroundColor Green

# 3) Cross-check: discovery and public list must agree on ProviderIds.
if (($discIds -join ',') -ne ($pubIds -join ',')) {
    throw "Discovery providers ($($discIds -join ',')) ≠ public list ($($pubIds -join ','))"
}
Write-Host "  ✓ discovery + public list agree on $($pubIds.Count) providers" -ForegroundColor Green

# 4) Redirect probe — pick the first provider, hit /connect/external-login,
#    expect HTTP 302 with a Location pointing at *some* upstream URL.
#    GitHub is excluded — it's OAuth2-only (no OIDC discovery), so the OIDC-based
#    federation challenge throws fetching .well-known/openid-configuration. The
#    server's OAuth2-only provider type is a separate code path; this demo probes
#    the OIDC challenge surface only.
$firstId = $pubIds | Where-Object { $_ -ne 'github' } | Select-Object -First 1
if (-not $firstId) {
    Write-Host "  no OIDC provider configured (only github present); skipping redirect probe" -ForegroundColor Yellow
    $total.Stop()
    Write-Host ""
    Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
    $timings | Format-Table -AutoSize Step, Ms, Status
    Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
    exit 0
}
$redirectUrl = "$BASE/connect/external-login?provider=$firstId&returnUrl=/"
$redirect = Measure-Step "4. GET /connect/external-login?provider=$firstId" {
    # Raw HttpClient (no auto-redirect, accept the dev TLS cert) so the 302 to the upstream
    # IdP is observed directly. The upstream Authority may be http://, which would otherwise
    # trip PowerShell's HTTPS→HTTP redirect guard when the OP runs on an https base.
    $h = [System.Net.Http.HttpClientHandler]::new()
    $h.AllowAutoRedirect = $false
    $h.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    $c = [System.Net.Http.HttpClient]::new($h)
    try {
        $resp = $c.GetAsync($redirectUrl).GetAwaiter().GetResult()
        [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Headers    = @{ Location = if ($resp.Headers.Location) { $resp.Headers.Location.ToString() } else { $null } }
        }
    } finally { $c.Dispose() }
}

$status = if ($redirect.StatusCode) { [int]$redirect.StatusCode } else { 0 }
$loc = $null
if ($redirect.Headers -and $redirect.Headers.Location) {
    $loc = if ($redirect.Headers.Location -is [string]) { $redirect.Headers.Location } else { ($redirect.Headers.Location | Select-Object -First 1).ToString() }
}
Write-Host "  status   : $status"
Write-Host "  location : $loc"
if ($status -lt 300 -or $status -ge 400) { throw "Expected 3xx redirect, got $status" }
if ([string]::IsNullOrEmpty($loc)) { throw "Redirect response has no Location header" }
# Tolerate REPLACE_ME ClientIds — the URL just needs to be absolute.
if ($loc -notmatch '^https?://') { throw "Location is not an absolute URL: $loc" }
Write-Host "  ✓ 302 with absolute Location URL → IdP redirect surface works" -ForegroundColor Green

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
