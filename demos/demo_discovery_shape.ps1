# Discovery shape regression — locks /.well-known/openid-configuration JSON shape.
# Probes:
#   1. fetch discovery
#   2. assert no array property has duplicates (catches the historical
#      dpop_signing_alg_values_supported double-emit bug)
#   3. assert required fields per RFC 8414 §2 / OIDC Discovery §3 are present
#   4. assert no advertised secret/internal leak (issuer must NOT contain "REPLACE_ME",
#      no `*_internal` keys, etc.)
# Usage: pwsh -File demo_discovery_shape.ps1

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

# 1) Fetch discovery as a raw object so we can probe arrays generically.
$disc = Measure-Step "1. GET /.well-known/openid-configuration" {
    Invoke-RestMethod "$BASE/.well-known/openid-configuration"
}

# 2) Required fields per RFC 8414 §2 / OIDC Discovery §3.
$required = @(
    'issuer',
    'authorization_endpoint',
    'token_endpoint',
    'jwks_uri',
    'response_types_supported',
    'subject_types_supported',
    'id_token_signing_alg_values_supported'
)
$missing = @()
foreach ($f in $required) {
    if (-not $disc.PSObject.Properties.Name.Contains($f)) { $missing += $f }
}
if ($missing.Count -gt 0) {
    throw "Discovery missing required fields: $($missing -join ', ')"
}
Write-Host "  ✓ all $($required.Count) required RFC 8414 / OIDC Discovery fields present" -ForegroundColor Green

# 3) Dedupe sweep — every advertised array property must have unique values.
$arrayProps = $disc.PSObject.Properties | Where-Object { $_.Value -is [System.Collections.IEnumerable] -and $_.Value -isnot [string] }
$dupReports = @()
foreach ($prop in $arrayProps) {
    $vals = @($prop.Value | ForEach-Object {
        if ($_ -is [string] -or $_ -is [int] -or $_ -is [long]) { $_ }
        elseif ($_ -is [pscustomobject] -and $_.PSObject.Properties.Name.Contains('id')) { "obj:$($_.id)" }
        else { $null }
    } | Where-Object { $_ -ne $null })
    if ($vals.Count -eq 0) { continue }
    $unique = $vals | Select-Object -Unique
    if ($vals.Count -ne $unique.Count) {
        $dups = $vals | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { "$($_.Name)×$($_.Count)" }
        $dupReports += "$($prop.Name) has duplicates: [$($dups -join ', ')]"
    }
}
Measure-Step "2. dedupe sweep across array fields" {
    if ($dupReports.Count -gt 0) {
        throw "Duplicate values detected:`n  " + ($dupReports -join "`n  ")
    }
    Write-Host "  ✓ no duplicates across all advertised array fields" -ForegroundColor Green
} | Out-Null

# 4) DPoP-specific lock: must be present, must dedupe, must be a subset of the canonical RFC 9449 alg set.
Measure-Step "3. dpop_signing_alg_values_supported shape" {
    if (-not $disc.dpop_signing_alg_values_supported) {
        throw "dpop_signing_alg_values_supported missing (DPoP advertised as supported but no alg list)"
    }
    $algs = @($disc.dpop_signing_alg_values_supported)
    $uniqueAlgs = $algs | Select-Object -Unique
    if ($algs.Count -ne $uniqueAlgs.Count) {
        throw "dpop_signing_alg_values_supported has duplicates: [$($algs -join ', ')]"
    }
    $rfcAllowed = @('RS256','RS384','RS512','PS256','PS384','PS512','ES256','ES384','ES512','EdDSA')
    $bad = $algs | Where-Object { $rfcAllowed -notcontains $_ }
    if ($bad.Count -gt 0) {
        throw "dpop_signing_alg_values_supported has non-RFC-9449 algs: $($bad -join ', ')"
    }
    Write-Host "  ✓ dpop algs deduped, all from RFC 9449 §5 catalog: [$($algs -join ', ')]" -ForegroundColor Green
} | Out-Null

# 5) Leak guard: issuer/endpoints must not contain placeholder strings, no *_internal keys.
Measure-Step "4. leak / placeholder guard" {
    if ($disc.issuer -match 'REPLACE_ME|TODO|XXX') {
        throw "issuer contains placeholder: $($disc.issuer)"
    }
    $internalKeys = $disc.PSObject.Properties.Name | Where-Object { $_ -match '_internal$|_debug$|_secret$' }
    if ($internalKeys.Count -gt 0) {
        throw "discovery exposes internal keys: $($internalKeys -join ', ')"
    }
    Write-Host "  ✓ no placeholders, no *_internal/*_debug/*_secret keys" -ForegroundColor Green
} | Out-Null

# 6) RFC 8414 §2 / RFC 7591 §2 — when private_key_jwt is advertised, the matching
#    *_auth_signing_alg_values_supported field MUST be present (otherwise clients
#    can't pick an alg that the server will accept).
Measure-Step "5. private_key_jwt ↔ *_auth_signing_alg_values_supported coverage" {
    $assertionAlgFields = @{
        token_endpoint_auth_methods_supported          = 'token_endpoint_auth_signing_alg_values_supported'
        introspection_endpoint_auth_methods_supported  = 'introspection_endpoint_auth_signing_alg_values_supported'
        revocation_endpoint_auth_methods_supported     = 'revocation_endpoint_auth_signing_alg_values_supported'
    }
    $errors = @()
    foreach ($methodsField in $assertionAlgFields.Keys) {
        $algField = $assertionAlgFields[$methodsField]
        $methods  = $disc.$methodsField
        if (-not $methods) { continue }
        $hasJwt = ($methods -contains 'private_key_jwt') -or ($methods -contains 'client_secret_jwt')
        if (-not $hasJwt) { continue }
        $algs = $disc.$algField
        if (-not $algs -or $algs.Count -eq 0) {
            $errors += "$methodsField advertises private_key_jwt but $algField is missing/empty"
            continue
        }
        # Must include at least one widely-implemented signing alg.
        $bridgeAlgs = @('RS256','ES256','PS256')
        $hasBridge  = ($algs | Where-Object { $bridgeAlgs -contains $_ }).Count -gt 0
        if (-not $hasBridge) {
            $errors += "$algField does not include any of RS256/ES256/PS256: [$($algs -join ', ')]"
        }
    }
    if ($errors.Count -gt 0) { throw ($errors -join "`n") }
    Write-Host "  ✓ private_key_jwt advertisement matched by signing-alg list on token/introspect/revoke" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
