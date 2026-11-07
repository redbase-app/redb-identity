#requires -Version 7.0
<#
.SYNOPSIS
    Provisions the W6-0 backchannel service-account secret for local development.

.DESCRIPTION
    The Identity host (Tsak.Worker, context 'identity.core') and the Identity.Web
    BFF must share one client_credentials secret so that:

      • SeedBackchannelClientHostedService can register the OpenIddict application
        'identity-backchannel' on host startup.
      • RevokedSidsPollHostedService (BFF) can mint a machine-token and poll
        /api/v1/identity/revoked-sids/since every minute.

    This script generates one 32-byte random base64 secret (or accepts a custom
    one) and sets THREE environment variables in User scope so both processes
    pick it up on next start:

      Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret
          → consumed by SeedBackchannelClientHostedService inside Tsak.Worker
      Identity__BackchannelClient__ClientId
          → consumed by BackchannelTokenProvider in redb.Identity.Web
      Identity__BackchannelClient__ClientSecret
          → consumed by BackchannelTokenProvider in redb.Identity.Web

    Idempotent: if the env-vars already exist and match, no changes are made.
    Use -Force to rotate (regenerates a fresh secret and overwrites both sides).

.PARAMETER Secret
    Custom secret to use instead of a generated random one. Must be non-empty.

.PARAMETER ClientId
    Backchannel client identifier. Default 'identity-backchannel' (matches the
    default in SeedBackchannelClientOptions and the canonical context.json).

.PARAMETER Scope
    Environment-variable scope. Default 'User' (per-user, persists across
    sessions). 'Machine' requires elevation. 'Process' is volatile.

.PARAMETER Force
    Regenerate the secret even if env-vars already exist. Use to rotate.

.PARAMETER Clear
    Remove all three env-vars (cleanup). Other parameters are ignored.

.EXAMPLE
    ./scripts/dev-backchannel-secret.ps1
    # Idempotent: generates a new secret on first run, no-op on subsequent runs.

.EXAMPLE
    ./scripts/dev-backchannel-secret.ps1 -Force
    # Rotates the secret. Both Tsak.Worker AND Identity.Web must be restarted.
    # If a stale 'identity-backchannel' OpenIddict app already exists with the
    # OLD secret, the host seeder will skip (idempotent on ClientId, not Secret)
    # — you must either delete the app via the management API or run with the
    # original secret.

.EXAMPLE
    ./scripts/dev-backchannel-secret.ps1 -Secret 'my-explicit-dev-secret'
    # Use a known secret (e.g. shared between team members).

.EXAMPLE
    ./scripts/dev-backchannel-secret.ps1 -Clear
    # Removes all three env-vars. Useful before switching to a different identity instance.
#>
[CmdletBinding()]
param(
    [string]$Secret,

    [string]$ClientId = "identity-backchannel",

    [ValidateSet("User", "Machine", "Process")]
    [string]$Scope = "User",

    [switch]$Force,

    [switch]$Clear
)

$ErrorActionPreference = "Stop"

# Three variables that must move in lockstep.
$HostSecretVar  = "Tsak__Contexts__identity.core__Override__Identity__SeedBackchannelClient__ClientSecret"
$BffClientIdVar = "Identity__BackchannelClient__ClientId"
$BffSecretVar   = "Identity__BackchannelClient__ClientSecret"

function Get-Env([string]$name) {
    [Environment]::GetEnvironmentVariable($name, $Scope)
}

function Set-Env([string]$name, [string]$value) {
    [Environment]::SetEnvironmentVariable($name, $value, $Scope)
    # User/Machine scopes are only seen by NEW processes — also mirror into the
    # current process env so 'dotnet run' from THIS shell picks it up immediately.
    if ($Scope -ne "Process") {
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

function Remove-Env([string]$name) {
    [Environment]::SetEnvironmentVariable($name, $null, $Scope)
    if ($Scope -ne "Process") {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}

if ($Clear) {
    Write-Host "Clearing backchannel env-vars from $Scope scope..." -ForegroundColor Yellow
    Remove-Env $HostSecretVar
    Remove-Env $BffClientIdVar
    Remove-Env $BffSecretVar
    Write-Host "  ✓ cleared" -ForegroundColor Green
    return
}

$existingHostSecret = Get-Env $HostSecretVar
$existingBffId      = Get-Env $BffClientIdVar
$existingBffSecret  = Get-Env $BffSecretVar

$allSet = -not [string]::IsNullOrEmpty($existingHostSecret) `
    -and -not [string]::IsNullOrEmpty($existingBffId) `
    -and -not [string]::IsNullOrEmpty($existingBffSecret)

$consistent = $allSet `
    -and ($existingHostSecret -eq $existingBffSecret) `
    -and ($existingBffId -eq $ClientId)

if ($consistent -and -not $Force -and -not $Secret) {
    Write-Host "Backchannel secret already provisioned in $Scope scope:" -ForegroundColor Green
    Write-Host "  $HostSecretVar"
    Write-Host "  $BffClientIdVar = $existingBffId"
    Write-Host "  $BffSecretVar"
    Write-Host "(use -Force to rotate, -Clear to remove)" -ForegroundColor DarkGray
    return
}

if ($allSet -and -not $consistent -and -not $Force -and -not $Secret) {
    Write-Warning "Existing env-vars are INCONSISTENT (host secret ≠ BFF secret, or ClientId mismatch)."
    Write-Warning "Re-run with -Force to overwrite, or with -Secret <value> to set explicit value."
    exit 1
}

if (-not $Secret) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $Secret = [Convert]::ToBase64String($bytes)
    Write-Host "Generated new random secret (32 bytes, base64-encoded)." -ForegroundColor Cyan
} else {
    Write-Host "Using explicit secret from -Secret parameter." -ForegroundColor Cyan
}

Set-Env $HostSecretVar  $Secret
Set-Env $BffClientIdVar $ClientId
Set-Env $BffSecretVar   $Secret

Write-Host "`nProvisioned backchannel credentials in $Scope scope:" -ForegroundColor Green
Write-Host "  $HostSecretVar"
Write-Host "  $BffClientIdVar = $ClientId"
Write-Host "  $BffSecretVar"

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Restart Tsak.Worker (SeedBackchannelClientHostedService will create/verify the OpenIddict app)."
Write-Host "  2. Restart redb.Identity.Web (RevokedSidsPollHostedService will start polling)."
if ($Scope -ne "Process") {
    Write-Host "     • THIS shell already sees the new env-vars (mirrored into Process scope)."
    Write-Host "     • OTHER already-open shells need to be reopened — User-scope env-vars are loaded at process start."
}
Write-Host ""
Write-Host "If you rotated the secret with -Force and the 'identity-backchannel' OpenIddict" -ForegroundColor DarkYellow
Write-Host "application already exists, the host seeder is idempotent on ClientId and will NOT" -ForegroundColor DarkYellow
Write-Host "update the stored secret. Either delete the app via management API and restart, or" -ForegroundColor DarkYellow
Write-Host "use the original secret." -ForegroundColor DarkYellow
