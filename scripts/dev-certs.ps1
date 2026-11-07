#requires -Version 7.0
<#
.SYNOPSIS
    Provisions a locally-trusted TLS certificate for redb.Identity.Web dev.

.DESCRIPTION
    W6-1: HTTPS by default for the BFF in development. Two paths:

      1. mkcert (preferred) — issues a cert chained to a per-user root
         CA that the OS already trusts. Output: ./certs/identity-web.pfx.
         Kestrel reads it via the Kestrel:Endpoints:Https:Certificate
         section in appsettings.Development.json.

      2. dotnet dev-certs https --trust (fallback) — uses the ASP.NET Core
         developer cert. No file output; Kestrel picks it up implicitly
         when no explicit cert is configured.

    Choice is automatic: mkcert if on PATH, otherwise dev-certs.

.PARAMETER PfxPassword
    Password for the generated PFX (mkcert path). Defaults to "redb-dev".
    The same value must appear in appsettings.Development.json under
    Kestrel:Endpoints:Https:Certificate:Password.

.PARAMETER OutDir
    Output directory for the PFX. Defaults to ./certs at the repo root.

.PARAMETER Force
    Re-issue even if the PFX already exists.

.EXAMPLE
    pwsh ./redb.Identity/scripts/dev-certs.ps1

.EXAMPLE
    pwsh ./redb.Identity/scripts/dev-certs.ps1 -Force
#>
[CmdletBinding()]
param(
    [string]$PfxPassword = 'redb-dev',
    [string]$OutDir = (Join-Path $PSScriptRoot '..' '..' 'certs'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[dev-certs] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[dev-certs] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[dev-certs] $msg" -ForegroundColor Yellow }

$mkcert = Get-Command mkcert -ErrorAction SilentlyContinue

if ($mkcert) {
    Write-Info "mkcert found: $($mkcert.Source)"

    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    $OutDir = (Resolve-Path $OutDir).Path

    $pfxPath = Join-Path $OutDir 'identity-web.pfx'

    if ((Test-Path $pfxPath) -and -not $Force) {
        Write-Ok "PFX already exists: $pfxPath (use -Force to re-issue)"
    }
    else {
        Write-Info 'Installing mkcert local CA (idempotent)...'
        & mkcert -install | Out-Null

        Push-Location $OutDir
        try {
            Write-Info 'Issuing cert for localhost / 127.0.0.1 / ::1 ...'
            & mkcert `
                -pkcs12 `
                -p12-file 'identity-web.pfx' `
                localhost 127.0.0.1 ::1
        }
        finally {
            Pop-Location
        }

        # mkcert -pkcs12 uses fixed password "changeit"; re-export with our password.
        Write-Info 'Re-exporting PFX with configured password...'
        $cert = Get-PfxData -FilePath $pfxPath -Password (ConvertTo-SecureString -String 'changeit' -AsPlainText -Force)
        $cert.EndEntityCertificates[0] | Export-PfxCertificate `
            -FilePath $pfxPath `
            -Password (ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force) `
            -Force | Out-Null

        Write-Ok "Wrote $pfxPath"
    }

    Write-Host ''
    Write-Ok 'mkcert provisioning done. Kestrel will load this PFX via appsettings.Development.json.'
    Write-Host '  Path:     ' $pfxPath
    Write-Host '  Password: ' $PfxPassword
    Write-Host ''
    Write-Host 'Next:'
    Write-Host '  cd redb.Identity/src/redb.Identity.Web'
    Write-Host '  dotnet run'
    return
}

Write-Warn2 'mkcert not found on PATH — falling back to dotnet dev-certs.'
Write-Warn2 'For a wider-compatibility cert (containers, multi-host names) install mkcert:'
Write-Warn2 '  https://github.com/FiloSottile/mkcert'
Write-Host ''

Write-Info 'Trusting the ASP.NET Core developer certificate...'
& dotnet dev-certs https --trust
if ($LASTEXITCODE -ne 0) {
    throw "dotnet dev-certs failed with exit code $LASTEXITCODE"
}

Write-Ok 'ASP.NET Core dev certificate installed and trusted.'
Write-Host 'Kestrel picks it up automatically — no PFX path needed in config.'
Write-Host ''
Write-Host 'Next:'
Write-Host '  cd redb.Identity/src/redb.Identity.Web'
Write-Host '  dotnet run --launch-profile https'
