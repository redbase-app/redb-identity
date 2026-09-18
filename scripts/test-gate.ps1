#!/usr/bin/env pwsh
<#
.SYNOPSIS
    The Identity test gate: every test project of redb.Identity, on one storage provider.

.DESCRIPTION
    Runs the three test projects the solution carries - redb.Identity.Tests (the engine, provider
    matrix), redb.Identity.Client.Tests (the SDK, pure unit) and redb.Identity.Web.Tests (the BFF,
    pure unit) - and prints one summary. Client and Web tests do not touch storage; they are in the
    gate because a gate that runs one project out of three is how tests stay red for months without
    anyone noticing (RevokedSidsPollHostedServiceTests since 2026-07, SearchUsers_GETs_with_query
    since 2026-06, DevTlsContractTests since 2026-05).

    The provider matrix is three invocations of this script, one per -Provider, started in parallel
    the way the owner runs them. Brokers are shared between those processes; suites that need one
    isolate themselves per provider (see AuditIbmMqIntegrationTests).

.PARAMETER Provider
    sqlite (default) | postgres | mssql - exported as REDB_PROVIDER for redb.Identity.Tests.

.PARAMETER Filter
    Optional `dotnet test --filter` expression applied to redb.Identity.Tests only.

.PARAMETER NoBuild
    Skip the build (the last build of each project is used). Only when you know it is fresh.

.EXAMPLE
    pwsh redb.Identity/scripts/test-gate.ps1 -Provider postgres
#>
param(
    [ValidateSet("sqlite", "postgres", "mssql")]
    [string]$Provider = "sqlite",
    [string]$Filter,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")
$env:REDB_PROVIDER = $Provider
$env:DOTNET_CLI_UI_LANGUAGE = "en"

$projects = @(
    @{ Name = "redb.Identity.Tests";        Path = "tests\redb.Identity.Tests\redb.Identity.Tests.csproj";               UsesFilter = $true  },
    @{ Name = "redb.Identity.Client.Tests"; Path = "tests\redb.Identity.Client.Tests\redb.Identity.Client.Tests.csproj"; UsesFilter = $false },
    @{ Name = "redb.Identity.Web.Tests";    Path = "tests\redb.Identity.Web.Tests\redb.Identity.Web.Tests.csproj";       UsesFilter = $false }
)

$results = @()
$failed = $false
foreach ($p in $projects) {
    $csproj = Join-Path $root $p.Path
    Write-Host "`n=== $($p.Name)  [REDB_PROVIDER=$Provider] ===" -ForegroundColor Cyan

    if (-not $NoBuild) {
        dotnet build $csproj -c Debug --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "build failed: $($p.Name) (exit $LASTEXITCODE)" }
    }

    $args = @("test", $csproj, "--no-build", "--nologo")
    if ($Filter -and $p.UsesFilter) { $args += @("--filter", $Filter) }

    $output = & dotnet @args 2>&1
    $exit = $LASTEXITCODE
    $output | Where-Object { $_ -match '^\s*Failed |Passed!|Failed!|Error Message|^\s+Expected' } | ForEach-Object { Write-Host $_ }

    $summary = ($output | Select-String -Pattern 'Passed:\s+(\d+).*Total:\s+(\d+)|Failed:\s+(\d+),\s+Passed:\s+(\d+)' | Select-Object -Last 1).Line
    $results += [pscustomobject]@{ Project = $p.Name; Exit = $exit; Summary = ($summary ?? "<no summary line>").Trim() }
    if ($exit -ne 0) { $failed = $true }
}

Write-Host "`n=== Gate summary  [REDB_PROVIDER=$Provider] ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

if ($failed) { Write-Host "GATE RED" -ForegroundColor Red; exit 1 }
Write-Host "GATE GREEN" -ForegroundColor Green
exit 0
