<#
.SYNOPSIS
    Builds redb.Identity.Core and redb.Identity.Http, packs them as Tsak .tpkg modules,
    and copies into redb.Tsak.Worker/Libs/ for hot-reload.

.DESCRIPTION
    Two .tpkg packages produced (Release):
      - redb.Identity.Core.tpkg   (Core engine: schemes, OpenIddict stores, OIDC server,
                                   MFA, WebAuthn, federation, audit, key rotation,
                                   DPAPI, claim mappers — all transitive third-party
                                   deps that Tsak host doesn't already provide)
      - redb.Identity.Http.tpkg   (HTTP transport facade: 26 controllers; depends on Core)

    Each .tpkg = ZIP { manifest.json, *.config.json, *.dll [, *.pdb] }.

    Host-provided assemblies (already loaded by Tsak Worker default ALC) are EXCLUDED
    automatically. The exclude set is the union of:
      - $TsakWorkerBin\*.dll      (Worker's own publish bin)
      - $TsakSharedLibs\*.dll     (Worker/Libs/shared/*)
    Plus a small explicit list (Identity-internal DLLs that Http doesn't repackage).

.PARAMETER Configuration
    Build configuration. Default: Release. Debug not used here — Tsak hot-loads modules
    in its own process; cross-process attach to a hot-loaded ALC is unreliable. If you
    need to step through Identity code, run a separate console host project under VS.

.PARAMETER NoBuild
    Skip 'dotnet build' (use last produced bin). Useful when iterating on the script
    or when build was just done.

.PARAMETER Module
    Which modules to pack: Core | Http | All (default: All).

.PARAMETER TsakLibs
    Override target Libs directory. Default: ../redb.Tsak/src/redb.Tsak.Worker/Libs.

.PARAMETER NoCopy
    Don't copy resulting .tpkg into Tsak Libs (only produce in scripts/output).

.EXAMPLE
    ./scripts/pack-tpkg.ps1
    # Build Release, pack both, copy into Tsak Worker Libs.

.EXAMPLE
    ./scripts/pack-tpkg.ps1 -NoBuild -Module Http
    # Re-pack only Http (after editing a controller, with build done elsewhere).
#>
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [switch]$NoBuild,

    [ValidateSet("Core", "Http", "All")]
    [string]$Module = "All",

    [string]$TsakLibs,

    [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

# ── Resolve paths ──────────────────────────────────────────────────────
$ScriptRoot   = Split-Path -Parent $MyInvocation.MyCommand.Path
$IdentityRoot = Resolve-Path (Join-Path $ScriptRoot "..")
$RepoRoot     = Resolve-Path (Join-Path $IdentityRoot "..")
$Solution     = Join-Path $IdentityRoot "redb.Identity.slnx"
$OutputDir    = Join-Path $ScriptRoot "output"

if (-not $TsakLibs) {
    $TsakLibs = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\Libs"
}
$TsakWorkerBinRelease = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\bin\Release\net9.0"
$TsakWorkerBinDebug   = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\bin\Debug\net9.0"
$TsakLibsRoot         = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\Libs"
$TsakSharedLibs       = Join-Path $TsakLibsRoot "shared"

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

# ── Build ──────────────────────────────────────────────────────────────
# CopyLocalLockFileAssemblies=true forces NuGet PackageReference assemblies (OpenIddict,
# Argon2, Fido2, Otp.NET, MyCSharp.HttpUserAgentParser, …) to be copied into bin/.
# Without it, library-SDK projects only emit own DLL + ProjectReference outputs, and
# the .tpkg would be missing all third-party deps.
# We pass via /p: instead of editing csproj to avoid bloating test-project bin folders.
if (-not $NoBuild) {
    Write-Host "`n=== Building redb.Identity ($Configuration) ===" -ForegroundColor Cyan
    & dotnet build $Solution -c $Configuration --nologo /p:CopyLocalLockFileAssemblies=true
    if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }
}

# ── Build EXCLUDE set (host-provided assemblies) ───────────────────────
$ExcludeSet = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

function Add-Excludes-FromDir([string]$Dir) {
    if (-not (Test-Path $Dir)) {
        Write-Host "Exclude source skipped (missing): $Dir" -ForegroundColor DarkGray
        return
    }
    $before = $ExcludeSet.Count
    Get-ChildItem -Path $Dir -Filter *.dll -File -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$ExcludeSet.Add($_.Name) }
    $added = $ExcludeSet.Count - $before
    Write-Host "Exclude source: $Dir (+$added)" -ForegroundColor DarkGray
}

# Worker bin: scan whichever Configuration actually built (Debug if Release missing).
# Sometimes both exist if user has built both — scan both, union of names is what's host-resident.
Add-Excludes-FromDir $TsakWorkerBinRelease
Add-Excludes-FromDir $TsakWorkerBinDebug
# Tpkg-side resolution: ALC reads Libs\ root + Libs\shared\. Anything sitting there is
# host-provided to every loaded module — exclude both.
Add-Excludes-FromDir $TsakLibsRoot
Add-Excludes-FromDir $TsakSharedLibs

# Always-exclude (cosmetic / not transferred)
@(
    "redb.Identity.Tests.dll"
) | ForEach-Object { [void]$ExcludeSet.Add($_) }

# Force-INCLUDE patterns: DLLs that match these wildcard patterns are ALWAYS
# packaged with the .tpkg even if a same-named DLL exists in the host bin.
# Reason: host ships an OLDER major version (e.g. Microsoft.IdentityModel.Protocols
# 6.35.0.0) that is binary-incompatible with what OpenIddict.Validation 7.x demands
# (Microsoft.IdentityModel.Protocols 8.4.0.0). Without override the module ALC
# resolves the host's old DLL → FileNotFoundException at runtime.
$ForceIncludePatterns = @(
    'Microsoft.IdentityModel.*.dll'
)

Write-Host "Exclude set built: $($ExcludeSet.Count) host-provided DLLs" -ForegroundColor DarkGray

# ── Pack one module ────────────────────────────────────────────────────
function Pack-Module {
    param(
        [string]$ModuleName,            # "redb.Identity.Core"
        [string]$ProjectDir,             # full path to project dir
        [string]$ConfigFileName,         # "redb.Identity.Core.config.json"
        [string[]]$ExtraExcludes = @()   # additional DLL names to skip
    )

    Write-Host "`n=== Packing $ModuleName ===" -ForegroundColor Cyan

    $bin       = Join-Path $ProjectDir "bin\$Configuration\net9.0"
    $manifest  = Join-Path $ProjectDir "Module\manifest.json"
    $config    = Join-Path $ProjectDir $ConfigFileName

    if (-not (Test-Path $bin))      { throw "Bin dir missing: $bin" }
    if (-not (Test-Path $manifest)) { throw "Manifest missing: $manifest" }
    if (-not (Test-Path $config))   { throw "Config missing: $config" }

    $staging = Join-Path $env:TEMP "tpkg-$ModuleName-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $staging | Out-Null

    try {
        Copy-Item $manifest -Destination $staging
        Copy-Item $config   -Destination $staging

        $localExcludes = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $ExcludeSet)     { [void]$localExcludes.Add($n) }
        foreach ($n in $ExtraExcludes)  { [void]$localExcludes.Add($n) }

        $included = @()
        $skipped  = @()
        Get-ChildItem -Path $bin -Filter *.dll -File | ForEach-Object {
            $name = $_.Name
            $isExcluded = $localExcludes.Contains($name)
            if ($isExcluded) {
                # Override exclusion when the DLL matches a force-include pattern
                foreach ($pattern in $ForceIncludePatterns) {
                    if ($name -like $pattern) { $isExcluded = $false; break }
                }
            }
            if ($isExcluded) {
                $skipped += $name
            } else {
                Copy-Item $_.FullName -Destination $staging
                $included += $name
            }
        }

        Write-Host ("  Included : {0} DLLs" -f $included.Count) -ForegroundColor Green
        Write-Host ("  Excluded : {0} DLLs (host-provided)" -f $skipped.Count) -ForegroundColor DarkGray

        $tpkg = Join-Path $OutputDir "$ModuleName.tpkg"
        if (Test-Path $tpkg) { Remove-Item $tpkg -Force }
        Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $tpkg -CompressionLevel Optimal -Force

        $size = (Get-Item $tpkg).Length
        Write-Host ("  Created  : {0}  ({1:N1} KB)" -f $tpkg, ($size / 1KB)) -ForegroundColor Green

        if (-not $NoCopy) {
            if (-not (Test-Path $TsakLibs)) { New-Item -ItemType Directory -Path $TsakLibs | Out-Null }
            $dest = Join-Path $TsakLibs "$ModuleName.tpkg"
            Copy-Item $tpkg -Destination $dest -Force
            (Get-Item $dest).LastWriteTime = Get-Date   # touch → triggers Tsak hot-reload watcher
            Write-Host ("  Copied   : {0}" -f $dest) -ForegroundColor Green
        }

        return [pscustomobject]@{
            Module    = $ModuleName
            Included  = $included.Count
            Excluded  = $skipped.Count
            SizeKB    = [math]::Round($size / 1KB, 1)
            Tpkg      = $tpkg
            DllNames  = $included
        }
    }
    finally {
        if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ── Run ────────────────────────────────────────────────────────────────
$results = @()

if ($Module -in @("Core", "All")) {
    # The Tsak entry-point project is the *thin* shim `redb.Identity.Core.Module`.
    # Its bin/ contains:
    #   - redb.Identity.Core.Module.dll  ← the EntryPoint (isolated per-package ALC)
    #   - redb.Identity.Core.dll         ← COMPANION (visible to facade .tpkg's via
    #     redb.Identity.Contracts.dll        LoadedAssemblyTracker / Default ALC)
    #   - OpenIddict.*, Konscious.Argon2, Fido2, Otp.NET, MyCSharp.HttpUserAgentParser*
    #   - all transitive NuGet runtime DLLs not already provided by Tsak host.
    $results += Pack-Module `
        -ModuleName "redb.Identity.Core.Module" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Core.Module") `
        -ConfigFileName "redb.Identity.Core.Module.config.json"
}

if ($Module -in @("Http", "All")) {
    # Http.tpkg must NOT carry anything that already lives in Core.tpkg —
    # Tsak loads dependencies first (manifest.Dependencies) so types come from Core's ALC.
    # If we duplicate transitive NuGet DLLs (OpenIddict, Argon2, Fido2, …) into Http.tpkg,
    # we get type-identity collisions across ALCs.
    # Http.tpkg gets the union of Core.Module's DllNames as ExtraExcludes — every DLL
    # already shipped as a Core.Module companion is dropped from Http.tpkg, so Http.tpkg
    # ends up containing only the HTTP-facade DLL (`redb.Identity.Http.dll`).
    # Type identity is preserved cross-ALC because the Tsak ModuleAssemblyLoadContext
    # delegates resolution to the Default ALC (LoadedAssemblyTracker) before probing
    # local probe paths — Core.Module's companions are loaded into Default ALC and
    # shared by Assembly identity.
    $httpExtraExcludes = @(
        "redb.Identity.Core.dll",
        "redb.Identity.Contracts.dll"
    )
    $coreResult = $results | Where-Object { $_.Module -eq "redb.Identity.Core.Module" } | Select-Object -First 1
    if ($coreResult) {
        $httpExtraExcludes += $coreResult.DllNames
    }

    $results += Pack-Module `
        -ModuleName "redb.Identity.Http" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Http") `
        -ConfigFileName "redb.Identity.Http.config.json" `
        -ExtraExcludes $httpExtraExcludes
}

# ── Copy external context.json (Tsak Layer 3, devops-editable) ────────
# This single file replaces business defaults that previously lived inside each
# .tpkg's {Module}.config.json. Tsak's TsakCoordinator.LoadModuleConfigFiles reads
# {sourceDir}/context.json (sourceDir = folder where .tpkg lives = $TsakLibs) and
# merges it into EVERY module's effective config in that folder. Each context binds
# only the sections it knows (Core → Identity:*, Http → IdentityTransport:*); shared
# Redb:identity-pg is wired into both. The slim in-package {Module}.config.json now
# carries only ContextName + AutoStart (module identity).
if (-not $NoCopy) {
    $externalContext = Join-Path $IdentityRoot "context.json"
    if (Test-Path $externalContext) {
        $contextDest = Join-Path $TsakLibs "context.json"
        Copy-Item $externalContext -Destination $contextDest -Force
        (Get-Item $contextDest).LastWriteTime = Get-Date   # touch → triggers hot-reload
        $contextSize = (Get-Item $contextDest).Length
        Write-Host ("`n=== External context.json ===") -ForegroundColor Cyan
        Write-Host ("  Source : {0}" -f $externalContext) -ForegroundColor DarkGray
        Write-Host ("  Copied : {0}  ({1:N1} KB)" -f $contextDest, ($contextSize / 1KB)) -ForegroundColor Green
    } else {
        Write-Warning "External context.json not found at $externalContext — modules will run with stub defaults only."
    }
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Select-Object Module, Included, Excluded, SizeKB, Tpkg | Format-Table -AutoSize

Write-Host "`nDone." -ForegroundColor Green
if (-not $NoCopy) {
    Write-Host "Tsak Worker should hot-reload modules from: $TsakLibs" -ForegroundColor Yellow
    Write-Host "Devops single source of truth: $TsakLibs\context.json" -ForegroundColor Yellow
}
