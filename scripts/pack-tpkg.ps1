<#
.SYNOPSIS
    Builds the Contracts carrier, redb.Identity.Core, redb.Identity.Http, redb.Identity.Grpc and redb.Identity.Soap, packs them as Tsak .tpkg
    modules, and copies into redb.Tsak.Worker/modules/ for hot-reload.

.DESCRIPTION
    Five .tpkg packages produced (Release):
      - redb.Identity.Contracts.tpkg (contracts CARRIER: an empty module whose companion is
                                   redb.Identity.Contracts.dll - the single process-wide
                                   instance every Identity module resolves against; reload it
                                   only on a contract change, then reload everyone)
      - redb.Identity.Core.tpkg   (Core engine: schemes, OpenIddict stores, OIDC server,
                                   MFA, WebAuthn, federation, audit, key rotation,
                                   DPAPI, claim mappers — all transitive third-party
                                   deps that Tsak host doesn't already provide)
      - redb.Identity.Http.tpkg   (HTTP transport facade: 26 controllers; depends on Core)
      - redb.Identity.Grpc.tpkg   (gRPC service-to-service facade; depends on Core)
      - redb.Identity.Soap.tpkg   (WS-Trust facade; depends on Core)

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
    Which modules to pack: Contracts | Core | Http | Grpc | Soap | All (default: All).

.PARAMETER TsakModules
    Override target modules directory. Default: ../redb.Tsak/src/redb.Tsak.Worker/modules.

.PARAMETER NoCopy
    Don't copy resulting .tpkg into Tsak modules (only produce in scripts/output).

.EXAMPLE
    ./scripts/pack-tpkg.ps1
    # Build Release, pack both, copy into Tsak Worker modules.

.EXAMPLE
    ./scripts/pack-tpkg.ps1 -NoBuild -Module Http
    # Re-pack only Http (after editing a controller, with build done elsewhere).
#>
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [switch]$NoBuild,

    [ValidateSet("Contracts", "Core", "Http", "Grpc", "Soap", "All")]
    [string]$Module = "All",

    [string]$TsakModules,

    [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

# ── Resolve paths ──────────────────────────────────────────────────────
$ScriptRoot   = Split-Path -Parent $MyInvocation.MyCommand.Path
$IdentityRoot = Resolve-Path (Join-Path $ScriptRoot "..")
$RepoRoot     = Resolve-Path (Join-Path $IdentityRoot "..")
$Solution     = Join-Path $IdentityRoot "redb.Identity.slnx"
$OutputDir    = Join-Path $ScriptRoot "output"

if (-not $TsakModules) {
    # modules\, not Libs\ — Libs is the deprecated drop directory. Libs\shared still holds the
    # host-provided framework DLLs and stays below as an exclude source, but nothing is dropped there.
    $TsakModules = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\modules"
}
$TsakWorkerBinRelease = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\bin\Release\net10.0"
$TsakWorkerBinDebug   = Join-Path $RepoRoot "redb.Tsak\src\redb.Tsak.Worker\bin\Debug\net10.0"
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

# name -> the copy the HOST will actually load. First source wins, and the scan order below is the
# runtime's own order (worker bin, then the shared layer, then the frameworks), so the recorded path
# is the assembly a module really binds to. Read by the version gate in Pack-Module.
$HostProvided = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)

function Add-Excludes-FromDir([string]$Dir) {
    if (-not (Test-Path $Dir)) {
        Write-Host "Exclude source skipped (missing): $Dir" -ForegroundColor DarkGray
        return
    }
    $before = $ExcludeSet.Count
    Get-ChildItem -Path $Dir -Filter *.dll -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            [void]$ExcludeSet.Add($_.Name)
            if (-not $HostProvided.ContainsKey($_.Name)) { $HostProvided[$_.Name] = $_.FullName }
        }
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

# Shared frameworks: the runtime resolves these by name for the host, and ModuleAssemblyLoadContext
# asks the Default ALC before probing the package - so a copy inside a .tpkg can never win a resolve.
# It is dead weight, and until the Tsak fix (ca994106) LoadedAssemblyTracker byte-loaded it a second
# time into the non-collectible Default context. BOTH frameworks must be scanned: Microsoft.Extensions
# .Configuration / .Options / .Logging / .Diagnostics.HealthChecks ship in the ASP.NET framework, not
# in the runtime one. These names were excluded by accident until 2026-09-18, when build-shared stopped
# copying framework assemblies into Libs\shared; stating the rule here makes the package independent of
# whatever that layer happens to contain.
$WorkerTfm = Split-Path $TsakWorkerBinRelease -Leaf   # net10.0 - the same constant the bin paths use
if ($WorkerTfm -notmatch '^net(?<major>\d+)\.') {
    throw "Cannot read the framework major from '$WorkerTfm' (expected netN.M). Fix `$TsakWorkerBinRelease."
}
$TfmMajor   = [int]$Matches['major']
$DotnetRoot = if ($env:DOTNET_ROOT) { $env:DOTNET_ROOT } else { Split-Path (Get-Command dotnet -ErrorAction Stop).Source }

foreach ($fwName in @("Microsoft.NETCore.App", "Microsoft.AspNetCore.App")) {
    $fwRoot = Join-Path $DotnetRoot "shared\$fwName"
    if (-not (Test-Path $fwRoot)) {
        throw "Shared framework $fwName is not installed under $DotnetRoot. Without it the exclude set is wrong and the packages would carry framework assemblies."
    }
    # Highest installed version of the worker's major. Sort as [version], never as text:
    # a string sort puts 9.0.20 above 10.0.8 and would pick the wrong framework.
    $fwDir = Get-ChildItem $fwRoot -Directory |
        Where-Object { ($_.Name -as [version]) -and ($_.Name -as [version]).Major -eq $TfmMajor } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1
    if (-not $fwDir) {
        throw "No $fwName $TfmMajor.x found under $fwRoot, but the worker targets $WorkerTfm. Install the matching runtime."
    }
    Add-Excludes-FromDir $fwDir.FullName
}

# Always-exclude (cosmetic / not transferred)
@(
    "redb.Identity.Tests.dll"
) | ForEach-Object { [void]$ExcludeSet.Add($_) }

# ── Version gate ───────────────────────────────────────────────────────
# There used to be a force-include list here (Microsoft.IdentityModel.*): those DLLs were packaged
# even though the host had them, on the reasoning that the host shipped an older, incompatible major
# and the module needed its own. That never worked and cannot work: ModuleAssemblyLoadContext asks
# the Default ALC before probing the package - it must, or contract types would split - and since
# Tsak's ca994106 LoadedAssemblyTracker prefers the host copy too. The packaged copies were 1.26 MB
# the loader never looked at, plus a Troubleshooting entry advising a cure that cures nothing.
#
# The real hazard is not "the host has it" but "the host has a DIFFERENT major", and that used to be
# silent: the module compiled against one version, the host loaded another, and the failure surfaced
# far away as a FileNotFoundException inside OpenIddict. The gate below turns that divergence into a
# packaging error naming both sides, so it is fixed by moving a pin rather than by shipping a copy
# that will be ignored.
function Get-AssemblyVersionOrNull([string]$Path) {
    try {
        return [System.Reflection.AssemblyName]::GetAssemblyName($Path).Version
    }
    catch [System.BadImageFormatException] {
        return $null   # native or mixed-mode file - there is no managed identity to compare
    }
    catch {
        Write-Host ("  version unreadable ({0}): {1}" -f $_.Exception.GetType().Name, $Path) -ForegroundColor DarkGray
        return $null
    }
}

Write-Host "Exclude set built: $($ExcludeSet.Count) host-provided DLLs" -ForegroundColor DarkGray

# ── Pack one module ────────────────────────────────────────────────────
function Pack-Module {
    param(
        [string]$ModuleName,            # "redb.Identity.Core"
        [string]$ProjectDir,             # full path to project dir
        [string]$ConfigFileName,         # "redb.Identity.Core.config.json"
        [string[]]$ExtraExcludes = @(),  # additional DLL names to skip
        [string[]]$ContentDirs = @()     # subdirectories of bin\ to ship whole (e.g. "Wsdl")
    )

    Write-Host "`n=== Packing $ModuleName ===" -ForegroundColor Cyan

    $bin       = Join-Path $ProjectDir "bin\$Configuration\net10.0"
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

        $included      = @()
        $skipped       = @()
        $divergedMajor = @()
        $divergedMinor = @()
        Get-ChildItem -Path $bin -Filter *.dll -File | ForEach-Object {
            $name = $_.Name
            $isExcluded = $localExcludes.Contains($name)
            if ($isExcluded) {
                $skipped += $name

                # Version gate. Only for names the HOST provides: ExtraExcludes are the sibling
                # package's assemblies (a facade skips what Core.Module ships), and those two DO
                # share one context by design, so there is nothing to diverge.
                if ($HostProvided.ContainsKey($name)) {
                    $ourVer  = Get-AssemblyVersionOrNull $_.FullName
                    $hostVer = Get-AssemblyVersionOrNull $HostProvided[$name]
                    if ($ourVer -and $hostVer -and $ourVer -ne $hostVer) {
                        $line = "  {0}: module {1}, host {2}  [host copy: {3}]" -f $name, $ourVer, $hostVer, $HostProvided[$name]
                        if ($ourVer.Major -ne $hostVer.Major) { $divergedMajor += $line } else { $divergedMinor += $line }
                    }
                }
            } else {
                Copy-Item $_.FullName -Destination $staging
                $included += $name
            }
        }

        if ($divergedMajor.Count -gt 0) {
            $msg = "{0}: major version divergence with the host on {1} assembly(ies):" -f $ModuleName, $divergedMajor.Count
            $msg += [Environment]::NewLine + ($divergedMajor -join [Environment]::NewLine) + [Environment]::NewLine
            $msg += "The host wins at runtime - the module's load context asks the Default one first - so packaging our own copy cannot fix this. "
            $msg += "Move a pin instead: the module project under redb.Identity\src, and redb.Tsak\src\redb.Tsak.Worker\redb.Tsak.Worker.csproj "
            $msg += "(System.IdentityModel.Tokens.Jwt also comes from redb.Licensing)."
            throw $msg
        }
        foreach ($w in $divergedMinor) {
            Write-Warning ("{0}: minor version divergence with the host, the host copy is what loads.{1}{2}" -f $ModuleName, [Environment]::NewLine, $w)
        }

        Write-Host ("  Included : {0} DLLs" -f $included.Count) -ForegroundColor Green
        Write-Host ("  Excluded : {0} DLLs (host-provided)" -f $skipped.Count) -ForegroundColor DarkGray

        # Content that is not a DLL and lives in a subdirectory: the WS-Trust WSDL, and anything like it
        # later. The DLL loop above reads only the root of bin\, so without this such a file is silently
        # left out of the package — and the code that looks for it degrades quietly rather than failing,
        # which is exactly the combination that ships a module missing half its purpose.
        foreach ($dir in $ContentDirs) {
            $source = Join-Path $bin $dir
            if (-not (Test-Path $source)) { throw "Content directory missing: $source" }

            Copy-Item $source -Destination $staging -Recurse -Force
            $files = @(Get-ChildItem -Path $source -File -Recurse)
            Write-Host ("  Content  : {0}\ ({1} files)" -f $dir, $files.Count) -ForegroundColor Green
        }

        $tpkg = Join-Path $OutputDir "$ModuleName.tpkg"
        if (Test-Path $tpkg) { Remove-Item $tpkg -Force }
        Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $tpkg -CompressionLevel Optimal -Force

        $size = (Get-Item $tpkg).Length
        Write-Host ("  Created  : {0}  ({1:N1} KB)" -f $tpkg, ($size / 1KB)) -ForegroundColor Green

        if (-not $NoCopy) {
            if (-not (Test-Path $TsakModules)) { New-Item -ItemType Directory -Path $TsakModules | Out-Null }
            $dest = Join-Path $TsakModules "$ModuleName.tpkg"
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

if ($Module -in @("Contracts", "All")) {
    # The contracts CARRIER: an empty module whose payload is its companion,
    # redb.Identity.Contracts.dll — the one process-wide instance of the DTO assembly that every
    # Identity module resolves against. Packed FIRST and excluded from everyone else, so that
    # hot-reloading any single module (whose reload force-Replaces its own companions in the
    # tracker) never swaps the contracts out from under the others (Tsak F-12).
    # Reloading THIS package replaces the instance and must be followed by reloading every
    # Identity module — which a contract change requires semantically anyway.
    $results += Pack-Module `
        -ModuleName "redb.Identity.Contracts" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Contracts.Module") `
        -ConfigFileName "redb.Identity.Contracts.Module.config.json"
}

# Every later package excludes what the carrier ships, exactly as the facades exclude what
# Core.Module ships. When only a subset is being packed the carrier result is absent — then the
# carrier's own bin answers instead, so a lone `-Module Core` repack still excludes the contracts.
$contractsResult = $results | Where-Object { $_.Module -eq "redb.Identity.Contracts" } | Select-Object -First 1
$contractsExcludes = @()
if ($contractsResult) {
    $contractsExcludes = $contractsResult.DllNames
} else {
    $contractsBin = Join-Path $IdentityRoot "src\redb.Identity.Contracts.Module\bin\$Configuration\net10.0"
    if (Test-Path $contractsBin) {
        $contractsExcludes = @(Get-ChildItem -Path $contractsBin -Filter *.dll -File | ForEach-Object { $_.Name })
    }
}
if (-not ($contractsExcludes -contains "redb.Identity.Contracts.dll")) {
    # Refuse to build a core package that would smuggle its own contracts copy back in.
    throw "Contracts carrier not built — run with -Module Contracts (or All), or build src\redb.Identity.Contracts.Module first."
}

if ($Module -in @("Core", "All")) {
    # The Tsak entry-point project is the *thin* shim `redb.Identity.Core.Module`.
    # Its bin/ contains:
    #   - redb.Identity.Core.Module.dll  ← the EntryPoint (isolated per-package ALC)
    #   - redb.Identity.Core.dll         ← COMPANION (visible to facade .tpkg's via
    #                                        LoadedAssemblyTracker / Default ALC)
    #   - OpenIddict.*, Konscious.Argon2, Fido2, Otp.NET, MyCSharp.HttpUserAgentParser*
    #   - all transitive NuGet runtime DLLs not already provided by Tsak host.
    # redb.Identity.Contracts.dll is deliberately NOT here — the carrier package above ships it.
    $results += Pack-Module `
        -ModuleName "redb.Identity.Core.Module" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Core.Module") `
        -ConfigFileName "redb.Identity.Core.Module.config.json" `
        -ExtraExcludes $contractsExcludes
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
    $httpExtraExcludes += $contractsExcludes

    $results += Pack-Module `
        -ModuleName "redb.Identity.Http" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Http") `
        -ConfigFileName "redb.Identity.Http.config.json" `
        -ExtraExcludes $httpExtraExcludes
}

if ($Module -in @("Grpc", "All")) {
    # Same rule as Http: a facade .tpkg must NOT duplicate anything Core.Module already ships.
    # Tsak loads dependencies first, so Core's companions live in the Default ALC and are shared by
    # assembly identity; duplicating them here would create type-identity collisions across ALCs.
    # The result is a tiny package carrying only redb.Identity.Grpc.dll.
    $grpcExtraExcludes = @(
        "redb.Identity.Core.dll",
        "redb.Identity.Contracts.dll"
    )
    $coreResultForGrpc = $results | Where-Object { $_.Module -eq "redb.Identity.Core.Module" } | Select-Object -First 1
    if ($coreResultForGrpc) {
        $grpcExtraExcludes += $coreResultForGrpc.DllNames
    }
    $grpcExtraExcludes += $contractsExcludes

    $results += Pack-Module `
        -ModuleName "redb.Identity.Grpc" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Grpc") `
        -ConfigFileName "redb.Identity.Grpc.config.json" `
        -ExtraExcludes $grpcExtraExcludes
}

if ($Module -in @("Soap", "All")) {
    # Same rule as Http and Grpc: a facade .tpkg must NOT duplicate anything Core.Module already ships.
    # The result is a tiny package carrying redb.Identity.Soap.dll and the WSDL it publishes.
    $soapExtraExcludes = @(
        "redb.Identity.Core.dll",
        "redb.Identity.Contracts.dll"
    )
    $coreResultForSoap = $results | Where-Object { $_.Module -eq "redb.Identity.Core.Module" } | Select-Object -First 1
    if ($coreResultForSoap) {
        $soapExtraExcludes += $coreResultForSoap.DllNames
    }
    $soapExtraExcludes += $contractsExcludes

    $results += Pack-Module `
        -ModuleName "redb.Identity.Soap" `
        -ProjectDir (Join-Path $IdentityRoot "src\redb.Identity.Soap") `
        -ConfigFileName "redb.Identity.Soap.config.json" `
        -ExtraExcludes $soapExtraExcludes `
        -ContentDirs @("Wsdl")   # the contract, served on GET; without it the facade answers POST only
}

# ── Copy external context.json (Tsak Layer 3, devops-editable) ────────
# This single file replaces business defaults that previously lived inside each
# .tpkg's {Module}.config.json. Tsak's TsakCoordinator.LoadModuleConfigFiles reads
# {sourceDir}/context.json (sourceDir = folder where .tpkg lives = $TsakModules) and
# merges it into EVERY module's effective config in that folder. Each context binds
# only the sections it knows (Core → Identity:*, Http → IdentityTransport:*); shared
# Redb:identity-pg is wired into both. The slim in-package {Module}.config.json now
# carries only ContextName + AutoStart (module identity).
# context.json is ALWAYS emitted into scripts/output alongside the two .tpkg so that
# output/ is a self-contained, deployable bundle: { *.tpkg + context.json }. Whoever
# drops these files into a Tsak host's module folder (e.g. dist worker\modules\) gets the
# shared Layer-3 config too — without it the modules boot on in-tpkg stub defaults only
# (AllowEphemeralKeys=false, UsePropsSigningKeyStore=false → "no signing credentials").
# When -not $NoCopy we ALSO copy into the dev Worker modules dir for hot-reload.
$externalContext = Join-Path $IdentityRoot "context.json"
if (Test-Path $externalContext) {
    Write-Host ("`n=== External context.json ===") -ForegroundColor Cyan
    Write-Host ("  Source : {0}" -f $externalContext) -ForegroundColor DarkGray

    # (1) scripts/output — part of the shippable artifact set (ALWAYS)
    $outputContext = Join-Path $OutputDir "context.json"
    Copy-Item $externalContext -Destination $outputContext -Force
    $outCtxSize = (Get-Item $outputContext).Length
    Write-Host ("  Output : {0}  ({1:N1} KB)" -f $outputContext, ($outCtxSize / 1KB)) -ForegroundColor Green

    # (2) dev Worker Libs — hot-reload (gated by -NoCopy)
    if (-not $NoCopy) {
        $contextDest = Join-Path $TsakModules "context.json"
        Copy-Item $externalContext -Destination $contextDest -Force
        (Get-Item $contextDest).LastWriteTime = Get-Date   # touch → triggers hot-reload
        Write-Host ("  Copied : {0}" -f $contextDest) -ForegroundColor Green
    }
} else {
    Write-Warning "External context.json not found at $externalContext — modules will run with stub defaults only."
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Select-Object Module, Included, Excluded, SizeKB, Tpkg | Format-Table -AutoSize

Write-Host "`nDone." -ForegroundColor Green
if (-not $NoCopy) {
    Write-Host "Tsak Worker should hot-reload modules from: $TsakModules" -ForegroundColor Yellow
    Write-Host "Devops single source of truth: $TsakModules\context.json" -ForegroundColor Yellow
}
