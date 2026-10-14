#Requires -Version 7.0
[CmdletBinding()]
param(
    [AllowEmptyString()][string]$Prefix,
    [switch]$Force,
    [switch]$SkipBuild,
    [Alias('h')][switch]$Help
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Help) {
    @'
Usage: pwsh -File scripts/install.ps1 [-Prefix PATH] [-Force] [-SkipBuild] [-Help]
Build the local checkout and install its native release binary to PREFIX/bin/banshee.exe.
Windows only; requires PowerShell 7, Cargo/Rust and the MSVC C++ build tools.
Default prefix: $env:PREFIX or $HOME/.local. Relative prefixes use your current directory.
Existing files are refused unless -Force is supplied; links/directories are refused.
Cargo target-directory settings are respected. No downloaded executable is installed.
-SkipBuild reuses a local release binary (native-target layout first, then release/).
Example: ./scripts/install.ps1 -Prefix "$HOME/.local"
'@
    exit 0
}
$stage = $null
try {
    if (-not $IsWindows) { throw 'Use scripts/install.sh on Linux.' }
    if (-not $PSBoundParameters.ContainsKey('Prefix')) {
        $Prefix = if ($env:PREFIX) { $env:PREFIX } else { Join-Path $HOME '.local' }
    }
    if ([string]::IsNullOrWhiteSpace($Prefix)) { throw '-Prefix must not be empty.' }
    $Prefix = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Prefix)
    $binDirectory = Join-Path $Prefix 'bin'
    $destination = Join-Path $binDirectory 'banshee.exe'
    function Assert-Destination {
        foreach ($path in @($binDirectory, $destination)) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Installation path is a link/reparse point: $path"
            }
        }
        if (Test-Path -LiteralPath $destination) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                throw "Destination is not a regular file: $destination"
            }
            if (-not $Force) { throw "Destination exists: $destination (use -Force to replace)." }
        }
    }
    Assert-Destination
    foreach ($tool in @('cargo', 'rustc')) {
        if (-not (Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) {
            throw "Missing prerequisite: $tool"
        }
    }
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try {
        $hostText = & rustc -vV
        if ($LASTEXITCODE -ne 0) { throw 'Rust host detection failed.' }
        $hostTriple = ($hostText | Where-Object { $_ -match '^host: ' }) -replace '^host: ', ''
        if (-not $hostTriple) { throw 'Cannot determine native Rust host.' }
        if ($SkipBuild) {
            $metadataText = & cargo metadata --no-deps --locked --format-version 1
            if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
            $targetDirectory = ($metadataText | ConvertFrom-Json).target_directory
            $artifacts = @(foreach ($candidate in @(
                (Join-Path $targetDirectory "$hostTriple/release/banshee.exe"),
                (Join-Path $targetDirectory 'release/banshee.exe')
            )) {
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate; break }
            })
        } else {
            $buildOutput = & cargo build --release --locked --bin banshee --target $hostTriple --message-format=json-render-diagnostics
            if ($LASTEXITCODE -ne 0) { throw 'Cargo build failed; see diagnostics above.' }
            $artifacts = @($buildOutput | ForEach-Object {
                $event = $_ | ConvertFrom-Json
                if ($event.reason -eq 'compiler-artifact' -and $event.target.name -eq 'banshee' -and
                    'bin' -in $event.target.kind -and $event.executable) { $event.executable }
            })
        }
        if ($artifacts.Count -ne 1) { throw 'No local release binary; run installer without -SkipBuild.' }
        $binary = $artifacts[0]
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Built executable missing: $binary" }
        & $binary --version | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Local binary does not run on this host; rebuild without -SkipBuild.' }
    } finally { Pop-Location }
    [IO.Directory]::CreateDirectory($binDirectory) | Out-Null
    $stage = Join-Path $binDirectory ".banshee-install-$([guid]::NewGuid()).tmp"
    [IO.File]::Copy($binary, $stage, $false)
    Assert-Destination
    # Same-directory rename publishes a complete file; default mode cannot overwrite a racing writer.
    [IO.File]::Move($stage, $destination, [bool]$Force)
    Write-Output "Installed banshee to $destination"
    Write-Output "Add $binDirectory to PATH, then run: banshee --help"
} catch {
    [Console]::Error.WriteLine("error: $($_.Exception.Message)")
    exit 2
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Force }
}
