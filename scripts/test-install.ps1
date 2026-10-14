#Requires -Version 7.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Run scripts/test-install.sh on Linux.' }
$installer = Join-Path $PSScriptRoot 'install.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) "banshee-install-test-$([guid]::NewGuid())"
[IO.Directory]::CreateDirectory($work) | Out-Null
$oldTarget = $env:CARGO_TARGET_DIR
$oldPrefix = $env:PREFIX
$oldBuildTarget = $env:CARGO_BUILD_TARGET
function Invoke-Installer([int]$Expected, [string[]]$Options) {
    $output = & pwsh -NoProfile -File $installer -SkipBuild @Options 2>&1
    if ($LASTEXITCODE -ne $Expected) { throw "Installer expected $Expected, got ${LASTEXITCODE}: $output" }
    return ($output -join "`n")
}
function Invoke-Cli([int]$Expected, [string[]]$Options) {
    $output = & $script:binary @Options 2>&1
    if ($LASTEXITCODE -ne $Expected) { throw "CLI expected $Expected, got ${LASTEXITCODE}: $output" }
    return ($output -join "`n")
}
Push-Location $work
try {
    if ((Invoke-Installer 0 @('-Help')) -notmatch 'Usage:') { throw 'Missing installer help.' }
    Invoke-Installer 1 @('-UnknownOption') | Out-Null # PowerShell parameter binding exit status
    Invoke-Installer 1 @('-Prefix') | Out-Null
    Invoke-Installer 2 @('-Prefix', '') | Out-Null
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try {
        $metadataText = & cargo metadata --no-deps --locked --format-version 1
        if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
        $targetDirectory = ($metadataText | ConvertFrom-Json).target_directory
        $hostText = & rustc -vV
        if ($LASTEXITCODE -ne 0) { throw 'Rust host detection failed.' }
        $hostTriple = ($hostText | Where-Object { $_ -match '^host: ' }) -replace '^host: ', ''
        $sourceBinary = @(
            (Join-Path $targetDirectory "$hostTriple/release/banshee.exe"),
            (Join-Path $targetDirectory 'release/banshee.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $sourceBinary) {
            & cargo build --release --locked --bin banshee --target $hostTriple
            if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
            $sourceBinary = Join-Path $targetDirectory "$hostTriple/release/banshee.exe"
        }
    } finally { Pop-Location }
    # Override any cross-build default and exercise a nonstandard Cargo target directory.
    $env:CARGO_TARGET_DIR = Join-Path $work 'cargo target'
    $env:CARGO_BUILD_TARGET = 'unavailable-test-target'
    $env:PREFIX = Join-Path $work 'local prefix'
    Invoke-Installer 2 @() | Out-Null # SkipBuild must fail when the selected target directory is empty.
    $seedDirectory = Join-Path $env:CARGO_TARGET_DIR "$hostTriple/release"
    [IO.Directory]::CreateDirectory($seedDirectory) | Out-Null
    Copy-Item -LiteralPath $sourceBinary -Destination (Join-Path $seedDirectory 'banshee.exe')
    Invoke-Installer 0 @() | Out-Null
    $script:binary = Join-Path $env:PREFIX 'bin/banshee.exe'
    $digest = (Get-FileHash -LiteralPath $binary).Hash
    if (-not (Get-ChildItem -LiteralPath $env:CARGO_TARGET_DIR -Recurse -Filter banshee.exe)) {
        throw 'Cargo target-directory override was not respected.'
    }
    Invoke-Installer 2 @() | Out-Null
    if ((Get-FileHash -LiteralPath $binary).Hash -ne $digest) { throw 'Refused install changed binary.' }
    [IO.File]::WriteAllText($binary, 'preserve this sentinel')
    Invoke-Installer 2 @() | Out-Null
    if ([IO.File]::ReadAllText($binary) -ne 'preserve this sentinel') { throw 'Existing file was overwritten.' }
    Invoke-Installer 0 @('-Force') | Out-Null
    if ((Get-FileHash -LiteralPath $binary).Hash -ne $digest) { throw 'Force did not install built binary.' }
    Invoke-Installer 0 @('-Prefix', 'relative prefix') | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $work 'relative prefix/bin/banshee.exe'))) {
        throw 'Relative prefix did not use caller directory.'
    }
    [IO.Directory]::CreateDirectory((Join-Path $work 'directory prefix/bin/banshee.exe')) | Out-Null
    Invoke-Installer 2 @('-Prefix', (Join-Path $work 'directory prefix'), '-Force') | Out-Null
    $junctionPrefix = Join-Path $work 'junction prefix'
    [IO.Directory]::CreateDirectory($junctionPrefix) | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $junctionPrefix 'bin') -Target (Join-Path $env:PREFIX 'bin') | Out-Null
    Invoke-Installer 2 @('-Prefix', $junctionPrefix, '-Force') | Out-Null
    $nativeTargetDirectory = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = Join-Path $work 'flat cargo target'
    [IO.Directory]::CreateDirectory((Join-Path $env:CARGO_TARGET_DIR 'release')) | Out-Null
    Copy-Item -LiteralPath $sourceBinary -Destination (Join-Path $env:CARGO_TARGET_DIR 'release/banshee.exe')
    Invoke-Installer 0 @('-Prefix', (Join-Path $work 'flat prefix')) | Out-Null
    $env:CARGO_TARGET_DIR = $nativeTargetDirectory
    if (Get-ChildItem -LiteralPath (Join-Path $env:PREFIX 'bin') -Force -Filter '.banshee-install-*') {
        throw 'Installer left staging files behind.'
    }
    if ((Invoke-Cli 0 @('--help')) -notmatch 'QUICK START:') { throw 'Missing CLI help.' }
    Invoke-Cli 0 @('--version') | Out-Null
    Invoke-Cli 0 @('extract', '--help') | Out-Null
    if ((Invoke-Cli 0 @('decode', 'base64', 'aGVsbG8=')) -ne 'hello') { throw 'Decoder example failed.' }
    if ((Invoke-Cli 0 @('recipe', 'base64|url', 'aGVsbG8lMjB3b3JsZA==', '--raw')) -ne 'hello world') {
        throw 'Recipe example failed.'
    }
    $stdinResult = 'aGVsbG8=' | & $binary decode base64
    if ($LASTEXITCODE -ne 0 -or $stdinResult -ne 'hello') { throw 'stdin example failed.' }
    Invoke-Cli 0 @('whatis', 'aGVsbG8=') | Out-Null
    Invoke-Cli 0 @('hash', 'calculate', 'hello', '--algorithm', 'sha256') | Out-Null
    Invoke-Cli 0 @('timestamp', 'to-human', '1704067200') | Out-Null
    Invoke-Cli 0 @('extract', 'https://example.com 192.0.2.1', '--defang') | Out-Null
    Invoke-Cli 1 @('--fail-on-findings', 'extract', '192.0.2.1') | Out-Null
    Invoke-Cli 2 @('unknown-command') | Out-Null
    [IO.File]::WriteAllText((Join-Path $work 'sample.txt'), 'hello')
    Invoke-Cli 0 @('report', 'sample.txt', '--format', 'json', '--output', 'report.json') | Out-Null
    Get-Content -LiteralPath 'report.json' -Raw | ConvertFrom-Json | Out-Null
    Invoke-Cli 2 @('report', 'sample.txt', '--format', 'json', '--output', 'report.json') | Out-Null
    Invoke-Cli 0 @('report', 'sample.txt', '--format', 'json', '--output', 'report.json', '--force') | Out-Null
    Invoke-Cli 0 @('evidence', 'create', 'sample.txt', '--output', 'case-evidence') | Out-Null
    Invoke-Cli 0 @('evidence', 'verify', 'case-evidence') | Out-Null
    Invoke-Cli 0 @('diff', 'report.json', 'report.json') | Out-Null
    foreach ($shell in @('bash', 'zsh', 'fish', 'powershell', 'elvish')) {
        if (-not (Invoke-Cli 0 @('completions', $shell))) { throw "Empty completions: $shell" }
    }
    Invoke-Cli 0 @('completions', 'powershell', '--output', 'banshee-completion.ps1') | Out-Null
    . (Join-Path $work 'banshee-completion.ps1')
    Invoke-Cli 0 @('completions', 'bash', '--output', 'banshee-completion.bash') | Out-Null
    if (-not (Invoke-Cli 0 @('manpage'))) { throw 'Empty manual.' }
    Invoke-Cli 0 @('manpage', '--output', 'banshee.1') | Out-Null
    if ((Get-Item -LiteralPath 'banshee.1').Length -eq 0) { throw 'Empty manual file.' }
    Write-Output 'PASS: isolated Windows installation, overwrite policy, Cargo target override, help, errors and daily examples.'
} finally {
    Pop-Location
    $env:CARGO_TARGET_DIR = $oldTarget
    $env:PREFIX = $oldPrefix
    $env:CARGO_BUILD_TARGET = $oldBuildTarget
    # Keep the unique test directory and build cache for inspection; never touch a user prefix.
    Write-Output "Test artifacts: $work"
}
