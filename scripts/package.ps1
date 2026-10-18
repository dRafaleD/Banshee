# Requires PowerShell 7; run from the repository root after a release build.
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$SbomPath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
    $metadataText = & cargo metadata --no-deps --format-version 1 --locked
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $metadata = $metadataText | ConvertFrom-Json
    $package = $metadata.packages | Where-Object name -EQ 'banshee'
    $hostText = & rustc -vV
    if ($LASTEXITCODE -ne 0) { throw 'Rust host detection failed.' }
    $triple = ($hostText | Where-Object { $_ -match '^host: ' }) -replace '^host: ', ''
    if ($triple -notin @('x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu',
        'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin')) {
        throw "Unsupported packaging host: $triple"
    }
    $executable = if ($IsWindows) { 'banshee.exe' } else { 'banshee' }
    $binary = Join-Path $metadata.target_directory "release/$executable"
    $versionText = & $binary --version
    if ($LASTEXITCODE -ne 0 -or $versionText -ne "banshee $($package.version)") {
        throw 'Release binary does not match Cargo package version.'
    }
    $name = "banshee-$($package.version)-$triple"
    $output = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $repoRoot 'dist' }
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    $extension = if ($IsWindows) { 'zip' } else { 'tar.gz' }
    $archive = Join-Path $output "$name.$extension"
    if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
    # Retain this uniquely allocated work directory for inspection on failure.
    $work = Join-Path $metadata.target_directory "package-$([guid]::NewGuid())"
    $stage = Join-Path $work $name
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -LiteralPath $binary -Destination $stage
    if ($SbomPath) {
        $sbom = Get-Content -LiteralPath $SbomPath -Raw | ConvertFrom-Json
        if ($sbom.bomFormat -ne 'CycloneDX' -or $sbom.specVersion -ne '1.5' -or $sbom.metadata.component.name -ne 'banshee' -or
            $sbom.metadata.component.version -ne $package.version -or $sbom.components.Count -eq 0) {
            throw 'SBOM must describe this Banshee version and contain dependencies.'
        }
        $targets = @($sbom.metadata.properties | Where-Object name -EQ 'cdx:rustc:sbom:target:triple')
        if ($targets.Count -ne 1 -or $targets[0].value -ne $triple) {
            throw 'SBOM target must match the packaging host.'
        }
        Copy-Item -LiteralPath $SbomPath -Destination (Join-Path $stage 'banshee.sbom.json')
        Copy-Item -LiteralPath $SbomPath -Destination (Join-Path $output "$name.sbom.json")
    }
    foreach ($document in @('README.md', 'README.tr.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'ROADMAP.md')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $document) -Destination $stage
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'examples') -Destination $stage -Recurse
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs') -Destination $stage -Recurse
    New-Item -ItemType Directory -Path (Join-Path $stage 'assets') | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot 'assets/banshee-banner-green-animated-v3.gif') -Destination (Join-Path $stage 'assets')
    $completions = Join-Path $stage 'completions'
    New-Item -ItemType Directory -Path $completions | Out-Null
    foreach ($shell in @('bash', 'zsh', 'fish', 'powershell', 'elvish')) {
        $completionText = & $binary completions $shell
        if ($LASTEXITCODE -ne 0) { throw "Completion generation failed: $shell" }
        $completionText | Set-Content -LiteralPath (Join-Path $completions "banshee.$shell") -Encoding utf8NoBOM
    }
    $manual = & $binary manpage
    if ($LASTEXITCODE -ne 0) { throw 'Manpage generation failed.' }
    $manual | Set-Content -LiteralPath (Join-Path $stage 'banshee.1') -Encoding utf8NoBOM
    if ($IsWindows) {
        Compress-Archive -LiteralPath $stage -DestinationPath $archive
    } else {
        & tar -czf $archive -C $work $name
        if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
    }
    $unpack = Join-Path $work 'unpacked'
    New-Item -ItemType Directory -Path $unpack | Out-Null
    if ($IsWindows) {
        Expand-Archive -LiteralPath $archive -DestinationPath $unpack
    } else {
        & tar -xzf $archive -C $unpack
        if ($LASTEXITCODE -ne 0) { throw 'Archive extraction failed.' }
    }
    $shipped = Join-Path $unpack "$name/$executable"
    $decoded = & $shipped decode base64 aGVsbG8=
    if ($LASTEXITCODE -ne 0 -or $decoded -ne 'hello') { throw 'Packaged decoder smoke test failed.' }
    & $shipped rules validate (Join-Path $unpack "$name/examples/rules.toml")
    if ($LASTEXITCODE -ne 0) { throw 'Packaged rules validation failed.' }
    $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$digest  $name.$extension" | Set-Content -LiteralPath "$archive.sha256" -Encoding utf8NoBOM
    Write-Output "Verified package: $archive"
} finally {
    Pop-Location
}
