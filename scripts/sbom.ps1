# Generate a target-specific production dependency inventory without changing Cargo.lock.
[CmdletBinding()]
param([string]$OutputPath = 'target/banshee.sbom.json')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
    $lockBefore = (Get-FileHash -LiteralPath 'Cargo.lock' -Algorithm SHA256).Hash
    $hostText = & rustc -vV
    if ($LASTEXITCODE -ne 0) { throw 'Rust host detection failed.' }
    $triple = ($hostText | Where-Object { $_ -match '^host: ' }) -replace '^host: ', ''
    # cargo-cyclonedx appends .json to this basename beside Cargo.toml.
    & cargo cyclonedx --format json --spec-version 1.5 --target $triple --override-filename banshee.cyclonedx
    if ($LASTEXITCODE -ne 0) { throw 'SBOM generation failed.' }
    if ((Get-FileHash -LiteralPath 'Cargo.lock' -Algorithm SHA256).Hash -ne $lockBefore) {
        throw 'SBOM generation changed Cargo.lock; review dependencies before packaging.'
    }
    $generated = Join-Path $repoRoot 'banshee.cyclonedx.json'
    $sbom = Get-Content -LiteralPath $generated -Raw | ConvertFrom-Json
    if ($sbom.bomFormat -ne 'CycloneDX' -or $sbom.specVersion -ne '1.5' -or
        $sbom.metadata.component.name -ne 'banshee' -or $sbom.components.Count -eq 0) {
        throw 'Generated SBOM does not describe Banshee dependencies.'
    }
    $output = [IO.Path]::GetFullPath($OutputPath)
    New-Item -ItemType Directory -Force -Path (Split-Path $output -Parent) | Out-Null
    Copy-Item -LiteralPath $generated -Destination $output
    Write-Output "Verified CycloneDX inventory: $output ($($sbom.components.Count) components; $triple)"
} finally { Pop-Location }
