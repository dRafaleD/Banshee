# Verify that a package cannot silently contain the wrong dependency inventory.
#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SbomPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Get-Content -LiteralPath $SbomPath -Raw
$work = Join-Path ([IO.Path]::GetTempPath()) "banshee-package-test-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $work | Out-Null
foreach ($case in @('wrong-version', 'wrong-package', 'wrong-target', 'missing-target', 'invalid-json')) {
    $inventory = $source | ConvertFrom-Json
    switch ($case) {
        'wrong-version' { $inventory.metadata.component.version = '999.0.0' }
        'wrong-package' { $inventory.metadata.component.name = 'not-banshee' }
        'wrong-target' {
            ($inventory.metadata.properties | Where-Object name -EQ 'cdx:rustc:sbom:target:triple').value = 'wrong-host'
        }
        'missing-target' { $inventory.metadata.properties = @() }
    }
    $inputPath = Join-Path $work "$case.json"
    $text = if ($case -eq 'invalid-json') { '{not-json' } else { $inventory | ConvertTo-Json -Depth 100 }
    $text | Set-Content -LiteralPath $inputPath -Encoding utf8NoBOM
    $outputPath = Join-Path $work $case
    $diagnostics = & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'package.ps1') -SbomPath $inputPath -OutputDirectory $outputPath 2>&1
    if ($LASTEXITCODE -eq 0) { throw "Invalid inventory was accepted: $case" }
    if (@(Get-ChildItem -LiteralPath $outputPath -File -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "Rejected inventory left deliverable files: $case"
    }
    if ($case -in @('wrong-target', 'missing-target') -and ($diagnostics -join '') -notmatch 'SBOM target') {
        throw "Target rejection was not explicit: $case"
    }
}
Write-Output 'PASS: invalid JSON, wrong package/version and incompatible SBOM targets rejected.'
Write-Output "Test artifacts: $work"
exit 0
