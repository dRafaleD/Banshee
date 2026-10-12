# Requires PowerShell 7. Fills packaging/ templates from verified release checksums.
# It only writes local files under the output directory; submitting the results to
# Scoop, Homebrew or winget is a separate, manual and reviewed step.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$Dist = 'dist',
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "Invalid version: $Version" }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Dist 'packaging' }

$triples = @('x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
    'x86_64-apple-darwin', 'aarch64-apple-darwin')
$hashes = @{}
foreach ($triple in $triples) {
    $extension = if ($triple -like '*windows*') { 'zip' } else { 'tar.gz' }
    $archive = "banshee-$Version-$triple.$extension"
    $sidecar = Join-Path $Dist "$archive.sha256"
    if (-not (Test-Path -LiteralPath $sidecar)) { continue }
    $fields = (Get-Content -LiteralPath $sidecar -Raw).Trim() -split '\s+'
    if ($fields.Count -ne 2 -or $fields[1] -ne $archive -or $fields[0] -notmatch '^[0-9a-f]{64}$') {
        throw "Unexpected checksum sidecar: $sidecar"
    }
    $archivePath = Join-Path $Dist $archive
    if (Test-Path -LiteralPath $archivePath) {
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $fields[0]) { throw "Checksum mismatch for $archive" }
    }
    $hashes[$triple] = $fields[0]
}

function Expand-Template([string]$Template, [string[]]$Required) {
    foreach ($triple in $Required) {
        if (-not $hashes.ContainsKey($triple)) { return $null }
    }
    $text = (Get-Content -LiteralPath (Join-Path $repoRoot $Template) -Raw).Replace('@VERSION@', $Version)
    foreach ($triple in $hashes.Keys) {
        $text = $text.Replace("@SHA256_$triple@", $hashes[$triple])
        $text = $text.Replace("@SHA256UPPER_$triple@", $hashes[$triple].ToUpperInvariant())
    }
    if ($text -match '@[A-Z0-9_.-]+@') { throw "Unfilled placeholder in $Template" }
    return $text
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$outputs = @(
    @{ Template = 'packaging/scoop/banshee.json.template'; Name = 'scoop/banshee.json'
        Required = @('x86_64-pc-windows-msvc') },
    @{ Template = 'packaging/homebrew/banshee.rb.template'; Name = 'homebrew/banshee.rb'
        Required = @('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin') },
    @{ Template = 'packaging/winget/dRafaleD.Banshee.yaml.template'; Name = 'winget/dRafaleD.Banshee.yaml'
        Required = @('x86_64-pc-windows-msvc') },
    @{ Template = 'packaging/winget/dRafaleD.Banshee.installer.yaml.template'; Name = 'winget/dRafaleD.Banshee.installer.yaml'
        Required = @('x86_64-pc-windows-msvc') },
    @{ Template = 'packaging/winget/dRafaleD.Banshee.locale.en-US.yaml.template'; Name = 'winget/dRafaleD.Banshee.locale.en-US.yaml'
        Required = @('x86_64-pc-windows-msvc') }
)
foreach ($item in $outputs) {
    $text = Expand-Template $item.Template $item.Required
    if ($null -eq $text) {
        Write-Warning "Skipping $($item.Name): checksums missing for $($item.Required -join ', ')"
        continue
    }
    $target = Join-Path $OutputDirectory $item.Name
    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    $text | Set-Content -LiteralPath $target -Encoding utf8NoBOM -NoNewline
    Write-Output "Rendered $target"
}
