# Builds the single-file browser page: dist/web/banshee.html with the
# WebAssembly module embedded. Runs on Windows PowerShell 5.1 and PowerShell 7.
# Requires: rustup target add wasm32-unknown-unknown
[CmdletBinding()]
param(
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'dist/web' }
Push-Location (Join-Path $repoRoot 'web')
try {
    & cargo build --locked --release --target wasm32-unknown-unknown
    if ($LASTEXITCODE -ne 0) { throw 'WebAssembly build failed.' }
} finally {
    Pop-Location
}
$wasmPath = Join-Path $repoRoot 'web/target/wasm32-unknown-unknown/release/banshee_web.wasm'
$wasm = [System.IO.File]::ReadAllBytes($wasmPath)
if ($wasm.Length -lt 8 -or $wasm[0] -ne 0 -or $wasm[1] -ne 0x61 -or $wasm[2] -ne 0x73 -or $wasm[3] -ne 0x6D) {
    throw "Not a WebAssembly module: $wasmPath"
}
$metadata = & cargo metadata --no-deps --format-version 1 --locked --manifest-path (Join-Path $repoRoot 'Cargo.toml') | ConvertFrom-Json
$version = ($metadata.packages | Where-Object name -EQ 'banshee').version
$template = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'web/index.template.html'))
$page = $template.Replace('@VERSION@', $version).Replace('@WASM_BASE64@', [Convert]::ToBase64String($wasm))
if ($page.Contains('@WASM_BASE64@') -or $page.Contains('@VERSION@')) { throw 'Unfilled template placeholder.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$target = Join-Path $OutputDirectory 'banshee.html'
[System.IO.File]::WriteAllText($target, $page, (New-Object System.Text.UTF8Encoding($false)))
$digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "Built $target ($([math]::Round((Get-Item $target).Length / 1MB, 1)) MiB, sha256 $digest)"
