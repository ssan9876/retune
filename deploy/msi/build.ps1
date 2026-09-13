<#
.SYNOPSIS
  Builds the Retune agent and packages it as an MSI.

.DESCRIPTION
  Requires the WiX 5 CLI: dotnet tool install --global wix --version 5.0.2
  The MSI is unsigned, so a manual install shows a SmartScreen warning;
  deployment through GPO or a management tool does not care.
#>
param(
  [string]$Version = "0.1.0",
  [string]$OutDir = "bin"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null

$agentExe = Join-Path $out "retune-agent.exe"
$msi = Join-Path $out "retune-agent.msi"

Write-Host "Building the agent for windows/amd64..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
& go build -trimpath -o $agentExe (Join-Path $root "cmd/retune-agent")
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

Write-Host "Building $msi (version $Version)..."
& wix build -arch x64 `
  -ext WixToolset.Util.wixext `
  -d Version=$Version `
  -d AgentExe=$agentExe `
  (Join-Path $PSScriptRoot "Package.wxs") `
  -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "Built $msi"
