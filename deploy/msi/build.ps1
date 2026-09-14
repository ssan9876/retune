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
  [string]$OutDir = "bin",
  # Path to release.key, or env:NAME. When set, the build is signed and the
  # .sig is written beside the MSI.
  [string]$ReleaseKey = "",
  # Comma-separated public keys the agent embeds. Required with -ReleaseKey.
  [string]$TrustedKeys = ""
)

$ErrorActionPreference = "Stop"

if ($ReleaseKey -ne "" -and $TrustedKeys -eq "") { throw "-TrustedKeys is required with -ReleaseKey" }

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null

$agentExe = Join-Path $out "retune-agent.exe"
$msi = Join-Path $out "retune-agent.msi"

Write-Host "Building the agent for windows/amd64..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
& go build -trimpath `
  -ldflags "-X retune/internal/agent/facts.AgentVersion=$Version -X retune/internal/agent/facts.TrustedKeysRaw=$TrustedKeys" `
  -o $agentExe (Join-Path $root "cmd/retune-agent")
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

if ($ReleaseKey -ne "") {
  Write-Host "Signing the agent..."
  & go run ./cmd/retune-sign sign --key $ReleaseKey --version $Version $agentExe
  if ($LASTEXITCODE -ne 0) { throw "signing failed" }
} else {
  Write-Host "The agent is unsigned and trusts no release key (pass -ReleaseKey and -TrustedKeys)."
}

Write-Host "Building $msi (version $Version)..."
& wix build -arch x64 `
  -ext WixToolset.Util.wixext `
  -d Version=$Version `
  -d AgentExe=$agentExe `
  (Join-Path $PSScriptRoot "Package.wxs") `
  -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "Built $msi"
