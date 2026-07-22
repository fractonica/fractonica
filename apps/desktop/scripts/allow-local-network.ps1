[CmdletBinding()]
param(
  [string]$NodePath
)

$ErrorActionPreference = "Stop"
$baseRuleName = "Fractonica Local Network (Private)"

if ($env:OS -ne "Windows_NT") {
  throw "Windows Firewall configuration is available only on Windows."
}

if ([string]::IsNullOrWhiteSpace($NodePath)) {
  $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
  $candidates = @(
    (Join-Path $repositoryRoot "target\debug\fractonica-node.exe"),
    (Join-Path $repositoryRoot "target\release\fractonica-node.exe")
  )
  $NodePath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

if ([string]::IsNullOrWhiteSpace($NodePath) -or -not (Test-Path -LiteralPath $NodePath -PathType Leaf)) {
  throw "Could not find fractonica-node.exe. Start or build the desktop app first."
}

$NodePath = (Resolve-Path -LiteralPath $NodePath).Path
$developmentBuild = $NodePath -match "[\\/]target[\\/](debug|release)[\\/]fractonica-node\.exe$"
$ruleName = if ($developmentBuild) { "$baseRuleName [Development]" } else { $baseRuleName }

# `Get-NetFirewallRule` requires elevation on some Windows installations, but
# netsh can check an exact rule name without elevation. Installed and
# development binaries use separate names so a rule for one path cannot mask
# a missing rule for the other.
& netsh.exe advfirewall firewall show rule name="$ruleName" | Out-Null
if ($LASTEXITCODE -eq 0) {
  Write-Output "Fractonica already has the required Private-network firewall rule."
  return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
  $arguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "`"$PSCommandPath`"",
    "-NodePath",
    "`"$NodePath`""
  )
  $process = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "The elevated Windows Firewall configuration failed with exit code $($process.ExitCode)."
  }
  return
}

& netsh.exe advfirewall firewall delete rule name="$ruleName" | Out-Null
& netsh.exe advfirewall firewall add rule `
  name="$ruleName" `
  dir=in `
  action=allow `
  program="$NodePath" `
  enable=yes `
  profile=private `
  protocol=TCP `
  localport=8789 `
  edge=no | Out-Null

if ($LASTEXITCODE -ne 0) {
  throw "Windows Firewall rejected the Fractonica local-network rule."
}

Write-Output "Allowed Fractonica node inbound on TCP 8789 for Private networks: $NodePath"
