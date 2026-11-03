#requires -version 5.1
[CmdletBinding()]
param(
    [string]$PacUrl = "http://proxy.example.internal:8081/proxy.pac"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SourceDir = $PSScriptRoot
$Controller = Join-Path $SourceDir "Proxy-Control-Endpoint.ps1"
$GuiSource = Join-Path $SourceDir "Proxy-Control.exe"

$InstallDir = Join-Path $env:ProgramFiles "Security Web Gateway\Proxy Control"
$GuiDestination = Join-Path $InstallDir "Proxy-Control.exe"
$StartMenuDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Proxy Control"
$ShortcutPath = Join-Path $StartMenuDir "Proxy Control.lnk"

if (-not (Test-Path $Controller)) {
    throw "Controller was not found: $Controller"
}

if (-not (Test-Path $GuiSource)) {
    throw "GUI executable was not found: $GuiSource"
}

# Install/upgrade the machine-wide policy and controller first.
$p = Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$Controller`"",
        "-Mode", "Install",
        "-PacUrl", "`"$PacUrl`""
    ) `
    -Wait `
    -PassThru `
    -WindowStyle Hidden

if ($p.ExitCode -ne 0) {
    throw "Proxy Control controller installation failed with exit code $($p.ExitCode)."
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $GuiSource -Destination $GuiDestination -Force

# Remove any legacy Start Menu entries and create one clean program shortcut.
if (Test-Path $StartMenuDir) {
    Remove-Item -Path $StartMenuDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $GuiDestination
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Description = "Security Web Gateway Endpoint Control"
$Shortcut.Save()

# Reinforce endpoint ACLs after copying the GUI.
& icacls.exe $InstallDir /inheritance:r | Out-Null
& icacls.exe $InstallDir /grant:r `
    "*S-1-5-18:(OI)(CI)F" `
    "*S-1-5-32-544:(OI)(CI)F" `
    "*S-1-5-32-545:(OI)(CI)RX" | Out-Null

Write-Host "Proxy Control v1.3.1 installed successfully."
Write-Host "Start Menu: Proxy Control -> Proxy Control"
exit 0
