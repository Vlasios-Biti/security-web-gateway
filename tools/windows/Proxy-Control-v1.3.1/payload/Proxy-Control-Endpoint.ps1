#requires -version 5.1
<#
.SYNOPSIS
  Proxy Control
.DESCRIPTION
  Machine-wide PAC configuration for Windows 10/11.
  Enable/Disable/Install/Uninstall require Administrator elevation.
  Standard users can read Status but cannot change the configuration.

  IMPORTANT:
  - This controls Windows/WinINet-style system proxy configuration.
  - Applications with their own proxy/network stack may ignore Windows proxy settings.
  - Hard anti-bypass enforcement should additionally be done at the network/firewall layer.
#>

[CmdletBinding()]
param(
    [ValidateSet("Install","Enable","Disable","Status","Uninstall")]
    [string]$Mode = "Status",

    [ValidatePattern('^https?://')]
    [string]$PacUrl = "",

    [switch]$ElevatedChild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProductName = "Proxy Control"
$ProductVersion = "1.3.1"
$DefaultPacUrl = "http://proxy.example.internal:8081/proxy.pac"

$InstallDir = Join-Path $env:ProgramFiles "Security Web Gateway\Proxy Control"
$InstalledScript = Join-Path $InstallDir "Proxy-Control-Endpoint.ps1"

$StateDir = Join-Path $env:ProgramData "Security Web Gateway\Proxy Control"
$LogDir = Join-Path $StateDir "Logs"
$BackupFile = Join-Path $StateDir "preinstall-backup.json"
$LogFile = Join-Path $LogDir "control.log"

$StartMenuDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Proxy Control"

$PolicyInternetSettings = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$MachineInternetSettings = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
$ProxyControlPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel"
$WinHttpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
$ProductKey = "HKLM:\SOFTWARE\SecurityWebGateway\ProxyControl"
$script:TrustedStateReady = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    if ($Mode -eq "Status") { return }
    if (Test-IsAdministrator) { return }

    Write-Host "Administrator privileges are required for mode: $Mode" -ForegroundColor Yellow
    Write-Host "Windows UAC will request Administrator credentials." -ForegroundColor Yellow

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-Mode", $Mode,
        "-PacUrl", "`"$PacUrl`"",
        "-ElevatedChild"
    )

    try {
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -Wait -PassThru
        exit $p.ExitCode
    }
    catch {
        Write-Error "Elevation was cancelled or failed. No configuration changes were made."
        exit 5
    }
}

function Ensure-Key {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    if (-not (Test-IsAdministrator) -or -not $script:TrustedStateReady) { return }

    Ensure-Key -Path "HKLM:\SOFTWARE\SecurityWebGateway"

    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $line = "{0} | {1} | {2} | {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ssK"), $env:COMPUTERNAME, ([Security.Principal.WindowsIdentity]::GetCurrent().Name), $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Set-Dword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-StringValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

function Remove-ValueIfPresent {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

function Get-RegistrySnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $result = [ordered]@{
        Path = $Path
        Name = $Name
        Exists = $false
        Kind = $null
        Value = $null
    }

    if (-not (Test-Path $Path)) {
        return [pscustomobject]$result
    }

    $item = Get-Item -Path $Path
    try {
        $value = $item.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = $item.GetValueKind($Name)
        $result.Exists = $true
        $result.Kind = $kind.ToString()
        $result.Value = $value
    }
    catch {
        # Value absent.
    }

    return [pscustomobject]$result
}

function Save-InitialBackup {
    if (Test-Path $BackupFile) {
        Write-Log "Initial backup already exists; preserving original backup."
        return
    }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    $targets = @(
        @($PolicyInternetSettings, "ProxySettingsPerUser"),
        @($PolicyInternetSettings, "AutoDetect"),
        @($MachineInternetSettings, "AutoConfigURL"),
        @($MachineInternetSettings, "ProxyEnable"),
        @($MachineInternetSettings, "AutoDetect"),
        @($MachineInternetSettings, "ProxyServer"),
        @($MachineInternetSettings, "ProxyOverride"),
        @($ProxyControlPolicy, "Proxy"),
        @($ProxyControlPolicy, "Autoconfig"),
        @($WinHttpKey, "DisableWpad")
    )

    $snapshots = foreach ($t in $targets) {
        Get-RegistrySnapshot -Path $t[0] -Name $t[1]
    }

    $backup = [ordered]@{
        Product = $ProductName
        Version = $ProductVersion
        CreatedAt = (Get-Date).ToString("o")
        Computer = $env:COMPUTERNAME
        Values = @($snapshots)
    }

    $backup | ConvertTo-Json -Depth 8 | Set-Content -Path $BackupFile -Encoding UTF8
    Write-Log "Saved pre-install registry backup."
}

function Convert-RegistryKindToPropertyType {
    param([string]$Kind)
    switch ($Kind) {
        "DWord"       { return "DWord" }
        "QWord"       { return "QWord" }
        "String"      { return "String" }
        "ExpandString"{ return "ExpandString" }
        "MultiString" { return "MultiString" }
        "Binary"      { return "Binary" }
        default       { return "String" }
    }
}

function Restore-InitialBackup {
    if (-not (Test-Path $BackupFile)) {
        Write-Warning "No pre-install backup was found. Only Security Web Gateway-owned policy values will be removed."
        Remove-ValueIfPresent $PolicyInternetSettings "ProxySettingsPerUser"
        Remove-ValueIfPresent $PolicyInternetSettings "AutoDetect"
        Remove-ValueIfPresent $ProxyControlPolicy "Proxy"
        Remove-ValueIfPresent $ProxyControlPolicy "Autoconfig"
        Remove-ValueIfPresent $WinHttpKey "DisableWpad"
        Remove-ValueIfPresent $MachineInternetSettings "AutoConfigURL"
        Set-Dword $MachineInternetSettings "ProxyEnable" 0
        return
    }

    $backup = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    Assert-BackupScope -Backup $backup

    foreach ($entry in $backup.Values) {
        if ($entry.Exists) {
            Ensure-Key $entry.Path
            $propertyType = Convert-RegistryKindToPropertyType $entry.Kind
            New-ItemProperty -Path $entry.Path -Name $entry.Name -PropertyType $propertyType -Value $entry.Value -Force | Out-Null
        }
        else {
            Remove-ValueIfPresent -Path $entry.Path -Name $entry.Name
        }
    }

    Write-Log "Restored pre-install registry values."
}

function Notify-InternetSettingsChanged {
    $signature = @'
using System;
using System.Runtime.InteropServices;

public static class SecurityWebGatewayWinInetNotify
{
    [DllImport("wininet.dll", SetLastError=true)]
    public static extern bool InternetSetOption(
        IntPtr hInternet,
        int dwOption,
        IntPtr lpBuffer,
        int dwBufferLength
    );
}
'@

    if (-not ("SecurityWebGatewayWinInetNotify" -as [type])) {
        Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue
    }

    # INTERNET_OPTION_SETTINGS_CHANGED = 39
    # INTERNET_OPTION_REFRESH          = 37
    [SecurityWebGatewayWinInetNotify]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [SecurityWebGatewayWinInetNotify]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
}

function Set-AdminOnlyLock {
    # Machine-wide proxy settings rather than per-user.
    Set-Dword $PolicyInternetSettings "ProxySettingsPerUser" 0

    # Prevent standard users from changing proxy and automatic configuration settings.
    Set-Dword $ProxyControlPolicy "Proxy" 1
    Set-Dword $ProxyControlPolicy "Autoconfig" 1

    # Explicitly suppress automatic discovery in the machine policy/config.
    Set-Dword $PolicyInternetSettings "AutoDetect" 0
    Set-Dword $MachineInternetSettings "AutoDetect" 0

    # Disable WPAD for WinHTTP. Explicit PAC URL is managed by Security Web Gateway instead.
    Set-Dword $WinHttpKey "DisableWpad" 1
}

function Set-ProductState {
    param(
        [Parameter(Mandatory)][ValidateSet("Enabled","Disabled")][string]$State,
        [string]$ConfiguredPacUrl
    )

    Ensure-Key $ProductKey
    Set-StringValue $ProductKey "ProductVersion" $ProductVersion
    Set-StringValue $ProductKey "State" $State
    if ($ConfiguredPacUrl) {
        Set-StringValue $ProductKey "PacUrl" $ConfiguredPacUrl
    } else {
        Remove-ValueIfPresent $ProductKey "PacUrl"
    }
    Set-StringValue $ProductKey "LastChangedAt" (Get-Date).ToString("o")
    Set-StringValue $ProductKey "LastChangedBy" ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
}


function Resolve-PacUrl {
    if (-not [string]::IsNullOrWhiteSpace($PacUrl)) { return $PacUrl }
    try {
        $saved = Get-ItemPropertyValue -Path $ProductKey -Name "PacUrl" -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace([string]$saved)) { return [string]$saved }
    } catch {}
    return $DefaultPacUrl
}

function Test-Pac {
    param([Parameter(Mandatory)][string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 -Method Get
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
            return [pscustomobject]@{ Reachable=$true; Detail=("HTTP {0}" -f $response.StatusCode) }
        }
        return [pscustomobject]@{ Reachable=$false; Detail=("HTTP {0}" -f $response.StatusCode) }
    }
    catch {
        return [pscustomobject]@{ Reachable=$false; Detail=$_.Exception.Message }
    }
}

function Enable-SecurityWebGateway {
    $effectivePacUrl = Resolve-PacUrl
    Save-InitialBackup
    Set-AdminOnlyLock

    # PAC controls proxy selection.
    # Manual proxy is kept OFF.
    Set-Dword $MachineInternetSettings "ProxyEnable" 0
    Set-StringValue $MachineInternetSettings "AutoConfigURL" $effectivePacUrl

    Set-ProductState -State "Enabled" -ConfiguredPacUrl $effectivePacUrl
    Notify-InternetSettingsChanged

    $pacTest = Test-Pac -Url $effectivePacUrl

    Write-Log "SWG enabled. PAC=$effectivePacUrl PACReachable=$($pacTest.Reachable) Detail=$($pacTest.Detail)"

    Write-Host ""
    Write-Host "Proxy Control: ENABLED" -ForegroundColor Green
    Write-Host "PAC URL: $effectivePacUrl"
    Write-Host "Proxy settings: machine-wide and locked for standard users."
    if ($pacTest.Reachable) {
        Write-Host "PAC reachability: OK ($($pacTest.Detail))" -ForegroundColor Green
    } else {
        Write-Warning "PAC was not reachable during this test: $($pacTest.Detail)"
        Write-Warning "The configuration is still installed. Verify server/network reachability."
    }
}

function Disable-SecurityWebGateway {
    Save-InitialBackup

    # Keep the admin-only policy lock active even while SWG is disabled.
    Set-AdminOnlyLock

    # DIRECT state: no PAC and no manual proxy.
    Remove-ValueIfPresent $MachineInternetSettings "AutoConfigURL"
    Set-Dword $MachineInternetSettings "ProxyEnable" 0

    Set-ProductState -State "Disabled"
    Notify-InternetSettingsChanged

    Write-Log "SWG disabled by administrator. Windows system proxy is DIRECT and settings remain locked."

    Write-Host ""
    Write-Host "Proxy Control: DISABLED" -ForegroundColor Yellow
    Write-Host "Windows system proxy state: DIRECT"
    Write-Host "Proxy settings remain locked for standard users."
}

function New-ControlCmd {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$ModeName
    )

    $path = Join-Path $StartMenuDir $FileName
    $content = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$InstalledScript" -Mode $ModeName
"@
    Set-Content -Path $path -Value $content -Encoding ASCII
}

function Assert-BackupScope {
    param([Parameter(Mandatory)]$Backup)
    $allowed = @(
        "$PolicyInternetSettings|ProxySettingsPerUser", "$PolicyInternetSettings|AutoDetect",
        "$MachineInternetSettings|AutoConfigURL", "$MachineInternetSettings|ProxyEnable",
        "$MachineInternetSettings|AutoDetect", "$MachineInternetSettings|ProxyServer",
        "$MachineInternetSettings|ProxyOverride", "$ProxyControlPolicy|Proxy",
        "$ProxyControlPolicy|Autoconfig", "$WinHttpKey|DisableWpad"
    )
    if ($Backup.Product -ne $ProductName -or $Backup.Computer -ne $env:COMPUTERNAME -or @($Backup.Values).Count -ne $allowed.Count) {
        throw "The proxy backup does not match this computer or expected format. No registry values were restored."
    }
    $seen = @{}
    foreach ($entry in $Backup.Values) {
        $key = "{0}|{1}" -f $entry.Path, $entry.Name
        if ($key -notin $allowed -or $seen.ContainsKey($key) -or $entry.Exists -isnot [bool]) { throw "Unexpected or duplicate registry target in proxy backup." }
        if ($entry.Exists -and $entry.Kind -notin @('DWord','QWord','String','ExpandString','MultiString','Binary')) { throw "Unsupported registry type in proxy backup." }
        $seen[$key] = $true
    }
}

function Assert-TrustedLocalPath {
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing redirected local path: $Path" }
        if ($ancestor -is [IO.FileInfo]) { $ancestor = $ancestor.Directory } else { $ancestor = $ancestor.Parent }
    }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "Untrusted owner of $Path. Administrator inspection is required." }
    $writes = [Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership,DeleteSubdirectoriesAndFiles'
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and ($rule.FileSystemRights -band $writes) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) {
            throw "Untrusted write permission on $Path. Administrator inspection is required."
        }
    }
}

function Set-ManagedDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path,[bool]$UserRead = $false)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admins)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    if ($UserRead) {
        $identity = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Initialize-TrustedStorage {
    foreach ($path in @((Split-Path $StateDir),$StateDir,$LogDir,(Split-Path $InstallDir),$InstallDir)) {
        if (Test-Path -LiteralPath $path) { Assert-TrustedLocalPath $path }
        else { New-Item -ItemType Directory -Path $path | Out-Null }
        Set-ManagedDirectoryAcl -Path $path -UserRead ($path -eq $InstallDir -or $path -eq (Split-Path $InstallDir))
    }
    foreach ($path in @($BackupFile,$LogFile,$InstalledScript,(Join-Path $InstallDir 'Proxy-Control.exe'))) {
        if (Test-Path -LiteralPath $path) { Assert-TrustedLocalPath $path }
    }
    $script:TrustedStateReady = $true
}

function Set-SecureFilePermissions {
    Set-ManagedDirectoryAcl -Path $InstallDir -UserRead $true
    Set-ManagedDirectoryAcl -Path $StateDir
}

function Install-SecurityWebGateway {
    Save-InitialBackup

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null

    $source = (Resolve-Path $PSCommandPath).Path
    $destination = $InstalledScript

    if ($source -ne $destination) {
        Copy-Item -Path $source -Destination $destination -Force
    }

    # v1.3.1 uses a single Windows GUI application in Start Menu.
    # Legacy individual CMD shortcuts are intentionally not created here.

    Set-SecureFilePermissions

    Enable-SecurityWebGateway

    Write-Log "Product installed version $ProductVersion."
    Write-Host ""
    Write-Host "$ProductName $ProductVersion installed successfully." -ForegroundColor Green
    Write-Host "Start Menu: Proxy Control"
}

function Get-ValueSafe {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Show-Status {
    $state = Get-ValueSafe $ProductKey "State"
    $version = Get-ValueSafe $ProductKey "ProductVersion"
    $configuredPac = Get-ValueSafe $MachineInternetSettings "AutoConfigURL"
    $proxyEnable = Get-ValueSafe $MachineInternetSettings "ProxyEnable"
    $proxyPerUser = Get-ValueSafe $PolicyInternetSettings "ProxySettingsPerUser"
    $proxyLock = Get-ValueSafe $ProxyControlPolicy "Proxy"
    $autoConfigLock = Get-ValueSafe $ProxyControlPolicy "Autoconfig"
    $autoDetect = Get-ValueSafe $MachineInternetSettings "AutoDetect"
    $disableWpad = Get-ValueSafe $WinHttpKey "DisableWpad"

    Write-Host ""
    Write-Host "============================================================"
    Write-Host " Proxy Control Endpoint Status"
    Write-Host "============================================================"
    Write-Host ("Installed version      : {0}" -f $(if ($version) {$version} else {"Not registered"}))
    Write-Host ("Managed state          : {0}" -f $(if ($state) {$state} else {"Unknown"}))
    Write-Host ("PAC URL                : {0}" -f $(if ($configuredPac) {$configuredPac} else {"<none>"}))
    Write-Host ("Manual proxy enabled   : {0}" -f $(if ($proxyEnable -eq 1) {"YES"} else {"NO"}))
    Write-Host ("Proxy settings per user: {0}" -f $(if ($proxyPerUser -eq 0) {"NO (machine-wide)"} else {"YES / not enforced"}))
    Write-Host ("Proxy change lock      : {0}" -f $(if ($proxyLock -eq 1) {"ENABLED"} else {"NOT ENABLED"}))
    Write-Host ("Auto-config change lock: {0}" -f $(if ($autoConfigLock -eq 1) {"ENABLED"} else {"NOT ENABLED"}))
    Write-Host ("Auto detect            : {0}" -f $(if ($autoDetect -eq 0) {"OFF"} else {"ON / unknown"}))
    Write-Host ("WinHTTP WPAD           : {0}" -f $(if ($disableWpad -eq 1) {"DISABLED"} else {"DEFAULT / enabled"}))

    if ($configuredPac) {
        $pacTest = Test-Pac -Url $configuredPac
        Write-Host ("PAC reachability       : {0} ({1})" -f $(if ($pacTest.Reachable) {"OK"} else {"FAILED"}), $pacTest.Detail)
    }

    Write-Host "============================================================"
    Write-Host ""

    if (-not (Test-IsAdministrator)) {
        Write-Host "Current session is STANDARD/NON-ELEVATED." -ForegroundColor Cyan
        Write-Host "Enable/Disable requires Administrator credentials."
    } else {
        Write-Host "Current session is ADMINISTRATOR/ELEVATED." -ForegroundColor Yellow
    }
}

function Uninstall-SecurityWebGateway {
    Write-Host ""
    Write-Host "Uninstalling Proxy Control..." -ForegroundColor Yellow

    Restore-InitialBackup
    Notify-InternetSettingsChanged

    if (Test-Path $ProductKey) {
        Remove-Item -Path $ProductKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $StartMenuDir) {
        Remove-Item -Path $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Product uninstall initiated; pre-install settings restored."

    # Preserve backup/logs for audit. Program files are deleted after this PowerShell exits.
    if (Test-Path $InstallDir) {
        $escaped = $InstallDir.Replace('"','""')
        $cmd = "ping 127.0.0.1 -n 3 >nul & rmdir /s /q `"$escaped`""
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -WindowStyle Hidden | Out-Null
    }

    Write-Host "Pre-install proxy settings restored." -ForegroundColor Green
    Write-Host "Audit/backup files remain under: $StateDir"
}

Request-Elevation

try {
    if ($Mode -ne 'Status') { Initialize-TrustedStorage }
    switch ($Mode) {
        "Install"   { Install-SecurityWebGateway }
        "Enable"    { Enable-SecurityWebGateway }
        "Disable"   { Disable-SecurityWebGateway }
        "Status"    { Show-Status }
        "Uninstall" { Uninstall-SecurityWebGateway }
    }
}
catch {
    if (Test-IsAdministrator) {
        try { Write-Log "ERROR mode=$Mode message=$($_.Exception.Message)" } catch {}
    }
    Write-Error $_
    exit 1
}
