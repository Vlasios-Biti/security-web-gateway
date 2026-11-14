$ErrorActionPreference = 'Stop'
$controller = Join-Path $PSScriptRoot '../tools/windows/Proxy-Control-v1.3.1/payload/Proxy-Control-Endpoint.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($controller,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
# Load only the pure backup-data validator. Never load dispatch, elevation, ACL or registry writers.
$function = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-BackupScope'},$true)
if (-not $function) { throw 'Backup scope validator missing' }
Invoke-Expression $function.Extent.Text
$ProductName = 'Proxy Control'; $env:COMPUTERNAME = 'DUMMY-PC'
$PolicyInternetSettings = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
$MachineInternetSettings = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
$ProxyControlPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel'
$WinHttpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
$targets = @(
    @($PolicyInternetSettings,'ProxySettingsPerUser'),@($PolicyInternetSettings,'AutoDetect'),
    @($MachineInternetSettings,'AutoConfigURL'),@($MachineInternetSettings,'ProxyEnable'),
    @($MachineInternetSettings,'AutoDetect'),@($MachineInternetSettings,'ProxyServer'),
    @($MachineInternetSettings,'ProxyOverride'),@($ProxyControlPolicy,'Proxy'),
    @($ProxyControlPolicy,'Autoconfig'),@($WinHttpKey,'DisableWpad')
)
function New-DummyBackup {
    [pscustomobject]@{Product=$ProductName;Computer='DUMMY-PC';Values=@($targets | ForEach-Object {[pscustomobject]@{Path=$_[0];Name=$_[1];Exists=$false;Kind=$null;Value=$null}})}
}
$valid = New-DummyBackup
Assert-BackupScope $valid
foreach ($scenario in @('path','name','duplicate','type','computer','missing')) {
    $backup = New-DummyBackup
    switch ($scenario) {
        'path' {$backup.Values[0].Path='HKLM:\SOFTWARE\DummyOutsideProxyScope'}
        'name' {$backup.Values[0].Name='DummyOutsideProxyScope'}
        'duplicate' {$backup.Values[1]=$backup.Values[0]}
        'type' {$backup.Values[0].Exists='false'}
        'computer' {$backup.Computer='ANOTHER-DUMMY-PC'}
        'missing' {$backup.Values=@($backup.Values | Select-Object -Skip 1)}
    }
    $rejected = $false
    try { Assert-BackupScope $backup } catch { $rejected = $true }
    if (-not $rejected) { throw "Backup validator accepted invalid $scenario" }
}
Write-Output 'PASS: Windows backup targets validated without registry, ACL or elevation changes'
