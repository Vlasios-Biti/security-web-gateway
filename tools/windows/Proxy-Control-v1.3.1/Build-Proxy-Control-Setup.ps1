#requires -version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [ValidatePattern('^https?://')]
    [string]$PacUrl = "http://proxy.example.internal:8081/proxy.pac"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Version = "1.3.1"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
    $ScriptRoot = (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $ScriptRoot "dist"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $ScriptRoot $OutputDirectory
}

$PayloadDir = Join-Path $ScriptRoot "payload"
$GuiSource = Join-Path $ScriptRoot "Proxy-Control-GUI.cs"

if ($env:OS -ne "Windows_NT") {
    throw "This builder must run on Windows."
}

$CscCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)

$Csc = $null
foreach ($candidate in $CscCandidates) {
    if (Test-Path $candidate) {
        $Csc = $candidate
        break
    }
}
if (-not $Csc) {
    throw "Microsoft .NET Framework C# compiler csc.exe was not found."
}

$FrameworkDir = Split-Path -Parent $Csc
$References = @(
    (Join-Path $FrameworkDir "System.dll"),
    (Join-Path $FrameworkDir "System.Core.dll"),
    (Join-Path $FrameworkDir "System.Drawing.dll"),
    (Join-Path $FrameworkDir "System.Windows.Forms.dll")
)

foreach ($ref in $References) {
    if (-not (Test-Path $ref)) {
        throw "Required .NET assembly was not found: $ref"
    }
}

$RequiredPayload = @(
    "Proxy-Control-Endpoint.ps1",
    "Install-Proxy-Control.ps1",
    "README.txt"
)
foreach ($name in $RequiredPayload) {
    if (-not (Test-Path (Join-Path $PayloadDir $name))) {
        throw "Required payload file missing: $name"
    }
}
if (-not (Test-Path $GuiSource)) {
    throw "GUI source missing: $GuiSource"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path

$Work = Join-Path $env:TEMP ("Security-Web-Gateway-Proxy-Control-v131-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Work -Force | Out-Null

function Invoke-Csc {
    param(
        [Parameter(Mandatory)][string]$ResponseFile
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Csc
    $psi.Arguments = "@`"$ResponseFile`""
    $psi.WorkingDirectory = $Work
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Host $stdout
        Write-Host $stderr
        throw "C# compiler failed with exit code $($proc.ExitCode)."
    }
}

try {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Proxy Control GUI Builder v$Version" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Compiler: $Csc"
    Write-Host "PAC URL : $PacUrl"
    Write-Host ""

    # 1) Compile installed GUI
    $GuiExe = Join-Path $Work "Proxy-Control.exe"
    $GuiRsp = Join-Path $Work "gui.rsp"

    $GuiArgs = @(
        "/nologo",
        "/target:winexe",
        "/optimize+",
        "/platform:anycpu",
        "/out:`"$GuiExe`"",
        "/reference:`"$($References[0])`"",
        "/reference:`"$($References[1])`"",
        "/reference:`"$($References[2])`"",
        "/reference:`"$($References[3])`"",
        "`"$GuiSource`""
    )
    [IO.File]::WriteAllLines($GuiRsp, $GuiArgs, [Text.Encoding]::ASCII)
    Invoke-Csc -ResponseFile $GuiRsp

    if (-not (Test-Path $GuiExe)) {
        throw "GUI EXE was not created."
    }

    # 2) Copy compiled GUI into temporary payload for embedding
    $ControllerPath = Join-Path $PayloadDir "Proxy-Control-Endpoint.ps1"
    $InstallerPs1Path = Join-Path $PayloadDir "Install-Proxy-Control.ps1"
    $ReadmePath = Join-Path $PayloadDir "README.txt"

    $ControllerB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ControllerPath))
    $InstallerB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($InstallerPs1Path))
    $ReadmeB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ReadmePath))
    $GuiB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($GuiExe))

    # 3) Build setup bootstrapper
    $SetupSource = Join-Path $Work "SecurityWebGatewaySetup.cs"
    $TargetExe = Join-Path $OutputDirectory "Proxy-Control-Setup-v$Version.exe"

    $Bootstrap = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Proxy Control Setup")]
[assembly: System.Reflection.AssemblyCompany("Security Web Gateway")]
[assembly: System.Reflection.AssemblyProduct("Proxy Control")]
[assembly: System.Reflection.AssemblyVersion("1.3.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.3.1.0")]

namespace SecurityWebGateway.EndpointSetup
{
    internal static class Program
    {
        private const string ControllerB64 = "__CONTROLLER_B64__";
        private const string InstallerB64 = "__INSTALLER_B64__";
        private const string ReadmeB64 = "__README_B64__";
        private const string GuiB64 = "__GUI_B64__";
        private const string PacUrl = "__PAC_URL__";

        [STAThread]
        private static int Main()
        {
            try
            {
                if (!IsAdministrator())
                    return RelaunchElevated();

                return Install();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Proxy Control installation failed.\r\n\r\n" + ex.Message,
                    "Proxy Control Setup",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }
        }

        private static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static int RelaunchElevated()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath);

                using (Process p = Process.Start(psi))
                {
                    if (p == null) return 5;
                    p.WaitForExit();
                    return p.ExitCode;
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return 5;
            }
        }

        private static int Install()
        {
            string tempRoot = Path.Combine(
                Path.GetTempPath(),
                "Security-Web-Gateway-Endpoint-Setup-" + Guid.NewGuid().ToString("N")
            );

            Directory.CreateDirectory(tempRoot);

            try
            {
                string controller = Path.Combine(tempRoot, "Proxy-Control-Endpoint.ps1");
                string installer = Path.Combine(tempRoot, "Install-Proxy-Control.ps1");
                string readme = Path.Combine(tempRoot, "README.txt");
                string gui = Path.Combine(tempRoot, "Proxy-Control.exe");

                File.WriteAllBytes(controller, Convert.FromBase64String(ControllerB64));
                File.WriteAllBytes(installer, Convert.FromBase64String(InstallerB64));
                File.WriteAllBytes(readme, Convert.FromBase64String(ReadmeB64));
                File.WriteAllBytes(gui, Convert.FromBase64String(GuiB64));

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    @"WindowsPowerShell\v1.0\powershell.exe"
                );
                psi.Arguments =
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                    installer + "\" -PacUrl \"" + PacUrl + "\"";
                psi.WorkingDirectory = tempRoot;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                string stdout;
                string stderr;
                int exitCode;

                using (Process p = Process.Start(psi))
                {
                    if (p == null)
                        throw new InvalidOperationException("Could not start PowerShell.");

                    stdout = p.StandardOutput.ReadToEnd();
                    stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    exitCode = p.ExitCode;
                }

                string logPath = Path.Combine(
                    Path.GetTempPath(),
                    "Security-Web-Gateway-Endpoint-Setup.log"
                );

                File.WriteAllText(
                    logPath,
                    DateTime.Now.ToString("o") +
                    "\r\nExitCode=" + exitCode +
                    "\r\n\r\nSTDOUT:\r\n" + stdout +
                    "\r\n\r\nSTDERR:\r\n" + stderr,
                    Encoding.UTF8
                );

                if (exitCode != 0)
                {
                    MessageBox.Show(
                        "Installation failed. Exit code: " + exitCode +
                        "\r\n\r\nDiagnostic log:\r\n" + logPath,
                        "Proxy Control Setup",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return exitCode;
                }

                string installedGui = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    @"Security Web Gateway\Proxy Control\Proxy-Control.exe"
                );

                MessageBox.Show(
                    "Proxy Control v1.3.1 was installed successfully.",
                    "Proxy Control Setup",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                if (File.Exists(installedGui))
                {
                    Process.Start(installedGui);
                }

                return 0;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempRoot))
                        Directory.Delete(tempRoot, true);
                }
                catch { }
            }
        }
    }
}
'@

    $Bootstrap = $Bootstrap.Replace("__CONTROLLER_B64__", $ControllerB64)
    $Bootstrap = $Bootstrap.Replace("__INSTALLER_B64__", $InstallerB64)
    $Bootstrap = $Bootstrap.Replace("__README_B64__", $ReadmeB64)
    $Bootstrap = $Bootstrap.Replace("__GUI_B64__", $GuiB64)
    $Bootstrap = $Bootstrap.Replace("__PAC_URL__", $PacUrl.Replace("\\", "\\\\").Replace("\"", "\\\""))

    [IO.File]::WriteAllText(
        $SetupSource,
        $Bootstrap,
        (New-Object Text.UTF8Encoding($false))
    )

    $SetupRsp = Join-Path $Work "setup.rsp"
    $SetupArgs = @(
        "/nologo",
        "/target:winexe",
        "/optimize+",
        "/platform:anycpu",
        "/out:`"$TargetExe`"",
        "/reference:`"$($References[0])`"",
        "/reference:`"$($References[1])`"",
        "/reference:`"$($References[3])`"",
        "`"$SetupSource`""
    )
    [IO.File]::WriteAllLines($SetupRsp, $SetupArgs, [Text.Encoding]::ASCII)
    Invoke-Csc -ResponseFile $SetupRsp

    if (-not (Test-Path $TargetExe)) {
        throw "Setup EXE was not created."
    }

    $hash = (Get-FileHash -Path $TargetExe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path $TargetExe -Leaf)" |
        Set-Content -Path "$TargetExe.sha256" -Encoding ASCII

    Write-Host ""
    Write-Host "BUILD SUCCESS" -ForegroundColor Green
    Write-Host "Final installer:"
    Write-Host "  $TargetExe"
    Write-Host ""
    Write-Host "After installation the Start Menu contains ONE program:"
    Write-Host "  Proxy Control -> Proxy Control"
}
finally {
    if (Test-Path $Work) {
        Remove-Item -Path $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
