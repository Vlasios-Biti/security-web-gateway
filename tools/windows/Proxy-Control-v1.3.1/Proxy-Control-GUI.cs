using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: System.Reflection.AssemblyTitle("Proxy Control")]
[assembly: System.Reflection.AssemblyCompany("Security Web Gateway")]
[assembly: System.Reflection.AssemblyProduct("Proxy Control")]
[assembly: System.Reflection.AssemblyVersion("1.3.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.3.1.0")]

namespace SecurityWebGateway.Endpoint
{
    internal sealed class MainForm : Form
    {
        private const string ProductKey = @"SOFTWARE\SecurityWebGateway\ProxyControl";
        private const string MachineInternetSettings = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const string PolicyInternetSettings = @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const string ProxyControlPolicy = @"SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel";

        private readonly Label statusValue = new Label();
        private readonly Label pacValue = new Label();
        private readonly Label modeValue = new Label();
        private readonly Label lockValue = new Label();
        private readonly Label reachabilityValue = new Label();
        private readonly Label changedValue = new Label();

        private readonly Button startButton = new Button();
        private readonly Button stopButton = new Button();
        private readonly Button refreshButton = new Button();
        private readonly Button uninstallButton = new Button();

        internal MainForm()
        {
            Text = "Proxy Control";
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = true;
            ClientSize = new Size(640, 440);
            Font = new Font("Segoe UI", 9F);
            BackColor = Color.White;

            BuildUi();
            RefreshStatus();
        }

        private void BuildUi()
        {
            Label title = new Label();
            title.Text = "Proxy Control";
            title.Font = new Font("Segoe UI Semibold", 18F);
            title.AutoSize = true;
            title.Location = new Point(28, 22);
            Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Security Web Gateway client control";
            subtitle.Font = new Font("Segoe UI", 10F);
            subtitle.ForeColor = Color.DimGray;
            subtitle.AutoSize = true;
            subtitle.Location = new Point(31, 60);
            Controls.Add(subtitle);

            GroupBox statusBox = new GroupBox();
            statusBox.Text = "Status";
            statusBox.Location = new Point(28, 94);
            statusBox.Size = new Size(584, 210);
            Controls.Add(statusBox);

            AddStatusRow(statusBox, "SWG", statusValue, 34);
            AddStatusRow(statusBox, "PAC URL", pacValue, 67);
            AddStatusRow(statusBox, "Traffic mode", modeValue, 100);
            AddStatusRow(statusBox, "User settings lock", lockValue, 133);
            AddStatusRow(statusBox, "PAC server", reachabilityValue, 166);
            AddStatusRow(statusBox, "Last change", changedValue, 199);

            startButton.Text = "Start SWG";
            startButton.Size = new Size(125, 42);
            startButton.Location = new Point(28, 326);
            startButton.Click += delegate { RunAction("Enable"); };
            Controls.Add(startButton);

            stopButton.Text = "Stop SWG";
            stopButton.Size = new Size(125, 42);
            stopButton.Location = new Point(163, 326);
            stopButton.Click += delegate { RunAction("Disable"); };
            Controls.Add(stopButton);

            refreshButton.Text = "Refresh";
            refreshButton.Size = new Size(125, 42);
            refreshButton.Location = new Point(298, 326);
            refreshButton.Click += delegate { RefreshStatus(); };
            Controls.Add(refreshButton);

            uninstallButton.Text = "Uninstall";
            uninstallButton.Size = new Size(125, 42);
            uninstallButton.Location = new Point(487, 326);
            uninstallButton.Click += delegate { UninstallApplication(); };
            Controls.Add(uninstallButton);

            Label adminInfo = new Label();
            adminInfo.Text = "Start, Stop and Uninstall require Windows Administrator credentials.";
            adminInfo.ForeColor = Color.DimGray;
            adminInfo.AutoSize = true;
            adminInfo.Location = new Point(31, 391);
            Controls.Add(adminInfo);
        }

        private static void AddStatusRow(Control parent, string labelText, Label valueLabel, int y)
        {
            Label label = new Label();
            label.Text = labelText;
            label.Font = new Font("Segoe UI Semibold", 9F);
            label.AutoSize = true;
            label.Location = new Point(20, y - 2);
            parent.Controls.Add(label);

            valueLabel.Text = "-";
            valueLabel.AutoEllipsis = true;
            valueLabel.Location = new Point(180, y - 3);
            valueLabel.Size = new Size(375, 24);
            parent.Controls.Add(valueLabel);
        }

        private static object ReadRegistryValue(string subKey, string valueName)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey, false))
            {
                return key == null ? null : key.GetValue(valueName);
            }
        }

        private static string AsText(object value, string fallback)
        {
            return value == null ? fallback : Convert.ToString(value);
        }

        private void RefreshStatus()
        {
            try
            {
                object stateObj = ReadRegistryValue(ProductKey, "State");
                string state = AsText(stateObj, "Unknown");
                string pac = AsText(ReadRegistryValue(MachineInternetSettings, "AutoConfigURL"), "<none>");
                object perUserObj = ReadRegistryValue(PolicyInternetSettings, "ProxySettingsPerUser");
                object proxyLockObj = ReadRegistryValue(ProxyControlPolicy, "Proxy");
                object autoConfigLockObj = ReadRegistryValue(ProxyControlPolicy, "Autoconfig");
                string lastChange = AsText(ReadRegistryValue(ProductKey, "LastChangedAt"), "-");

                bool machineWide = perUserObj != null && Convert.ToInt32(perUserObj) == 0;
                bool proxyLocked = proxyLockObj != null && Convert.ToInt32(proxyLockObj) == 1;
                bool autoLocked = autoConfigLockObj != null && Convert.ToInt32(autoConfigLockObj) == 1;

                statusValue.Text = state.ToUpperInvariant();

                if (string.Equals(state, "Enabled", StringComparison.OrdinalIgnoreCase))
                {
                    statusValue.ForeColor = Color.DarkGreen;
                    modeValue.Text = "PROXY / PAC policy";
                    startButton.Enabled = false;
                    stopButton.Enabled = true;
                }
                else if (string.Equals(state, "Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    statusValue.ForeColor = Color.DarkOrange;
                    modeValue.Text = "DIRECT";
                    startButton.Enabled = true;
                    stopButton.Enabled = false;
                }
                else
                {
                    statusValue.ForeColor = Color.Firebrick;
                    modeValue.Text = "Unknown";
                    startButton.Enabled = true;
                    stopButton.Enabled = true;
                }

                pacValue.Text = pac;
                lockValue.Text = (machineWide && proxyLocked && autoLocked)
                    ? "ENFORCED - standard user cannot modify"
                    : "NOT fully enforced";
                lockValue.ForeColor = (machineWide && proxyLocked && autoLocked)
                    ? Color.DarkGreen
                    : Color.Firebrick;

                changedValue.Text = lastChange;

                if (!string.Equals(pac, "<none>", StringComparison.OrdinalIgnoreCase))
                {
                    Tuple<bool, string> result = TestPac(pac);
                    reachabilityValue.Text = result.Item2;
                    reachabilityValue.ForeColor = result.Item1 ? Color.DarkGreen : Color.Firebrick;
                }
                else
                {
                    reachabilityValue.Text = "Not applicable while SWG is stopped";
                    reachabilityValue.ForeColor = Color.DimGray;
                }
            }
            catch (Exception ex)
            {
                statusValue.Text = "ERROR";
                statusValue.ForeColor = Color.Firebrick;
                reachabilityValue.Text = ex.Message;
            }
        }

        private static Tuple<bool, string> TestPac(string url)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                request.Timeout = 2500;
                request.ReadWriteTimeout = 2500;
                request.AllowAutoRedirect = true;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    int code = (int)response.StatusCode;
                    return Tuple.Create(code >= 200 && code < 400, "Reachable - HTTP " + code);
                }
            }
            catch (Exception ex)
            {
                return Tuple.Create(false, "Unavailable - " + ex.Message);
            }
        }

        private void RunAction(string mode)
        {
            string controller = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Security Web Gateway\Proxy Control\Proxy-Control-Endpoint.ps1"
            );

            if (!File.Exists(controller))
            {
                MessageBox.Show(
                    "Proxy Control controller was not found:\r\n" + controller,
                    "Proxy Control",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return;
            }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" +
                                controller + "\" -Mode " + mode;
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WorkingDirectory = Path.GetDirectoryName(controller);

                using (Process p = Process.Start(psi))
                {
                    if (p == null)
                        return;

                    p.WaitForExit();

                    if (p.ExitCode != 0)
                    {
                        MessageBox.Show(
                            "The operation did not complete successfully. Exit code: " + p.ExitCode,
                            "Proxy Control",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning
                        );
                    }
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                MessageBox.Show(
                    "Administrator authorization was cancelled. No changes were made.",
                    "Proxy Control",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            finally
            {
                RefreshStatus();
            }
        }

        private void UninstallApplication()
        {
            DialogResult answer = MessageBox.Show(
                "Uninstall Proxy Control?\r\n\r\n" +
                "The proxy configuration that existed before the first Proxy Control installation will be restored.",
                "Confirm Uninstall",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2
            );

            if (answer != DialogResult.Yes)
                return;

            string controller = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Security Web Gateway\Proxy Control\Proxy-Control-Endpoint.ps1"
            );

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" +
                                controller + "\" -Mode Uninstall";
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WorkingDirectory = Path.GetDirectoryName(controller);

                using (Process p = Process.Start(psi))
                {
                    if (p == null)
                        return;

                    p.WaitForExit();

                    if (p.ExitCode == 0)
                    {
                        MessageBox.Show(
                            "Proxy Control was uninstalled and the previous proxy settings were restored.",
                            "Uninstall Complete",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information
                        );
                        Close();
                    }
                    else
                    {
                        MessageBox.Show(
                            "Uninstall did not complete successfully. Exit code: " + p.ExitCode,
                            "Proxy Control",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                    }
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                MessageBox.Show(
                    "Administrator authorization was cancelled. Nothing was uninstalled.",
                    "Proxy Control",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
