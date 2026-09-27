using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StopStealer.Core;

public class ScreenProtector
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private System.Threading.Timer? _monitorTimer;
    public bool IsMonitoring { get; private set; }

    private static readonly string[] ScreenshotToolProcesses = new[]
    {
        "snippingtool", "snipaste", "greenshot", "sharex", "lightshot",
        "droplr", "puush", "flameshot", "ksnip", "spectacle",
        "obs", "obs64", "obs32", "bandicam", "fraps", "nvidia",
        "amdvceenc", "steamwebhelper", "screenshot", "capture"
    };

    private static readonly string[] ScreenCaptureDlls = new[]
    {
        "gdi32.dll", "msimg32.dll", "dxgi.dll",
        "d3d11.dll", "dwmcore.dll"
    };

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        _monitorTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (IsSuspiciousScreenCapture(proc))
                        {
                            _logger.Log(new ThreatEvent
                            {
                                Type = ThreatType.ScreenshotAttempt,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                TargetPath = proc.MainModule?.FileName ?? "unknown",
                                Action = "MONITORING",
                                Severity = ThreatSeverity.Medium
                            });
                        }
                    }
                    catch { }
                }

                MonitorPrintScreen();
            }
            catch { }
        }, null, 0, 2000);
    }

    public void StopMonitoring()
    {
        IsMonitoring = false;
        _monitorTimer?.Dispose();
        _monitorTimer = null;
    }

    private void MonitorPrintScreen()
    {
        try
        {
            if (GetAsyncKeyState(0x2C) != 0 || GetAsyncKeyState(VK_SNAPSHOT) != 0)
            {
                _logger.Log(new ThreatEvent
                {
                    Type = ThreatType.ScreenshotAttempt,
                    ProcessName = "PrintScreen Key",
                    ProcessId = 0,
                    TargetPath = "Screen Capture Hotkey Detected",
                    Action = "ALERTED",
                    Severity = ThreatSeverity.Low
                });
            }
        }
        catch { }
    }

    private const int VK_SNAPSHOT = 0x2C;

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    private static bool IsSuspiciousScreenCapture(Process proc)
    {
        try
        {
            var name = proc.ProcessName.ToLowerInvariant();

            foreach (var tool in ScreenshotToolProcesses)
            {
                if (name.Contains(tool))
                {
                    var path = proc.MainModule?.FileName?.ToLowerInvariant() ?? "";

                    if (name == "obs" || name == "obs64" || name == "obs32")
                    {
                        if (path.Contains("obs-studio"))
                            return false;
                    }
                    if (name.Contains("steamwebhelper"))
                        return false;

                    return true;
                }
            }

            try
            {
                var mainPath = proc.MainModule?.FileName?.ToLowerInvariant() ?? "";
                if (mainPath.Contains("\\temp\\") && name.EndsWith(".exe"))
                {
                    if (proc.Modules.Count > 0)
                    {
                        bool hasGDI = false;
                        foreach (System.Diagnostics.ProcessModule module in proc.Modules)
                        {
                            var modName = module.ModuleName.ToLowerInvariant();
                            if (ScreenCaptureDlls.Any(d => modName.Contains(d)))
                                hasGDI = true;
                        }
                        if (hasGDI) return true;
                    }
                }
            }
            catch { }

            return false;
        }
        catch { return false; }
    }
}
