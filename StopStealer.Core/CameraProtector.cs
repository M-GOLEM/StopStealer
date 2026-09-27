using System.Diagnostics;
using Microsoft.Win32;

namespace StopStealer.Core;

public class CameraProtector
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private System.Threading.Timer? _monitorTimer;
    public bool IsMonitoring { get; private set; }

    private static readonly string[] SuspiciousCameraProcesses = new[]
    {
        "webcam", "camera", "snapcam", "manycam", "camtasia",
        "xsplit", "splitcam", "youcam", "debut", "webcorder"
    };

    private readonly HashSet<string> _knownCameraApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "windows.security.hevcvideoextension",
        "microsoft.windows.camera",
        "microsoft.yourphone",
        "microsoft.teams",
        "zoom.exe",
        "skype.exe",
        "discord.exe",
        "teams.exe",
        "meet.exe",
        "webex.exe"
    };

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        MonitorRegistryCameraAccess();

        _monitorTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (IsSuspiciousCameraAccess(proc))
                        {
                            _logger.Log(new ThreatEvent
                            {
                                Type = ThreatType.CameraAccess,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                TargetPath = proc.MainModule?.FileName ?? "unknown",
                                Action = "MONITORING",
                                Severity = ThreatSeverity.High
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, null, 0, 5000);
    }

    public void StopMonitoring()
    {
        IsMonitoring = false;
        _monitorTimer?.Dispose();
        _monitorTimer = null;
    }

    private void MonitorRegistryCameraAccess()
    {
        try
        {
            var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", false);
            if (key != null)
            {
                var value = key.GetValue("Value")?.ToString();
                if (value == "Deny")
                {
                    _logger.Log(new ThreatEvent
                    {
                        Type = ThreatType.CameraAccess,
                        ProcessName = "System",
                        ProcessId = 0,
                        TargetPath = "Camera Access Disabled via Registry",
                        Action = "CONFIGURED",
                        Severity = ThreatSeverity.Low
                    });
                }
            }
        }
        catch { }
    }

    private bool IsSuspiciousCameraAccess(Process proc)
    {
        try
        {
            var name = proc.ProcessName.ToLowerInvariant();

            foreach (var app in _knownCameraApps)
            {
                if (app.Contains(".exe"))
                {
                    if (name == Path.GetFileNameWithoutExtension(app).ToLowerInvariant())
                        return false;
                }
                else
                {
                    if (name.Contains(app.ToLowerInvariant()))
                        return false;
                }
            }

            foreach (var tool in SuspiciousCameraProcesses)
            {
                if (name.Contains(tool)) return true;
            }

            try
            {
                var path = proc.MainModule?.FileName?.ToLowerInvariant() ?? "";
                if (path.Contains("\\temp\\") && name.EndsWith(".exe"))
                {
                    foreach (ProcessModule module in proc.Modules)
                    {
                        var modPath = module.FileName.ToLowerInvariant();
                        if (modPath.Contains("avicap") || modPath.Contains("mf.dll") ||
                            modPath.Contains("mfreadwrite"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }
        catch { return false; }
    }
}
