using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace StopStealer.Core;

public class ClipboardProtector
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private System.Threading.Timer? _monitorTimer;
    private string _lastClipboard = "";
    public bool IsMonitoring { get; private set; }

    private static readonly string[] SensitivePatterns = new[]
    {
        @"mfa\.[A-Za-z0-9_-]{80,}", // Discord MFA token
        @"[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27,}", // Discord token
        @"-----BEGIN (RSA |EC )?PRIVATE KEY-----", // Private keys
        @"(?:password|passwd|pwd)\s*[:=]\s*\S+", // Passwords
        @"(?:api[_-]?key|apikey|secret)\s*[:=]\s*\S+", // API keys
        @"(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]+", // Stripe keys
        @"ghp_[A-Za-z0-9]{36}", // GitHub tokens
        @"AKIA[0-9A-Z]{16}", // AWS access keys
    };

    private static readonly Regex DiscordWebhookRegex = new(
        @"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DiscordTokenRegex = new(
        @"mfa\.[A-Za-z0-9_-]{80,}|[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        _monitorTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                var current = GetClipboardText();
                if (!string.IsNullOrEmpty(current) && current != _lastClipboard)
                {
                    _lastClipboard = current;

                    if (DiscordTokenRegex.IsMatch(current))
                    {
                        _logger.Log(new ThreatEvent
                        {
                            Type = ThreatType.DiscordTokenGrabber,
                            ProcessName = "Clipboard Monitor",
                            ProcessId = Environment.ProcessId,
                            TargetPath = "Clipboard (Discord Token Detected)",
                            Action = "ALERTED",
                            Severity = ThreatSeverity.Critical
                        });
                    }
                    else if (DiscordWebhookRegex.IsMatch(current))
                    {
                        _logger.Log(new ThreatEvent
                        {
                            Type = ThreatType.DiscordWebhookExfil,
                            ProcessName = "Clipboard Monitor",
                            ProcessId = Environment.ProcessId,
                            TargetPath = "Clipboard (Discord Webhook Detected)",
                            Action = "ALERTED",
                            Severity = ThreatSeverity.Critical
                        });
                    }
                    else
                    {
                        foreach (var pattern in SensitivePatterns)
                        {
                            if (Regex.IsMatch(current, pattern, RegexOptions.IgnoreCase))
                            {
                                _logger.Log(new ThreatEvent
                                {
                                    Type = ThreatType.ClipboardTheft,
                                    ProcessName = "Clipboard Monitor",
                                    ProcessId = Environment.ProcessId,
                                    TargetPath = "Clipboard (Sensitive Data Detected)",
                                    Action = "ALERTED",
                                    Severity = ThreatSeverity.High
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
        }, null, 0, 500);
    }

    public void StopMonitoring()
    {
        IsMonitoring = false;
        _monitorTimer?.Dispose();
        _monitorTimer = null;
    }

    [DllImport("user32.dll")]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    private static string GetClipboardText()
    {
        try
        {
            if (!OpenClipboard(IntPtr.Zero)) return "";
            var hData = GetClipboardData(13); // CF_UNICODETEXT
            if (hData == IntPtr.Zero) { CloseClipboard(); return ""; }
            var ptr = GlobalLock(hData);
            if (ptr == IntPtr.Zero) { CloseClipboard(); return ""; }
            var result = Marshal.PtrToStringUni(ptr) ?? "";
            GlobalUnlock(hData);
            CloseClipboard();
            return result;
        }
        catch { return ""; }
    }
}
