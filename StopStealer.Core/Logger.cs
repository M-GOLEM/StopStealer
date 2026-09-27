using System.Collections.Concurrent;

namespace StopStealer.Core;

public class ThreatLogger
{
    private static readonly Lazy<ThreatLogger> _instance = new(() => new ThreatLogger());
    public static ThreatLogger Instance => _instance.Value;

    private readonly ConcurrentQueue<ThreatEvent> _events = new();
    private readonly List<ThreatEvent> _allEvents = new();
    private readonly object _lock = new();
    private readonly string _logDir;

    public event Action<ThreatEvent>? OnThreatDetected;

    public int MaxEvents { get; set; } = 10000;

    private ThreatLogger()
    {
        _logDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "hellstorm", "Logs");
        Directory.CreateDirectory(_logDir);
    }

    public void Log(ThreatEvent threat)
    {
        _events.Enqueue(threat);
        lock (_lock)
        {
            _allEvents.Insert(0, threat);
            if (_allEvents.Count > MaxEvents)
                _allEvents.RemoveAt(_allEvents.Count - 1);
        }

        OnThreatDetected?.Invoke(threat);
        WriteToFile(threat);
    }

    private void WriteToFile(ThreatEvent threat)
    {
        try
        {
            var file = Path.Combine(_logDir, $"{DateTime.Now:yyyy-MM-dd}.log");
            var line = $"[{threat.Timestamp:HH:mm:ss.fff}] [{threat.Severity}] [{threat.Type}] " +
                       $"Process={threat.ProcessName}(PID:{threat.ProcessId}) " +
                       $"Target={threat.TargetPath} Action={threat.Action}\n";
            File.AppendAllText(file, line);
        }
        catch { }
    }

    public List<ThreatEvent> GetRecentEvents(int count = 100)
    {
        lock (_lock)
        {
            return _allEvents.Take(count).ToList();
        }
    }

    public ProtectionStats GetStats()
    {
        lock (_lock)
        {
            return new ProtectionStats
            {
                TotalThreatsBlocked = _allEvents.Count(t =>
                    t.Action.Contains("BLOCK") ||
                    t.Action == "MEMORY_BLOCK" ||
                    t.Action == "BEHAVIORAL_BLOCK" ||
                    t.Action == "REALTIME_BLOCK"),
                BrowserAttacksBlocked = _allEvents.Count(t =>
                    t.Type == ThreatType.BrowserDataAccess ||
                    t.Type == ThreatType.PasswordFileAccess ||
                    t.Type == ThreatType.CookieFileAccess ||
                    t.Type == ThreatType.CreditCardAccess),
                TokenStealsPrevented = _allEvents.Count(t =>
                    t.Type == ThreatType.TokenGrabAttempt ||
                    t.Type == ThreatType.DiscordTokenGrabber),
                ScreenshotBlocks = _allEvents.Count(t => t.Type == ThreatType.ScreenshotAttempt),
                ClipboardBlocks = _allEvents.Count(t => t.Type == ThreatType.ClipboardTheft),
                SuspiciousProcessBlocks = _allEvents.Count(t => t.Type == ThreatType.SuspiciousProcess),
                DiscordTokenBlocks = _allEvents.Count(t => t.Type == ThreatType.DiscordTokenGrabber),
                DiscordWebhookBlocks = _allEvents.Count(t => t.Type == ThreatType.DiscordWebhookExfil),
                DiscordInjectionBlocks = _allEvents.Count(t => t.Type == ThreatType.DiscordInjection),
                CryptUnprotectBlocks = _allEvents.Count(t => t.Type == ThreatType.CryptUnprotectData),
                LastThreatTime = _allEvents.FirstOrDefault()?.Timestamp ?? DateTime.MinValue,
                IsProtected = true
            };
        }
    }

    public List<ThreatEvent> GetAllEvents()
    {
        lock (_lock)
        {
            return _allEvents.ToList();
        }
    }
}
