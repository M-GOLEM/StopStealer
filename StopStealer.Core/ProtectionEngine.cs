namespace StopStealer.Core;

public class ProtectionEngine : IDisposable
{
    private readonly BehaviorEngine _behavior;
    private readonly BrowserProtector _browserProtector;
    private readonly ClipboardProtector _clipboardProtector;
    private readonly ScreenProtector _screenProtector;
    private readonly CameraProtector _cameraProtector;
    private readonly ProcessGuard _processGuard;
    private readonly GrabberScanner _grabberScanner;
    private readonly ThreatLogger _logger;

    public bool IsRunning { get; private set; }
    public event Action<ThreatEvent>? OnThreatDetected;
    public event Action<ProtectionStats>? OnStatsUpdated;

    private System.Threading.Timer? _statsTimer;

    public ProtectionEngine()
    {
        _behavior = new BehaviorEngine();
        _browserProtector = new BrowserProtector(_behavior);
        _clipboardProtector = new ClipboardProtector();
        _screenProtector = new ScreenProtector();
        _cameraProtector = new CameraProtector();
        _processGuard = new ProcessGuard(_behavior);
        _grabberScanner = new GrabberScanner(_behavior);
        _logger = ThreatLogger.Instance;

        _processGuard.GrabberCandidateSpotted += _grabberScanner.ScanNow;

        _logger.OnThreatDetected += e => OnThreatDetected?.Invoke(e);
    }

    public void Start()
    {
        if (IsRunning) return;

        _behavior.Start();
        _browserProtector.StartMonitoring();
        _clipboardProtector.StartMonitoring();
        _screenProtector.StartMonitoring();
        _cameraProtector.StartMonitoring();
        _processGuard.StartMonitoring();
        _grabberScanner.StartScanning();

        _statsTimer = new System.Threading.Timer(_ =>
        {
            OnStatsUpdated?.Invoke(GetStats());
        }, null, 0, 1500);

        IsRunning = true;

        _logger.Log(new ThreatEvent
        {
            Type = ThreatType.Unknown,
            ProcessName = "hellstorm",
            ProcessId = Environment.ProcessId,
            TargetPath = "System",
            Action = "PROTECTION_ENGAGED",
            Severity = ThreatSeverity.Low
        });
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _browserProtector.StopMonitoring();
        _clipboardProtector.StopMonitoring();
        _screenProtector.StopMonitoring();
        _cameraProtector.StopMonitoring();
        _processGuard.StopMonitoring();
        _grabberScanner.StopScanning();
        _behavior.Stop();

        _statsTimer?.Dispose();
        IsRunning = false;

        _logger.Log(new ThreatEvent
        {
            Type = ThreatType.Unknown,
            ProcessName = "hellstorm",
            ProcessId = Environment.ProcessId,
            TargetPath = "System",
            Action = "PROTECTION_DISENGAGED",
            Severity = ThreatSeverity.Low
        });
    }

    public ProtectionStats GetStats()
    {
        var stats = _logger.GetStats();
        stats.IsProtected = IsRunning;
        return stats;
    }

    public List<ThreatEvent> GetRecentEvents(int count = 100) => _logger.GetRecentEvents(count);
    public List<BrowserInfo> GetBrowserStatus() => BrowserProtector.GetAllBrowserInfos();

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}