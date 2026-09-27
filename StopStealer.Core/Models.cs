namespace StopStealer.Core;

public class ThreatEvent
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public ThreatType Type { get; set; }
    public string ProcessName { get; set; } = "";
    public int ProcessId { get; set; }
    public string TargetPath { get; set; } = "";
    public string Action { get; set; } = "";
    public ThreatSeverity Severity { get; set; }
}

public enum ThreatType
{
    BrowserDataAccess,
    TokenGrabAttempt,
    ScreenshotAttempt,
    CameraAccess,
    ClipboardTheft,
    SuspiciousProcess,
    PasswordFileAccess,
    CookieFileAccess,
    CreditCardAccess,
    Keylogger,
    ProcessInjection,
    DiscordTokenGrabber,
    DiscordWebhookExfil,
    DiscordInjection,
    CryptUnprotectData,
    DataCrawl,
    WebhookExfil,
    SuspiciousChildProcess,
    MemoryScanner,
    CredentialDumper,
    Unknown
}

public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public class ProtectionRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public RuleType Type { get; set; }
    public string Pattern { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool BlockByDefault { get; set; } = true;
    public List<string> WhitelistedProcesses { get; set; } = new();
}

public enum RuleType
{
    ProcessBlock,
    FileAccessBlock,
    RegistryBlock,
    NetworkBlock,
    BehavioralSignature
}

public class ProtectionStats
{
    public long TotalThreatsBlocked { get; set; }
    public long BrowserAttacksBlocked { get; set; }
    public long TokenStealsPrevented { get; set; }
    public long ScreenshotBlocks { get; set; }
    public long ClipboardBlocks { get; set; }
    public long SuspiciousProcessBlocks { get; set; }
    public long DiscordTokenBlocks { get; set; }
    public long DiscordWebhookBlocks { get; set; }
    public long DiscordInjectionBlocks { get; set; }
    public long CryptUnprotectBlocks { get; set; }
    public DateTime LastThreatTime { get; set; }
    public bool IsProtected { get; set; }
}

public class BrowserInfo
{
    public string Name { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string UserDataPath { get; set; } = "";
    public string LocalStatePath { get; set; } = "";
    public bool IsRunning { get; set; }
}
