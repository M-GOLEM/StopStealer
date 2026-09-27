using System.Diagnostics;
using System.Text.RegularExpressions;

namespace StopStealer.Core;

public class BrowserProtector
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private readonly BehaviorEngine _behavior;

    private FileSystemWatcher? _browserWatcher;
    private FileSystemWatcher? _discordWatcher;
    private System.Threading.Timer? _discordTokenTimer;
    private System.Threading.Timer? _memoryScanTimer;
    private FileSystemWatcher? _tempWatcher;

    public bool IsMonitoring { get; private set; }

    private static readonly string[] SensitiveFiles = new[]
    {
        "login data", "cookies", "web data", "local state", "preferences", "secure preferences",
        "history", "bookmarks", "autofill", "top sites", "current session", "current tabs",
        "favicons", "shortcuts", "archived history", "client side phishing", "account",
        "cookies.sqlite", "logins.json", "key4.db", "cert9.db", "cert8.db",
        "formhistory.sqlite", "places.sqlite", "permissions.sqlite", "content-prefs.sqlite",
        "storage.sqlite", "favicons.sqlite", "webappsstore.sqlite", "signons.sqlite",
        "login data-journal", "cookies-journal", "web data-journal"
    };

    private static readonly string[] BrowserFolders = new[]
    {
        "\\chrome\\", "\\edge\\", "\\firefox\\", "\\brave\\", "\\opera\\",
        "\\yandex\\", "\\vivaldi\\", "\\chromium\\", "\\librewolf\\", "\\waterfox\\",
        "\\palemoon\\", "\\google\\chrome\\", "\\microsoft\\edge\\", "\\mozilla\\firefox\\",
        "\\bravesoftware\\", "\\opera software\\", "\\user data\\", "\\profiles\\"
    };

    private static readonly string[] DiscordTokenStorageNames = new[]
    {
        "leveldb", "local storage", "session storage", "indexeddb", "cookies"
    };

    private static readonly Regex DiscordTokenRegex = new(
        @"mfa\.[A-Za-z0-9_-]{80,}|[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly string[] StealerIndicators = new[]
    {
        "dQw4w9WgXcQ:", "os_crypt", "encrypted_key", "CryptUnprotectData",
        "cryptunprotect", "dpapi", "decrypt", "leveldb", "token", "webhook",
        "sqlite", "discord_token"
    };

    private static readonly string[] DiscordInjectionDlls = new[]
    {
        "inject", "detour", "easyhook", "minhook", "mhook", "hook",
        "overlay", "discordstealer", "bluestacks" // bluestacks steals via emu
    };

    private readonly HashSet<string> _watchedBrowserDirs = new(StringComparer.OrdinalIgnoreCase);

    public BrowserProtector(BehaviorEngine behavior)
    {
        _behavior = behavior;
    }

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        StartBrowserWatcher();
        StartDiscordWatcher();
        StartDiscordTokenMonitor();
        StartTempDumpWatch();
    }

    public void StopMonitoring()
    {
        IsMonitoring = false;
        _browserWatcher?.Dispose();
        _browserWatcher = null;
        _discordWatcher?.Dispose();
        _discordWatcher = null;
        _tempWatcher?.Dispose();
        _tempWatcher = null;
        _discordTokenTimer?.Dispose();
        _discordTokenTimer = null;
        _memoryScanTimer?.Dispose();
        _memoryScanTimer = null;
    }

    #region Browser Watcher

    private void StartBrowserWatcher()
    {
        foreach (var config in GetBrowserConfigs())
        {
            if (!Directory.Exists(config.UserDataPath)) continue;
            if (_watchedBrowserDirs.Contains(config.UserDataPath)) continue;
            _watchedBrowserDirs.Add(config.UserDataPath);

            try
            {
                var watcher = new FileSystemWatcher(config.UserDataPath)
                {
                    NotifyFilter = NotifyFilters.LastWrite |
                                   NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };
                watcher.Created += OnBrowserFileEvent;
                watcher.Changed += OnBrowserFileEvent;
                watcher.Renamed += OnBrowserFileRenamed;
                _browserWatcher = watcher;
            }
            catch { }
        }
    }

    private void OnBrowserFileEvent(object sender, FileSystemEventArgs e)
    {
        var fullPath = e.FullPath.ToLowerInvariant();

        if (!IsSensitiveBrowserFile(fullPath)) return;

        var accessing = FindSuspiciousAccessor(e.FullPath);
        if (accessing == null) return;

        var suspect = GrabberScanner.IsCandidateProcess(
            accessing.ProcessName, GetProcessPathSafe(accessing).ToLowerInvariant());

        if (suspect) _behavior.RecordFileAccess(accessing.ProcessName, accessing.Id, e.FullPath);

        _logger.Log(new ThreatEvent
        {
            Type = ThreatType.BrowserDataAccess,
            ProcessName = accessing.ProcessName,
            ProcessId = accessing.Id,
            TargetPath = e.FullPath,
            Action = suspect ? "BLOCKED" : "MONITORING",
            Severity = suspect ? ThreatSeverity.High : ThreatSeverity.Medium
        });

        if (suspect) TryKill(accessing.Id);
    }

    private void OnBrowserFileRenamed(object sender, RenamedEventArgs e)
    {
        var oldPath = e.OldFullPath.ToLowerInvariant();
        if (!IsSensitiveBrowserFile(oldPath) || oldPath.EndsWith(".tmp")) return;

        var accessing = FindSuspiciousAccessor(e.FullPath);
        if (accessing == null) return;

        _logger.Log(new ThreatEvent
        {
            Type = ThreatType.BrowserDataAccess,
            ProcessName = accessing.ProcessName,
            ProcessId = accessing.Id,
            TargetPath = e.FullPath,
            Action = "BLOCKED_RENAME",
            Severity = ThreatSeverity.High
        });
    }

    #endregion

    #region Discord Watcher

    private void StartDiscordWatcher()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var discordPaths = new[]
        {
            Path.Combine(appData, "discord"),
            Path.Combine(localAppData, "discord"),
            Path.Combine(appData, "discordcanary"),
            Path.Combine(appData, "discordptb"),
            Path.Combine(appData, "lightcord"),
            Path.Combine(appData, "discorddevelopment")
        };

        foreach (var discordPath in discordPaths)
        {
            if (!Directory.Exists(discordPath)) continue;

            try
            {
                var watcher = new FileSystemWatcher(discordPath)
                {
                    NotifyFilter = NotifyFilters.LastWrite |
                                   NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };
                watcher.Created += OnDiscordFileEvent;
                watcher.Changed += OnDiscordFileEvent;
                _discordWatcher = watcher;
                break;
            }
            catch { }
        }
    }

    private void OnDiscordFileEvent(object sender, FileSystemEventArgs e)
    {
        var fullPath = e.FullPath.ToLowerInvariant();
        var name = e.Name?.ToLowerInvariant() ?? "";
        var accessing = FindSuspiciousAccessor(e.FullPath);
        if (accessing == null) return;

        if (IsDiscordTokenFile(fullPath, name))
        {
            var suspect = GrabberScanner.IsCandidateProcess(
                accessing.ProcessName, GetProcessPathSafe(accessing).ToLowerInvariant());
            if (suspect) _behavior.RecordFileAccess(accessing.ProcessName, accessing.Id, e.FullPath);
            _logger.Log(new ThreatEvent
            {
                Type = ThreatType.DiscordTokenGrabber,
                ProcessName = accessing.ProcessName,
                ProcessId = accessing.Id,
                TargetPath = e.FullPath,
                Action = suspect ? "BLOCKED" : "MONITORING",
                Severity = ThreatSeverity.Critical
            });
            if (suspect) TryKill(accessing.Id);
        }
        else if (name.Contains("webhook") || fullPath.Contains("webhook") ||
                 readerPathLooksLikeDump(fullPath))
        {
            var suspect = GrabberScanner.IsCandidateProcess(
                accessing.ProcessName, GetProcessPathSafe(accessing).ToLowerInvariant());
            _logger.Log(new ThreatEvent
            {
                Type = ThreatType.DiscordWebhookExfil,
                ProcessName = accessing.ProcessName,
                ProcessId = accessing.Id,
                TargetPath = e.FullPath,
                Action = suspect ? "BLOCKED" : "MONITORING",
                Severity = ThreatSeverity.Critical
            });
            if (suspect) TryKill(accessing.Id);
        }
    }

    #endregion

    #region Discord Token Deep Scan

    private void StartDiscordTokenMonitor()
    {
        _discordTokenTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                var dirs = new[]
                {
                    Path.Combine(appData, "discord"),
                    Path.Combine(appData, "discordcanary"),
                    Path.Combine(appData, "discordptb"),
                    Path.Combine(appData, "lightcord"),
                    Path.Combine(appData, "discorddevelopment")
                };

                foreach (var baseDir in dirs)
                {
                    if (!Directory.Exists(baseDir)) continue;

                    foreach (var sub in new[] { "Local Storage", "Session Storage", "IndexedDB" })
                    {
                        var dir = Path.Combine(baseDir, sub);
                        if (!Directory.Exists(dir)) continue;
                        ScanDirDeep(dir);
                    }
                }
            }
            catch { }
        }, null, 5000, 5000);
    }

    private void ScanDirDeep(string dir)
    {
        try
        {
            foreach (var file in SafeEnumerateFiles(dir, "*.log", "*.ldb"))
            {
                try
                {
                    var content = File.ReadAllText(file);
                    var match = DiscordTokenRegex.IsMatch(content);

                    if (match || content.Contains("dQw4w9WgXcQ:", StringComparison.OrdinalIgnoreCase))
                    {
                        // Informational only. Attribution at scan-time is unreliable,
                        // so we never kill from here; the real-time memory scanner
                        // (GrabberScanner) and WMI process guard do the blocking.
                        _logger.Log(new ThreatEvent
                        {
                            Type = ThreatType.DiscordTokenGrabber,
                            ProcessName = "(deep scan)",
                            ProcessId = 0,
                            TargetPath = file,
                            Action = "TOKEN_FILE_FOUND",
                            Severity = ThreatSeverity.High
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    #endregion

    #region Memory / Module Scan

    private void StartMemoryScan()
    {
        _memoryScanTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var n = proc.ProcessName.ToLowerInvariant();
                        if (BehaviorEngine.IsProtectedProcess(n)) continue;
                        if (n.Contains("chrome") || n.Contains("edge") || n.Contains("firefox") ||
                            n.Contains("brave") || n.Contains("opera") || n.Contains("yandex")) continue;

                        var path = GetProcessPathSafe(proc).ToLowerInvariant();

                        var inLowTrust = path.Contains("\\temp\\") || path.Contains("\\downloads\\") ||
                                         path.Contains("\\appdata\\local\\temp\\");
                        if (!inLowTrust) continue;

                        var hasSqlite = HasModule(proc, "sqlite");
                        var hasCrypt = HasModule(proc, "crypt");

                        if (hasSqlite && hasCrypt)
                        {
                            _logger.Log(new ThreatEvent
                            {
                                Type = ThreatType.CryptUnprotectData,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                TargetPath = path,
                                Action = "BLOCKED",
                                Severity = ThreatSeverity.Critical
                            });
                            TryKill(proc.Id);
                            _behavior.NoteKill(proc.ProcessName, proc.Id);
                        }
                        else if (hasSqlite)
                        {
                            _logger.Log(new ThreatEvent
                            {
                                Type = ThreatType.MemoryScanner,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                TargetPath = path,
                                Action = "MONITORING",
                                Severity = ThreatSeverity.Medium
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, null, 0, 5000);
    }

    private static bool HasModule(Process proc, string search)
    {
        try
        {
            foreach (ProcessModule module in proc.Modules)
            {
                if (String.IsNullOrEmpty(module.ModuleName)) continue;
                if (module.ModuleName.ToLowerInvariant().Contains(search)) return true;
            }
        }
        catch { }
        return false;
    }

    #endregion

    #region Temp Dump Watch

    private void StartTempDumpWatch()
    {
        var temp = Path.GetTempPath();
        if (!Directory.Exists(temp)) return;

        try
        {
            var watcher = new FileSystemWatcher(temp)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };
            watcher.Created += OnTempFileCreated;
            _tempWatcher = watcher;
        }
        catch { }
    }

    private void OnTempFileCreated(object sender, FileSystemEventArgs e)
    {
        var name = e.Name?.ToLowerInvariant() ?? "";
        if (name.Contains("_temp") || name.Contains("export") || name.Contains("dump") ||
            name.Contains("cookies") || name.Contains("login") || name.Contains("leveldb") ||
            name.Contains("password") || name.Contains("token"))
        {
            var creator = FindSuspiciousAccessor(e.FullPath);
            if (creator != null)
            {
                _logger.Log(new ThreatEvent
                {
                    Type = ThreatType.DataCrawl,
                    ProcessName = creator.ProcessName,
                    ProcessId = creator.Id,
                    TargetPath = e.FullPath,
                    Action = "STOLEN_DATA_COPY",
                    Severity = ThreatSeverity.Critical
                });
                TryKill(creator.Id);
            }
        }
    }

    #endregion

    #region Accessor Detection

    private static Process? FindSuspiciousAccessor(string filePath)
    {
        try
        {
            var browserNames = new[]
            {
                "chrome", "msedge", "firefox", "brave", "opera", "yandex",
                "vivaldi", "iexplore", "librewolf", "waterfox", "palemoon",
                "system", "svchost", "stopstealer", "hellstorm", "searchhost",
                "backgroundtaskhost", "applicationframehost", "explorer"
            };

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (browserNames.Any(b => name.Contains(b))) continue;

                    var path = GetProcessPathSafe(proc).ToLowerInvariant();
                    if (string.IsNullOrEmpty(path) || path == name) continue;

                    if (path.Contains("\\temp\\") || path.Contains("\\appdata\\local\\temp\\") ||
                        path.Contains("\\downloads\\") || path.Contains("\\appdata\\roaming\\") && !path.Contains("\\discord\\"))
                    {
                        return proc;
                    }
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    private void TryKill(int pid)
    {
        try
        {
            if (pid <= 0) return;
            using var proc = Process.GetProcessById(pid);
            if (BehaviorEngine.IsProtectedProcess(proc.ProcessName)) return;
            if (pid == Environment.ProcessId) return;
            proc.Kill(true);
        }
        catch { }
    }

    #endregion

    #region Helpers

    private static IEnumerable<string> SafeEnumerateFiles(string dir, params string[] patterns)
    {
        var list = new List<string>();
        try
        {
            foreach (var pat in patterns)
            {
                try { list.AddRange(Directory.GetFiles(dir, pat, SearchOption.AllDirectories)); }
                catch { }
            }
        }
        catch { }
        return list;
    }

    private static bool readerPathLooksLikeDump(string fullPath)
    {
        var lower = fullPath.ToLowerInvariant();
        return lower.Contains("\\temp\\") || lower.Contains("\\downloads\\") ||
               lower.Contains("\\recycle");
    }

    private static bool IsSensitiveBrowserFile(string path)
    {
        var lower = path.ToLowerInvariant();
        bool inBrowser = BrowserFolders.Any(f => lower.Contains(f));
        return inBrowser && SensitiveFiles.Any(f => lower.EndsWith(f));
    }

    private static bool IsDiscordTokenFile(string fullPath, string name)
    {
        return fullPath.Contains("discord") &&
               DiscordTokenStorageNames.Any(s => fullPath.Contains(s));
    }

    public static List<BrowserInfo> GetAllBrowserInfos()
    {
        var browsers = new List<BrowserInfo>();
        foreach (var config in GetBrowserConfigs())
        {
            browsers.Add(new BrowserInfo
            {
                Name = config.Name,
                ProcessName = config.ProcessName,
                UserDataPath = config.UserDataPath,
                LocalStatePath = Path.Combine(config.UserDataPath, "Local State"),
                IsRunning = Process.GetProcessesByName(config.ProcessName).Length > 0
            });
        }
        return browsers;
    }

    private static IEnumerable<(string Name, string ProcessName, string UserDataPath)> GetBrowserConfigs()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return new List<(string, string, string)>
        {
            ("Chrome", "chrome", Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge", "msedge", Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Firefox", "firefox", Path.Combine(roaming, "Mozilla", "Firefox", "Profiles")),
            ("Brave", "brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Opera", "opera", Path.Combine(roaming, "Opera Software", "Opera Stable")),
            ("Opera GX", "opera", Path.Combine(roaming, "Opera Software", "Opera GX Stable")),
            ("Vivaldi", "vivaldi", Path.Combine(local, "Vivaldi", "User Data")),
            ("Yandex", "browser", Path.Combine(local, "Yandex", "YandexBrowser", "User Data")),
            ("LibreWolf", "librewolf", Path.Combine(roaming, "LibreWolf", "Profiles")),
            ("Waterfox", "waterfox", Path.Combine(roaming, "Waterfox", "Profiles")),
        };
    }

    private static string GetProcessPathSafe(Process proc)
    {
        try { return proc.MainModule?.FileName ?? proc.ProcessName; }
        catch { return proc.ProcessName; }
    }

    #endregion
}