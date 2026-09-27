using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;

namespace StopStealer.Core;

/// <summary>
/// Real-time process guard. Uses WMI to catch new process creation immediately,
/// scores every process by trust (path, parent chain, loaded modules) and
/// kills anything that matches stealer signatures or low-trust behavior.
/// </summary>
public class ProcessGuard : IDisposable
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private readonly BehaviorEngine _behavior;
    private System.Threading.Timer? _sweepTimer;
    private ManagementEventWatcher? _creationWatcher;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _lock = new();

    private readonly ConcurrentDictionary<int, (string Cmd, long At)> _cmdCache = new();
    private readonly ConcurrentDictionary<int, (bool Has, long At)> _moduleCache = new();
    private readonly ConcurrentDictionary<int, (string Path, long At)> _pathCache = new();
    private Dictionary<int, int>? _parentCache;
    private long _parentCacheAt;
    private const long ParentCacheTtlMs = 5000;
    private const long CmdCacheTtlMs = 3000;
    private const long ModuleCacheTtlMs = 30000;
    private const long PathCacheTtlMs = 30000;

    public bool IsMonitoring { get; private set; }

    public event Action<int>? GrabberCandidateSpotted;

    private static readonly Regex HwidGrabRegex = new(
        @"(wmic|baseboard|csproduct|diskdrive|processor|win32_).{0,60}(uuid|serialnumber|processorid|uniqueid)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly string[] KnownMaliciousPatterns = new[]
    {
        "grab", "steal", "token", "clipper", "miner", "keylog",
        "dump", "extract", "crack", "exploit", "inject", "sniff",
        "reverse", "trojan", "backdoor", "rootkit", "spyware", "rat",
        "redline", "raccoon", "vidar", "azorult", "smoke",
        "emotet", "trickbot", "qakbot", "formbook", "agenttesla",
        "lumma", "risepro", "atomic", "amadey", "ducktail",
        "stealc", "mystic", "tycoon", "lu0", "ghost", "wacatac",
        "blank", "mercurial", "whitesnake", "kpot", "erofs",
        "yggrasil", "taurux", "shadow", "xmrig", "cpu-miner", "wildix"
    };

    private static readonly string[] KnownStealerFamily = new[]
    {
        "redline", "raccoon", "vidar", "azorult", "racoonstealer",
        "lumma", "rise pro", "risepro", "stealc", "mystic", "tycoon",
        "shanghai", "record", "saturn", "anticheat", "krd", "wacatac",
        "blankgrabber", "mercurialgrabber", "taurux", "kpot", "whitesnake",
        "grabber", "stealer", "hollow", "arcane", "shadowsteal"
    };

    private static readonly string[] SafeProcesses = new[]
    {
        "chrome", "msedge", "firefox", "brave", "opera", "librewolf",
        "yandex", "vivaldi", "iexplore", "stopstealer", "hellstorm",
        "explorer", "cmd", "powershell", "conhost", "pwsh",
        "taskmgr", "searchhost", "startmenuexperiencehost",
        "shellexperiencehost", "textinputhost", "dllhost",
        "runtimebroker", "ctfmon", "dwm", "sihost",
        "apphost", "widgets", "msedgewebview2", "applicationframehost",
        "systemsettings", "shell", "fontdrvhost", "smartscreen",
        "backgroundtaskhost", "settings", "winlogon", "wininit",
        "csrss", "services", "svchost", "lsass", "smss",
        "idle", "registry", "audiodg", "spoolsv", "wmiprvse",
        "dllhost", "santediag", "ocoainit64", "sinkhole", "agsclient"
    };

    private static readonly string[] LowTrustLocations = new[]
    {
        "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
        "\\appdata\\roaming\\", "\\startup\\", "\\microsoft\\windows\\start menu\\programs\\startup\\"
    };

    private static readonly string[] StealerSqliteDlls = new[]
    {
        "sqlite3.dll", "wxsqlite3.dll", "e_sqlite3.dll", "sqlite-modern",
        "leveldb.dll", "lsqlite3", "sqlite-wrap"
    };

    private static readonly Regex WebhookUrlRegex = new(
        @"(https?://)?(www\.)?(discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex TokenStorageRegex = new(
        @"(leveldb|Local Storage|Session Storage|IndexedDB|Login Data|Cookies|Web Data|os_crypt|encrypted_key|dQw4w9WgXcQ)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public ProcessGuard(BehaviorEngine behavior)
    {
        _behavior = behavior;
    }

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        SeedKnownPids();
        StartCreationWatcher();
        StartSweeper();
    }

    public void StopMonitoring()
    {
        IsMonitoring = false;
        _creationWatcher?.Stop();
        _creationWatcher = null;
        _sweepTimer?.Dispose();
        _sweepTimer = null;
    }

    private void SeedKnownPids()
    {
        lock (_lock)
        {
            _knownPids.Clear();
            foreach (var p in Process.GetProcesses())
            {
                try { _knownPids.Add(p.Id); } catch { }
            }
        }
    }

    // ---------- Real-time process creation (WMI) ----------
    private void StartCreationWatcher()
    {
        try
        {
            var query = new WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
            _creationWatcher = new ManagementEventWatcher(query);
            _creationWatcher.EventArrived += OnProcessCreated;
            _creationWatcher.Start();
        }
        catch
        {
            // WMI unavailable -> rely on the fast sweep timer only
        }
    }

    private void OnProcessCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var mo = new ManagementObject(e.NewEvent["TargetInstance"] as string ?? "");
            var pid = Convert.ToInt32(mo["ProcessId"]);
            var name = TryGet(mo, "Name") ?? "";
            var path = TryGet(mo, "ExecutablePath") ?? "";
            var cmdline = TryGet(mo, "CommandLine") ?? "";

            if (string.IsNullOrEmpty(name)) return;
            var lowerName = name.ToLowerInvariant();

            if (BehaviorEngine.IsProtectedProcess(lowerName)) return;

            int parentPid = 0;
            try { parentPid = Convert.ToInt32(mo["ParentProcessId"]); }
            catch { }

            var verdict = EvaluateNewProcess(name, path, cmdline);
            var hwidMatch = HwidGrabRegex.IsMatch(cmdline);
            if (verdict != null)
            {
                _logger.Log(new ThreatEvent
                {
                    Type = verdict.Value.Type,
                    ProcessName = name,
                    ProcessId = pid,
                    TargetPath = string.IsNullOrEmpty(path) ? cmdline : path,
                    Action = "REALTIME_BLOCK",
                    Severity = verdict.Value.Severity
                });
                Kill(pid);
                _behavior.NoteKill(name, pid);
                if (hwidMatch) TryKillScriptParent(parentPid);
            }
            else
            {
                lock (_lock) _knownPids.Add(pid);
                if (hwidMatch) TryKillScriptParent(parentPid);
                if (GrabberScanner.IsCandidateProcess(name, path))
                    GrabberCandidateSpotted?.Invoke(pid);
            }
        }
        catch { }
    }

    private void TryKillScriptParent(int parentPid)
    {
        if (parentPid <= 0) return;
        try
        {
            using var parent = Process.GetProcessById(parentPid);
            var pn = parent.ProcessName;
            var ppath = GetProcessPathSafe(parent);
            if (GrabberScanner.IsInterpreter(pn) || GrabberScanner.IsLowTrustPath(ppath))
                Kill(parentPid);
        }
        catch { }
    }

    private (ThreatType Type, ThreatSeverity Severity)? EvaluateNewProcess(string name, string path, string cmdline)
    {
        var n = name.ToLowerInvariant();
        var p = path.ToLowerInvariant();
        var c = cmdline.ToLowerInvariant();

        foreach (var safe in SafeProcesses)
            if (n.Contains(safe)) return null;

        // Command line reveals webhook / token store targeting?
        if (WebhookUrlRegex.IsMatch(cmdline))
            return (ThreatType.WebhookExfil, ThreatSeverity.Critical);
        if (TokenStorageRegex.IsMatch(cmdline) && (c.Contains("webhook") || c.Contains("post") || c.Contains("http")))
            return (ThreatType.TokenGrabAttempt, ThreatSeverity.Critical);

        // HWID harvesting (wmic csproduct get uuid etc.) from a scripted parent
        if (HwidGrabRegex.IsMatch(cmdline) &&
            (GrabberScanner.IsInterpreter(name) || GrabberScanner.IsLowTrustPath(path)))
            return (ThreatType.CredentialDumper, ThreatSeverity.Critical);

        // Known stealer family
        foreach (var family in KnownStealerFamily)
        {
            if (n.Contains(family) || p.Contains(family))
                return (ThreatType.SuspiciousProcess, ThreatSeverity.Critical);
        }

        foreach (var pattern in KnownMaliciousPatterns)
        {
            if (!n.Contains(pattern)) continue;

            // Only auto-kill malicious-pattern matches when they're in a low-trust location,
            // to avoid false positives on legitimate tools.
            foreach (var loc in LowTrustLocations)
            {
                if (p.Contains(loc))
                    return (ThreatType.SuspiciousProcess, ThreatSeverity.Critical);
            }
        }

        return null;
    }

    // ---------- Periodic deep sweep ----------
    private void StartSweeper()
    {
        _sweepTimer = new System.Threading.Timer(_ => Sweep(), null, 2500, 2500);
    }

    private void Sweep()
    {
        if (!IsMonitoring) return;
        try
        {
            // Cheap WMI query (ProcessId + Name only) - ExecutablePath in WMI
            // is slow, so we fetch it lazily per process via a cached helper.
            var rows = QueryAllProcessNames();
            if (rows == null) return;

            // Build parent map once per sweep (cached).
            var parentMap = GetParentMapCached();

            // Prune caches for processes that no longer exist.
            var liveIds = new HashSet<int>(rows.Count);
            foreach (var r in rows) liveIds.Add(r.Pid);
            foreach (var key in _cmdCache.Keys) if (!liveIds.Contains(key)) _cmdCache.TryRemove(key, out _);
            foreach (var key in _moduleCache.Keys) if (!liveIds.Contains(key)) _moduleCache.TryRemove(key, out _);
            foreach (var key in _pathCache.Keys) if (!liveIds.Contains(key)) _pathCache.TryRemove(key, out _);

            foreach (var row in rows)
            {
                try
                {
                    var n = row.Name.ToLowerInvariant();
                    if (BehaviorEngine.IsProtectedProcess(n)) continue;
                    if (SafeProcesses.Any(s => n.Contains(s))) continue;

                    var path = GetPathCached(row.Pid);
                    var verdict = DeepEvaluate(row.Name, path, row.Pid, parentMap);
                    if (verdict != null)
                    {
                        _logger.Log(new ThreatEvent
                        {
                            Type = verdict.Value.Type,
                            ProcessName = row.Name,
                            ProcessId = row.Pid,
                            TargetPath = string.IsNullOrEmpty(path) ? row.Name : path,
                            Action = verdict.Value.Action,
                            Severity = verdict.Value.Severity
                        });

                        if (verdict.Value.Action == "BLOCKED")
                        {
                            Kill(row.Pid);
                            _behavior.NoteKill(row.Name, row.Pid);
                        }
                        else
                        {
                            _behavior.SetTrust(row.Pid, verdict.Value.TrustScore);
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static List<(int Pid, string Name)>? QueryAllProcessNames()
    {
        var rows = new List<(int, string)>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name FROM Win32_Process");
            foreach (ManagementBaseObject o in searcher.Get())
            {
                try
                {
                    rows.Add((Convert.ToInt32(o["ProcessId"]), o["Name"]?.ToString() ?? ""));
                }
                catch { }
            }
            return rows;
        }
        catch { return null; }
    }

    private Dictionary<int, int> GetParentMapCached()
    {
        var now = Environment.TickCount64;
        if (_parentCache != null && now - _parentCacheAt < ParentCacheTtlMs)
            return _parentCache;
        var map = BuildParentMap();
        _parentCache = map;
        _parentCacheAt = now;
        return map;
    }

    private Dictionary<int, int> BuildParentMap()
    {
        var map = new Dictionary<int, int>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId FROM Win32_Process");
            foreach (ManagementBaseObject o in searcher.Get())
            {
                try
                {
                    var pid = Convert.ToInt32(o["ProcessId"]);
                    var ppid = Convert.ToInt32(o["ParentProcessId"]);
                    map[pid] = ppid;
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    private (ThreatType Type, ThreatSeverity Severity, string Action, int TrustScore)? DeepEvaluate(
        string name, string path, int pid, Dictionary<int, int> parentMap)
    {
        var n = name.ToLowerInvariant();
        if (BehaviorEngine.IsProtectedProcess(n)) return null;
        foreach (var safe in SafeProcesses)
            if (n.Contains(safe)) return null;

        var p = (string.IsNullOrEmpty(path) ? name : path).ToLowerInvariant();

        // Trust score starts at 100; knock points off for risky residence.
        int trust = 100;
        bool inLowTrust = LowTrustLocations.Any(l => p.Contains(l));
        if (p.Contains("\\temp\\") || p.Contains("\\appdata\\local\\temp\\")) trust -= 55;
        else if (p.Contains("\\downloads\\")) trust -= 35;
        else if (p.Contains("\\appdata\\roaming\\")) trust -= 25;
        else if (p.Contains("\\appdata\\")) trust -= 10;

        // High-trust, non-interpreter processes rarely need a WMI command-line
        // query; only fetch it when the process is already interesting, which
        // keeps the sweep cheap (WMI is the main perf killer).
        string? cmdline = null;
        bool cmdContext = inLowTrust || GrabberScanner.IsInterpreter(n) ||
                          KnownStealerFamily.Any(f => n.Contains(f)) ||
                          KnownMaliciousPatterns.Any(x => n.Contains(x));
        if (cmdContext)
            cmdline = GetCommandLineCached(pid);

        // Hidden attribute exe in temp is a classic stealer drop.
        try
        {
            var fi = new FileInfo(p);
            if ((fi.Attributes & FileAttributes.Hidden) != 0) trust -= 30;
        }
        catch { }

        // Parent chain: a temp process spawned from another temp process is worse.
        if (parentMap.TryGetValue(pid, out var ppid) && ppid != 0 && ppid != pid && IsTempPid(ppid, parentMap))
            trust -= 25;

        // Unsigned, tiny, recently-created in temp
        if (inLowTrust && trust <= 45)
        {
            try
            {
                var fi = new FileInfo(p);
                if ((DateTime.Now - fi.CreationTime).TotalMinutes < 30) trust -= 15;
            }
            catch { }
        }

        // Name + location based blocks
        foreach (var pattern in KnownMaliciousPatterns)
        {
            if (n.Contains(pattern) && inLowTrust)
                return (ThreatType.SuspiciousProcess, ThreatSeverity.Critical, "BLOCKED", 0);
        }

        // sqlite/dpapi module loaded by a low-trust process is a strong stealer signal
        if (inLowTrust && trust <= 45 && HasSuspiciousModulesCached(pid))
            return (ThreatType.CryptUnprotectData, ThreatSeverity.Critical, "BLOCKED", 0);

        // Command line shows webhook exfiltration
        if (!string.IsNullOrEmpty(cmdline) && WebhookUrlRegex.IsMatch(cmdline))
            return (ThreatType.WebhookExfil, ThreatSeverity.Critical, "BLOCKED", 0);

        // Command line referencing browser token stores from a non-browser process
        if (!string.IsNullOrEmpty(cmdline) && TokenStorageRegex.IsMatch(cmdline) && !n.Contains("chrome") &&
            !n.Contains("edge") && !n.Contains("firefox"))
            return (ThreatType.TokenGrabAttempt, ThreatSeverity.High, "MONITORING", trust);

        // HWID harvesting during sweep (catches already-running parents)
        if (!string.IsNullOrEmpty(cmdline) && HwidGrabRegex.IsMatch(cmdline) &&
            (inLowTrust || GrabberScanner.IsInterpreter(n)))
            return (ThreatType.CredentialDumper, ThreatSeverity.Critical, "BLOCKED", 0);

        // Feed trust into behavior engine
        if (trust < 100)
            _behavior.SetTrust(pid, trust);

        if (trust <= 25)
            return (ThreatType.SuspiciousProcess, ThreatSeverity.High, "MONITORING", trust);

        return null;
    }

    private bool IsTempPid(int pid, Dictionary<int, int> parentMap)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var path = GetProcessPathSafe(p);
            return path.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return parentMap.ContainsKey(pid); // unknown parent in map = still alive
        }
    }

    private static bool HasSuspiciousModules(Process proc)
    {
        try
        {
            foreach (ProcessModule module in proc.Modules)
            {
                var mn = module.ModuleName.ToLowerInvariant();
                foreach (var dll in StealerSqliteDlls)
                {
                    if (String.Equals(mn, dll, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static string GetProcessPathSafe(Process proc)
    {
        try { return proc.MainModule?.FileName ?? proc.ProcessName; }
        catch { return proc.ProcessName; }
    }

    private static string? GetCommandLineSafe(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}");
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject o in results)
                {
                    try { return o["CommandLine"]?.ToString(); }
                    catch { }
                }
            }
        }
        catch { }
        return null;
    }

    private string? GetCommandLineCached(int pid)
    {
        var now = Environment.TickCount64;
        if (_cmdCache.TryGetValue(pid, out var cached) && now - cached.At < CmdCacheTtlMs)
            return cached.Cmd;
        var cmd = GetCommandLineSafe(pid);
        _cmdCache[pid] = (cmd ?? "", now);
        return cmd;
    }

    private string GetPathCached(int pid)
    {
        var now = Environment.TickCount64;
        if (_pathCache.TryGetValue(pid, out var cached) && now - cached.At < PathCacheTtlMs)
            return cached.Path;
        string path;
        try
        {
            using var proc = Process.GetProcessById(pid);
            path = GetProcessPathSafe(proc);
        }
        catch { path = ""; }
        _pathCache[pid] = (path, now);
        return path;
    }

    private bool HasSuspiciousModulesCached(int pid)
    {
        var now = Environment.TickCount64;
        if (_moduleCache.TryGetValue(pid, out var cached) && now - cached.At < ModuleCacheTtlMs)
            return cached.Has;
        bool has = false;
        try
        {
            using var proc = Process.GetProcessById(pid);
            has = HasSuspiciousModules(proc);
        }
        catch { }
        _moduleCache[pid] = (has, now);
        return has;
    }

    private void Kill(int pid)
    {
        try
        {
            if (pid == Environment.ProcessId) return;
            using var proc = Process.GetProcessById(pid);
            proc.Kill(true);
        }
        catch { }
    }

    private static string? TryGet(ManagementBaseObject mo, string key)
    {
        try { return mo[key]?.ToString(); }
        catch { return null; }
    }

    public void Dispose() => StopMonitoring();
}