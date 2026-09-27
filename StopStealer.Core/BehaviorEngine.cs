using System.Collections.Concurrent;
using System.Diagnostics;

namespace StopStealer.Core;

/// <summary>
/// Behavioral correlation engine. Watches file-access patterns across a short
/// window and flags multi-target "crawl" signatures that single-file detection
/// would miss (e.g. a stealer reading Login Data, then Cookies, then Local
/// Storage within seconds).
/// </summary>
public class BehaviorEngine : IDisposable
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;

    private sealed class ProcessBehavior
    {
        public readonly object Sync = new();
        public readonly List<(string Path, DateTime When)> Accesses = new();
        public readonly List<string> DistinctRoots = new();
        public int TrustScore = 100;
        public bool Flagged;
    }

    private readonly ConcurrentDictionary<int, ProcessBehavior> _behaviors = new();
    private readonly ConcurrentDictionary<int, string> _pidToName = new();
    private System.Threading.Timer? _purgeTimer;
    private readonly object _purgeLock = new();

    public bool IsRunning { get; private set; }

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        _purgeTimer = new System.Threading.Timer(_ => PurgeOld(), null, 0, 10_000);
    }

    public void Stop()
    {
        IsRunning = false;
        _purgeTimer?.Dispose();
        _purgeTimer = null;
    }

    /// <summary>Feed every protectedfile access here (browser + discord watchers call this).</summary>
    public void RecordFileAccess(string processName, int pid, string path)
    {
        if (pid <= 0) return;
        var lower = path.ToLowerInvariant();
        var root = ProtectedRootable(lower);
        if (root == null) return;

        var behavior = _behaviors.GetOrAdd(pid, _ => new ProcessBehavior());
        lock (behavior.Sync)
        {
            if (behavior.Flagged) return;

            behavior.Accesses.Add((lower, DateTime.UtcNow));
            if (!behavior.DistinctRoots.Contains(root))
                behavior.DistinctRoots.Add(root);

            _pidToName[pid] = processName;

            var cutoff = DateTime.UtcNow.AddSeconds(-45);

            // --- Signature 1: multi-protected-target crawl ---------------------
            var distinct = behavior.DistinctRoots.Count;
            var recentTouches = behavior.Accesses.Count(a => a.When >= cutoff);
            if (distinct >= 3 && recentTouches >= 4)
            {
                Flag(pid, processName, ThreatType.DataCrawl,
                    target: string.Join(" | ", behavior.DistinctRoots.Take(8)),
                    severity: ThreatSeverity.Critical);
                return;
            }

            // --- Signature 2: Discord token storage pattern ---------------------
            if (lower.Contains("leveldb") && (lower.Contains("discord") || lower.Contains("token")))
            {
                var discordTouches = behavior.Accesses.Count(a =>
                    a.Path.Contains("leveldb") &&
                    (a.Path.Contains("discord") || a.Path.Contains("token")) && a.When >= cutoff);
                if (discordTouches >= 3)
                {
                    Flag(pid, processName, ThreatType.DiscordTokenGrabber,
                        target: string.Join(" | ", behavior.DistinctRoots.Where(r => r.Contains("leveldb")).Take(6)),
                        severity: ThreatSeverity.Critical);
                    return;
                }
            }

            // --- Signature 3: rapid-fire on one store --------------------------
            if (recentTouches >= 6 && distinct >= 2)
            {
                Flag(pid, processName, ThreatType.DataCrawl,
                    target: $"{behavior.DistinctRoots.Count} targets, {recentTouches} touches",
                    severity: ThreatSeverity.High);
            }
        }
    }

    /// <summary>Called by ProcessGuard when a suspicious process is about to be killed.</summary>
    public void NoteKill(string processName, int pid)
    {
        _behaviors.TryRemove(pid, out _);
        _pidToName.TryRemove(pid, out _);
    }

    public void SetTrust(int pid, int score)
    {
        if (pid <= 0) return;
        var behavior = _behaviors.GetOrAdd(pid, _ => new ProcessBehavior());
        lock (behavior.Sync) behavior.TrustScore = score;
    }

    private void Flag(int pid, string processName, ThreatType type, string target, ThreatSeverity severity)
    {
        var behavior = _behaviors[pid];
        lock (behavior.Sync) behavior.Flagged = true;

        _logger.Log(new ThreatEvent
        {
            Type = type,
            ProcessName = string.IsNullOrEmpty(processName) ? "(unknown)" : processName,
            ProcessId = pid,
            TargetPath = target,
            Action = "BEHAVIORAL_BLOCK",
            Severity = severity
        });

        Kill(pid);
    }

    private void Kill(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (IsProtectedProcess(proc.ProcessName)) return;
            if (pid == Environment.ProcessId) return;
            proc.Kill(true);
        }
        catch { }
        finally
        {
            _behaviors.TryRemove(pid, out _);
        }
    }

    internal static bool IsProtectedProcess(string processName)
    {
        var n = processName.ToLowerInvariant();
        if (n.Contains("hellstorm") || n.Contains("stopstealer")) return true;
        if (n.StartsWith("ms") || n.StartsWith("svchost") || n.StartsWith("system")) return true;
        foreach (var b in new[] { "chrome", "msedge", "firefox", "brave", "opera", "yandex", "vivaldi", "explorer", "searchhost" })
            if (n.Contains(b)) return true;
        return false;
    }

    private static string? ProtectedRootable(string lower)
    {
        if (lower.Contains("\\appdata\\") || lower.Contains("\\temp\\") || lower.Contains("\\downloads\\"))
            return lower;
        if (lower.Contains("\\discord") && (lower.Contains("leveldb") || lower.Contains("local storage") ||
                                             lower.Contains("session storage") || lower.Contains("indexeddb")))
            return lower;
        return null;
    }

    private void PurgeOld()
    {
        try
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-90);
            foreach (var kv in _behaviors)
            {
                ProcessBehavior b = kv.Value;
                lock (b.Sync)
                {
                    b.Accesses.RemoveAll(a => a.When < cutoff);
                    foreach (var root in b.Accesses.Select(a => ProtectedRootable(a.Path)).Where(r => r != null).Distinct())
                    {
                        if (root != null && !b.DistinctRoots.Contains(root)) b.DistinctRoots.Add(root);
                    }
                    if (b.Accesses.Count == 0 && b.DistinctRoots.Count == 0 && !b.Flagged)
                        _behaviors.TryRemove(kv.Key, out _);
                }
            }
        }
        catch { }
    }

    public void Dispose() => Stop();
}