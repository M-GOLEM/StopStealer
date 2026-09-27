using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace StopStealer.Core;

/// <summary>
/// Runtime token-grabber scanner. Read-based stealers (Golem, Vare, Ayhu and
/// friends) never create/write files, so FileSystemWatcher cannot see them.
/// This scanner instead hunts their process memory for the signatures every
/// grabber MUST hold in memory while it runs:
///   - "dQw4w9WgXcQ"      the leveldb token-dump prefix (grabber-only marker)
///   - discord webhook    the exfiltration URL
///   - CryptUnprotectData / os_crypt / encrypted_key   DPAPI master-key decrypt
///   - "users/@me"        the token-validation API endpoint
/// and kills the process the moment the combination appears.
/// </summary>
public sealed class GrabberScanner : IDisposable
{
    private readonly ThreatLogger _logger = ThreatLogger.Instance;
    private readonly BehaviorEngine _behavior;
    private System.Threading.Timer? _timer;
    private readonly ConcurrentDictionary<int, long> _lastScan = new();

    public bool IsScanning { get; private set; }

    private const long ScanCooldownMs = 6000;
    private const long MaxBytesPerProcess = 64L * 1024 * 1024;
    private const long MaxScanTimeMs = 800;

    private static readonly string[] ShortInterpreters = new[]
    {
        "py", "php", "perl", "ruby", "lua", "cscript", "wscript", "mshta",
        "jscript", "powershell", "pwsh", "deno", "bun"
    };

    private static readonly string[] LowTrustMarkers = new[]
    {
        "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\appdata\\roaming\\"
    };

    public GrabberScanner(BehaviorEngine behavior)
    {
        _behavior = behavior;
    }

    public void StartScanning()
    {
        if (IsScanning) return;
        IsScanning = true;
        _timer = new System.Threading.Timer(_ => Sweep(), null, 3500, 3500);
    }

    public void StopScanning()
    {
        IsScanning = false;
        _timer?.Dispose();
        _timer = null;
    }

    #region Candidate selection

    public static bool IsInterpreter(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var n = name.ToLowerInvariant();
        if (n.StartsWith("python")) return true;
        if (n.StartsWith("node") || n.Contains("npx")) return true;
        foreach (var i in ShortInterpreters)
        {
            if (n == i || n.StartsWith(i + ".")) return true;
        }
        return false;
    }

    public static bool IsLowTrustPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        foreach (var m in LowTrustMarkers)
            if (p.Contains(m)) return true;
        return false;
    }

    public static bool IsCandidateProcess(string name, string path)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (IsInterpreter(name)) return true;
        return IsLowTrustPath(path);
    }

    #endregion

    /// <summary>Event-driven immediate scan (from ProcessGuard on process creation).</summary>
    public void ScanNow(int pid)
    {
        if (pid <= 0) return;
        long now = Environment.TickCount64;
        if (_lastScan.TryGetValue(pid, out var last) && now - last < ScanCooldownMs) return;
        _lastScan[pid] = now;
        ThreadPool.QueueUserWorkItem(_ => ScanPid(pid));
    }

    private void Sweep()
    {
        if (!IsScanning) return;
        try
        {
            var rows = QueryAllProcessNames();
            if (rows == null) return;

            foreach (var row in rows)
            {
                try
                {
                    if (row.Pid == Environment.ProcessId || row.Pid == 0 || row.Pid == 4) continue;
                    var n = row.Name.ToLowerInvariant();
                    if (BehaviorEngine.IsProtectedProcess(n)) continue;

                    long now = Environment.TickCount64;
                    if (_lastScan.TryGetValue(row.Pid, out var last) && now - last < ScanCooldownMs) continue;

                    var path = GetPathCached(row.Pid);
                    if (string.IsNullOrEmpty(path) || IsSystemPath(path)) continue;
                    if (!IsCandidateProcess(n, path)) continue;

                    _lastScan[row.Pid] = now;
                    ScanPid(row.Pid);
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
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT ProcessId, Name FROM Win32_Process");
            foreach (System.Management.ManagementBaseObject o in searcher.Get())
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

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, (string Path, long At)> _pathCache =
        new();

    private string GetPathCached(int pid)
    {
        var now = Environment.TickCount64;
        if (_pathCache.TryGetValue(pid, out var cached) && now - cached.At < 30000)
            return cached.Path;
        string path;
        try
        {
            using var proc = Process.GetProcessById(pid);
            path = GetPathSafe(proc);
        }
        catch { path = ""; }
        _pathCache[pid] = (path, now);
        return path;
    }

    private void ScanPid(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var n = proc.ProcessName.ToLowerInvariant();
            if (BehaviorEngine.IsProtectedProcess(n)) return;

            var path = GetPathSafe(proc);
            if (!IsCandidateProcess(n, path)) return;

            if (ScanProcessMemory(pid, out var hit))
            {
                var type = TypeForHit(hit);
                _logger.Log(new ThreatEvent
                {
                    Type = type,
                    ProcessName = proc.ProcessName,
                    ProcessId = pid,
                    TargetPath = string.IsNullOrEmpty(path) ? $"memory::{hit}" : $"{path} :: {hit}",
                    Action = "MEMORY_BLOCK",
                    Severity = ThreatSeverity.Critical
                });

                Kill(proc);
                _behavior.NoteKill(proc.ProcessName, pid);
            }
        }
        catch { }
    }

    private static ThreatType TypeForHit(string hit)
    {
        if (hit.Contains("webhook")) return ThreatType.DiscordWebhookExfil;
        if (hit.Contains("DPAPI")) return ThreatType.CryptUnprotectData;
        return ThreatType.DiscordTokenGrabber;
    }

    private void Kill(Process proc)
    {
        try
        {
            if (BehaviorEngine.IsProtectedProcess(proc.ProcessName)) return;
            if (proc.Id == Environment.ProcessId) return;
            proc.Kill(true);
        }
        catch { }
    }

    #region Memory scan

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const long MEM_COMMIT = 0x1000;
    private const long PAGE_GUARD = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private static bool ScanProcessMemory(int pid, out string hit)
    {
        hit = "";
        var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero) return false;

        try
        {
            var lowTrust = IsLowTrustPath(GetPathSafe(Process.GetProcessById(pid)));
            long budget = MaxBytesPerProcess;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            long addr = 0;
            const long MaxAddr = 0x7FFFFFFFFFFF; // full 64-bit user address space

            while (addr < MaxAddr)
            {
                if (stopwatch.ElapsedMilliseconds > MaxScanTimeMs) break;
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProcess, new IntPtr(addr), out mbi,
                        (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
                    break;

                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0)
                {
                    long pos = 0;
                    while (pos < regionSize && budget > 0)
                    {
                        int chunkLen = (int)Math.Min(regionSize - pos, 1 << 20);
                        var buf = new byte[chunkLen];
                        UIntPtr done;
                        if (!ReadProcessMemory(hProcess, new IntPtr(addr + pos), buf,
                                (UIntPtr)chunkLen, out done))
                            break;

                        int n = (int)done.ToUInt64();
                        if (n <= 0) break;

                        budget -= n;
                        if (InspectChunk(buf, n, lowTrust, out hit)) return true;
                        pos += n;
                    }
                }

                addr += regionSize;
                if (addr < 0) break;
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static bool InspectChunk(byte[] buf, int n, bool lowTrust, out string hit)
    {
        var ascii = Encoding.Latin1.GetString(buf, 0, n);

        bool dTok = ascii.IndexOf("dQw4w9WgXcQ", StringComparison.OrdinalIgnoreCase) >= 0;
        bool dpapi = ascii.IndexOf("cryptunprotectdata", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     ascii.IndexOf("os_crypt", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     ascii.IndexOf("encrypted_key", StringComparison.OrdinalIgnoreCase) >= 0;
        bool webhook = ascii.IndexOf("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       ascii.IndexOf("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0;
        bool validate = ascii.IndexOf("users/@me", StringComparison.OrdinalIgnoreCase) >= 0;

        if (!dTok && !dpapi && !webhook && !validate)
        {
            var uni = Encoding.Unicode.GetString(buf, 0, n & ~1);
            dTok |= uni.IndexOf("dQw4w9WgXcQ", StringComparison.OrdinalIgnoreCase) >= 0;
            dpapi |= uni.IndexOf("cryptunprotectdata", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     uni.IndexOf("os_crypt", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     uni.IndexOf("encrypted_key", StringComparison.OrdinalIgnoreCase) >= 0;
            webhook |= uni.IndexOf("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       uni.IndexOf("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0;
            validate |= uni.IndexOf("users/@me", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        if (dTok) { hit = "dQw4w9WgXcQ token-dump prefix"; return true; }
        if (dpapi && webhook) { hit = "DPAPI decrypt + webhook exfil"; return true; }
        if (webhook && validate && (dpapi || lowTrust)) { hit = "webhook exfil + users/@me validation"; return true; }

        hit = "";
        return false;
    }

    #endregion

    public static bool IsSystemPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return p.StartsWith("c:\\windows\\");
    }

    private static string GetPathSafe(Process proc)
    {
        try { return proc.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }

    public void Dispose() => StopScanning();
}