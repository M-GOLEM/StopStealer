using System.Diagnostics;
using System.IO;
using System.Windows;
using StopStealer.Core;

namespace StopStealer.GUI;

public partial class App : System.Windows.Application
{
    private MainWindow? _mainWindow;
    private ProtectionEngine? _engine;

    private static readonly string CrashLog = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "hellstorm", "crash.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try { Directory.CreateDirectory(Path.GetDirectoryName(CrashLog)!); } catch { }

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            try { File.AppendAllText(CrashLog, $"[{DateTime.Now:HH:mm:ss.fff}] APPDOMAIN: {args.ExceptionObject}\n"); } catch { }
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            args.SetObserved();
            try { File.AppendAllText(CrashLog, $"[{DateTime.Now:HH:mm:ss.fff}] TASK: {args.Exception}\n"); } catch { }
        };

        var autostart = e.Args.Any(a => string.Equals(a, "--autostart", StringComparison.OrdinalIgnoreCase));

        DispatcherUnhandledException += (_, args) =>
        {
            Debug.WriteLine($"[hellstorm] Exception: {args.Exception}");
            args.Handled = true;
        };

        try
        {
            _engine = new ProtectionEngine();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[hellstorm] Engine init: {ex}");
        }

        try
        {
            _mainWindow = new MainWindow(_engine);
            _mainWindow.Show();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[hellstorm] Window: {ex}");
            System.Windows.MessageBox.Show(ex.ToString(), "hellstorm Error");
        }

        // Boot autostart: protection engaged immediately, window starts minimized.
        if (autostart && _mainWindow != null)
        {
            try { _mainWindow.EngageProtection(); } catch { }
            _mainWindow.WindowState = WindowState.Minimized;
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _engine?.Stop(); _engine?.Dispose(); }
        catch { }
        base.OnExit(e);
    }
}
