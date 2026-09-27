using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;
using StopStealer.Core;

namespace StopStealer.GUI;

public partial class MainWindow : Window
{
    private ProtectionEngine? _engine;
    private readonly List<ThreatEvent> _discordEvents = new();
    private readonly DispatcherTimer _clock;
    private bool _autoScroll = true;

    private static readonly SolidColorBrush CyanBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00d2ff"));
    private static readonly SolidColorBrush RedBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#ff2d55"));
    private static readonly SolidColorBrush StandbyBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#55668f"));
    private static readonly SolidColorBrush ActiveBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00ff88"));
    private static readonly SolidColorBrush GoldBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#f0a523"));
    private static readonly SolidColorBrush PurpleBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#a855f7"));
    private static readonly SolidColorBrush GreenBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00ff88"));
    private static readonly SolidColorBrush DimBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#7b8db8"));
    private static readonly SolidColorBrush GrayBrush = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#55668f"));

    private static readonly string[] PageTitles = { "PROTECTION OVERVIEW", "DISCORD SHIELD", "THREAT LOG", "BROWSERS", "MODULES" };

    public MainWindow(ProtectionEngine? engine)
    {
        InitializeComponent();
        _engine = engine;

        Closing += OnClosing;

        try { if (_engine != null) _engine.OnThreatDetected += OnThreatDetected; }
        catch { }

        LoadBrowserStatus();
        LoadStats();
        UpdateAutostartButton();

        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += (_, _) => ClockText.Text = DateTime.Now.ToString("HH:mm:ss");
        _clock.Start();

        var statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        statsTimer.Tick += (_, _) => LoadStats();
        statsTimer.Start();
    }

    private static readonly string AutostartValueName = "hellstorm";

    private static bool IsAutostartEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            return key?.GetValue(AutostartValueName) is string v && v.Length > 0;
        }
        catch { return false; }
    }

    private void UpdateAutostartButton()
    {
        if (BtnAutostart == null) return;
        BtnAutostart.Content = IsAutostartEnabled() ? "&#xE7C1;  AUTO-RUN: ON" : "&#xE7C1;  AUTO-RUN: OFF";
        BtnAutostart.Foreground = IsAutostartEnabled()
            ? (SolidColorBrush)new BrushConverter().ConvertFrom("#00ff88")!
            : (SolidColorBrush)new BrushConverter().ConvertFrom("#7b8db8")!;
    }

    private void BtnAutostart_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (IsAutostartEnabled())
            {
                key?.DeleteValue(AutostartValueName, false);
            }
            else
            {
                var exe = $@"""{Environment.ProcessPath}"" --autostart";
                key?.SetValue(AutostartValueName, exe);
            }
        }
        catch { }
        UpdateAutostartButton();
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        e.Cancel = true;
        Hide();
    }

    #region Nav

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string index &&
            int.TryParse(index, out var tabIndex) && tabIndex >= 0 && tabIndex < MainTabs.Items.Count)
        {
            MainTabs.SelectedIndex = tabIndex;
            PageTitle.Text = PageTitles[tabIndex];
        }
    }

    #endregion

    #region Threat events

    private void OnThreatDetected(ThreatEvent threat)
    {
        AddThreatEvent(threat);

        var typeName = threat.Type.ToString();
        if (typeName.Contains("Token") || typeName.Contains("Discord") ||
            threat.TargetPath.Contains("discord", StringComparison.OrdinalIgnoreCase) ||
            threat.TargetPath.Contains("leveldb", StringComparison.OrdinalIgnoreCase) ||
            threat.ProcessName.Contains("discord", StringComparison.OrdinalIgnoreCase))
        {
            AddDiscordEvent(threat);
        }
    }

    public void AddThreatEvent(ThreatEvent threat)
    {
        try
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(() => AddThreatEvent(threat));
                return;
            }
            ThreatGrid.Items.Insert(0, threat);
            TxtThreatCount.Text = $"{ThreatGrid.Items.Count} events";
            TxtThreatCountBar.Text = $"{ThreatGrid.Items.Count} threats";
            TxtRecentThreat.Text = $"  —  [{threat.Severity}] {threat.Type}: {threat.ProcessName} → {threat.TargetPath}";
            if (ThreatGrid.Items.Count > 500)
                ThreatGrid.Items.RemoveAt(ThreatGrid.Items.Count - 1);
            if (_autoScroll && ThreatGrid.Items.Count > 0)
                ThreatGrid.ScrollIntoView(ThreatGrid.Items[0]);
        }
        catch { }
    }

    private void AddDiscordEvent(ThreatEvent threat)
    {
        try
        {
            Dispatcher.BeginInvoke(() =>
            {
                _discordEvents.Insert(0, threat);
                TxtDiscordPlaceholder.Visibility = Visibility.Collapsed;
                DiscordGrid.Visibility = Visibility.Visible;
                DiscordGrid.Items.Insert(0, threat);
                if (DiscordGrid.Items.Count > 200)
                    DiscordGrid.Items.RemoveAt(DiscordGrid.Items.Count - 1);
            });
        }
        catch { }
    }

    #endregion

    #region Stats / UI updates

    public void UpdateStats(ProtectionStats? stats)
    {
        if (stats == null) return;
        try
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(() => UpdateStats(stats));
                return;
            }

            AnimateCounter(TxtTotalBlocked, stats.TotalThreatsBlocked);
            AnimateCounter(TxtBrowserBlocked, stats.BrowserAttacksBlocked);
            AnimateCounter(TxtTokensBlocked, stats.TokenStealsPrevented);
            AnimateCounter(TxtClipboardBlocked, stats.ClipboardBlocks);
            AnimateCounter(TxtDiscordTokens, stats.DiscordTokenBlocks);
            AnimateCounter(TxtWebhookBlocks, stats.DiscordWebhookBlocks);
            AnimateCounter(TxtInjectionBlocks, stats.DiscordInjectionBlocks);
            AnimateCounter(TxtCryptoBlocks, stats.CryptUnprotectBlocks);

            bool active = stats.IsProtected;

            StatusDot.Fill = active ? ActiveBrush : GrayBrush;
            StatusText.Text = active ? "ACTIVE" : "STANDBY";
            StatusText.Foreground = active ? ActiveBrush : DimBrush;
            HeroStatus.Text = active ? "SHIELD ENGAGED" : "SHIELD DISENGAGED";
            HeroStatus.Foreground = active ? ActiveBrush : GrayBrush;
            TxtEngineStatus.Text = active ? "engine: guarding in real-time" : "engine: idle";
            TxtEngineStatus.Foreground = active ? ActiveBrush : GrayBrush;

            var layerColor = active ? GreenBrush : GrayBrush;
            LayerProc.Fill = LayerBrowser.Fill = LayerDiscord.Fill = LayerBehavior.Fill = LayerClipboard.Fill = layerColor;
        }
        catch { }
    }

    private void AnimateCounter(System.Windows.Controls.TextBlock target, long value)
    {
        if (target == null) return;
        string text = value.ToString("N0");
        if (target.Text == text) return;
        target.Text = text;
    }

    private void LoadBrowserStatus()
    {
        try
        {
            var browsers = BrowserProtector.GetAllBrowserInfos();
            BrowserGrid.ItemsSource = browsers;
            TxtModuleCount.Text = $"{browsers.Count + 7} apps tracked";
        }
        catch { }
    }

    private void LoadStats()
    {
        try
        {
            var stats = _engine?.GetStats();
            if (stats != null) UpdateStats(stats);
        }
        catch { }
    }

    #endregion

    #region Button handlers

    private void BtnStart_Click(object sender, RoutedEventArgs e) => EngageProtection();

    /// <summary>Starts the engine and flips the UI to ACTIVE. Called by the
    /// START button and automatically at boot when launched with --autostart.</summary>
    public void EngageProtection()
    {
        if (_engine == null)
            _engine = new ProtectionEngine();

        _engine.OnThreatDetected -= OnThreatDetected;
        _engine.OnThreatDetected += OnThreatDetected;
        _engine.Start();

        BtnStart.IsEnabled = false;
        BtnStop.IsEnabled = true;
        PageTitle.Text = PageTitles[0];

        StatusDot.Fill = ActiveBrush;
        StatusText.Text = "ACTIVE";
        StatusText.Foreground = ActiveBrush;
        HeroStatus.Text = "SHIELD ENGAGED";
        HeroStatus.Foreground = ActiveBrush;
        TxtEngineStatus.Text = "engine: guarding in real-time";
        TxtEngineStatus.Foreground = ActiveBrush;

        var green = GreenBrush;
        LayerProc.Fill = LayerBrowser.Fill = LayerDiscord.Fill = LayerBehavior.Fill = LayerClipboard.Fill = green;
    }

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        _engine?.Stop();

        BtnStart.IsEnabled = true;
        BtnStop.IsEnabled = false;

        StatusDot.Fill = GrayBrush;
        StatusText.Text = "STANDBY";
        StatusText.Foreground = DimBrush;
        HeroStatus.Text = "SHIELD DISENGAGED";
        HeroStatus.Foreground = GrayBrush;
        TxtEngineStatus.Text = "engine: idle";
        TxtEngineStatus.Foreground = GrayBrush;

        var gray = GrayBrush;
        LayerProc.Fill = LayerBrowser.Fill = LayerDiscord.Fill = LayerBehavior.Fill = LayerClipboard.Fill = gray;
    }

    private void ToggleAutoScroll_Click(object sender, RoutedEventArgs e)
    {
        _autoScroll = !_autoScroll;
        BtnAutoScroll.Content = _autoScroll ? "AUTO-SCROLL ON" : "AUTO-SCROLL OFF";
    }

    private async void BtnExport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var events = ThreatGrid.Items.Cast<ThreatEvent>()
                .Select(t => new
                {
                    timestamp = t.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    severity = t.Severity.ToString(),
                    type = t.Type.ToString(),
                    processName = t.ProcessName,
                    processId = t.ProcessId,
                    targetPath = t.TargetPath,
                    action = t.Action
                }).ToList();

            var stats = _engine?.GetStats();
            var report = new
            {
                tool = "hellstorm",
                version = "1.0",
                designer = "hellstorm",
                exportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                totalEvents = events.Count,
                stats = stats == null ? null : new
                {
                    totalBlocked = stats.TotalThreatsBlocked,
                    browserAttacks = stats.BrowserAttacksBlocked,
                    tokenSteals = stats.TokenStealsPrevented,
                    discordTokens = stats.DiscordTokenBlocks,
                    webhookBlocks = stats.DiscordWebhookBlocks,
                    injectionBlocks = stats.DiscordInjectionBlocks,
                    cryptoBlocks = stats.CryptUnprotectBlocks,
                    clipboardTheft = stats.ClipboardBlocks,
                    processBlocks = stats.SuspiciousProcessBlocks,
                    isProtected = stats.IsProtected
                },
                threats = events,
                discordEvents = _discordEvents.Select(d => new
                {
                    timestamp = d.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    type = d.Type.ToString(),
                    processName = d.ProcessName,
                    targetPath = d.TargetPath,
                    action = d.Action
                }).ToList()
            };

            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });

            var reportsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "hellstorm", "Reports");
            Directory.CreateDirectory(reportsDir);

            var filePath = Path.Combine(reportsDir, $"report_{DateTime.Now:yyyy-MM-dd_HHmmss}.json");
            await File.WriteAllTextAsync(filePath, json);

            System.Windows.MessageBox.Show(
                $"Report saved:\n{filePath}\n\n{events.Count} threat events exported.",
                "hellstorm — Export Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Export failed:\n{ex.Message}",
                "hellstorm — Export Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        ThreatGrid.Items.Clear();
        TxtThreatCount.Text = "0 events";
        TxtThreatCountBar.Text = "0 threats";
        TxtRecentThreat.Text = "  — no threats recorded";
    }

    #endregion

    #region Window chrome

    private void WindowDrag(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
            DragMove();
    }

    private void BtnMinimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void BtnClose_Click(object sender, RoutedEventArgs e) => Application.Current.Shutdown();

    #endregion
}