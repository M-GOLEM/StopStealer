using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using StopStealer.Core;

namespace StopStealer.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private ProtectionEngine? _engine;
    private const string PipeName = "StopStealerPipe";

    public Worker(ILogger<Worker> logger) { _logger = logger; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("StopStealer Service starting...");

        _engine = new ProtectionEngine();
        _engine.OnThreatDetected += OnThreatDetected;
        _engine.Start();

        _ = Task.Run(() => RunPipeServer(stoppingToken), stoppingToken);

        _logger.LogInformation("StopStealer Service running. Protection active.");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(5000, stoppingToken);
        }

        _engine.Stop();
        _engine.Dispose();
        _logger.LogInformation("StopStealer Service stopped.");
    }

    private void OnThreatDetected(ThreatEvent threat)
    {
        _logger.LogWarning(
            "[{Severity}] {Type}: {Process}(PID:{Pid}) -> {Target} [{Action}]",
            threat.Severity, threat.Type, threat.ProcessName,
            threat.ProcessId, threat.TargetPath, threat.Action);
    }

    private async Task RunPipeServer(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message);

                await server.WaitForConnectionAsync(ct);
                using var reader = new StreamReader(server, Encoding.UTF8);
                using var writer = new StreamWriter(server, Encoding.UTF8) { AutoFlush = true };

                var request = await reader.ReadLineAsync(ct);
                if (request == "GET_STATS")
                {
                    var stats = _engine?.GetStats();
                    await writer.WriteLineAsync(JsonSerializer.Serialize(stats));
                }
                else if (request == "GET_EVENTS")
                {
                    var events = _engine?.GetRecentEvents(50);
                    await writer.WriteLineAsync(JsonSerializer.Serialize(events));
                }
                else if (request == "GET_BROWSERS")
                {
                    var browsers = _engine?.GetBrowserStatus();
                    await writer.WriteLineAsync(JsonSerializer.Serialize(browsers));
                }
                else if (request?.StartsWith("SET_ENABLED:") == true)
                {
                    var enabled = request.Split(':').Last() == "true";
                    if (enabled) _engine?.Start();
                    else _engine?.Stop();
                    await writer.WriteLineAsync($"OK:{enabled}");
                }
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(1000, ct); }
        }
    }
}
