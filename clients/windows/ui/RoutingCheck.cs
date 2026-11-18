using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal sealed record RoutingDecision(string Action, string? Rule);
internal sealed record RoutingResult(bool Ok, RoutingPolicy Policy, RoutingDecision? Decision);

internal static class RoutingCheck
{
    internal static async Task<RoutingResult> Run(RoutingPolicy policy, string? host = null)
    {
        if (!policy.Valid || host?.Length > 1024) throw new IOException("ROUTING_POLICY_INVALID");
        var engine = Path.Combine(AppContext.BaseDirectory, "FreeTurn.Engine.exe");
        if (!File.Exists(engine)) throw new IOException("ENGINE_MISSING");
        var input = JsonSerializer.Serialize(new { policy, host = host ?? "" });
        if (Encoding.UTF8.GetByteCount(input) > 96 * 1024) throw new IOException("ROUTING_POLICY_INVALID");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(engine, "--check-routing")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = new UTF8Encoding(false)
            }
        };
        process.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.StandardInput.WriteAsync(input.AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var result = await output; await error;
            if (process.ExitCode != 0 || result.Length > 96 * 1024) throw new IOException("ROUTING_POLICY_INVALID");
            var parsed = JsonSerializer.Deserialize<RoutingResult>(result, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (parsed is not { Ok: true } || !parsed.Policy.Valid) throw new IOException("ROUTING_POLICY_INVALID");
            return parsed;
        }
        catch
        {
            if (!process.HasExited) process.Kill();
            throw new IOException("ROUTING_POLICY_INVALID");
        }
    }
}
