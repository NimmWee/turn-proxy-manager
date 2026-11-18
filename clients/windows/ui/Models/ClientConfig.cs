// SPDX-License-Identifier: GPL-3.0-only
// Windows model adapted from hackdiaz-dev/turn-proxy-android 5.3.4,
// data/config/ClientConfig.kt. See THIRD_PARTY.md and Android-LICENSE.txt.
namespace FreeTurn.Windows.Models;

internal sealed record ClientConfig
{
    public string ServerAddress { get; init; } = "";
    public string CallLink { get; init; } = "";
    public string Provider { get; init; } = "vk";
    public int Threads { get; init; } = 12;
    public int StreamsPerCred { get; init; } = 12;
    public bool UseUdp { get; init; }
    public bool Bond { get; init; }
    public bool ManualCaptcha { get; init; }
    public string LocalPort { get; init; } = "127.0.0.1:9000";
    public bool DebugMode { get; init; }
    public bool UseCarrierDns { get; init; } = true;
    public string DnsMode { get; init; } = "auto";
    public string CustomDns { get; init; } = "";
    public bool SyncServerSwitches { get; init; } = true;
    public bool MagicSwitch { get; init; }
    public string MagicTurn { get; init; } = "";
    public string TunnelTransport { get; init; } = "none";
    public string WireGuardConfig { get; init; } = "";
    public string WireGuardTunnelName { get; init; } = "freeturn-wg";
    [System.Text.Json.Serialization.JsonIgnore]
    public bool WireGuardActive => TunnelTransport=="wireguard"&&!string.IsNullOrWhiteSpace(WireGuardConfig);
    public string SplitTunnelMode { get; init; } = "exclude";
    public string SplitTunnelApps { get; init; } = "";
    public bool SplitTunnelShared { get; init; }
    public bool LogsEnabled { get; init; } = true;
    public string ClientId { get; init; } = "";
    public override string ToString()=>"ClientConfig (private fields omitted)";
}
