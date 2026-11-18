// SPDX-License-Identifier: GPL-3.0-only
// Adapted from Android 5.3.4 data/config/SshConfig.kt. See THIRD_PARTY.md.
namespace FreeTurn.Windows.Models;

internal sealed record SshConfig
{
    public string Ip { get; init; } = "";
    public int Port { get; init; } = 22;
    public string Username { get; init; } = "root";
    public string Password { get; init; } = "";
    public string AuthType { get; init; } = "PASSWORD";
    public string SshKey { get; init; } = "";
    public string HostFingerprint { get; init; } = "";
    public string RootMode { get; init; } = "ROOT";
    public string SudoPassword { get; init; } = "";
    public bool SameHost(SshConfig other)=>!string.IsNullOrWhiteSpace(Ip)&&string.Equals(Ip,other.Ip,StringComparison.OrdinalIgnoreCase)&&Port==other.Port;
    public override string ToString()=>"SshConfig (private fields omitted)";
}
