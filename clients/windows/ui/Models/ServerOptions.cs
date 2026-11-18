// SPDX-License-Identifier: GPL-3.0-only
// Adapted from Android 5.3.4 ServerOpts.kt and KcpProfile.kt; see THIRD_PARTY.md.
namespace FreeTurn.Windows.Models;

internal sealed record KcpProfile(int NoDelay=1,int Interval=20,int Resend=2,int Nc=1,int SndWnd=512,int RcvWnd=512,int Mtu=1200,bool AckNoDelay=true)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public bool Valid=>NoDelay is >=0 and <=1&&Nc is >=0 and <=1&&Interval>0&&Resend>=0&&SndWnd>0&&RcvWnd>0&&Mtu is >=300 and <=1350;
}
internal sealed record ServerOptions
{
    public string ObfProfile { get; init; } = "none";
    public string ObfKey { get; init; } = "";
    public int ObfTimingMs { get; init; }
    public string ProxyMode { get; init; } = "udp";
    public KcpProfile Kcp { get; init; } = new();
    public string Method { get; init; } = "docker";
    public string Backend { get; init; } = "new";
    public int WgPort { get; init; } = 51820;
    public string WgNet { get; init; } = "10.13.13.0/24";
    public override string ToString()=>"ServerOptions (private fields omitted)";
}
