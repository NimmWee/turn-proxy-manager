using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace FreeTurn.Windows;

internal sealed record SystemAppRule([property:JsonPropertyName("path")]string Path,[property:JsonPropertyName("action")]string Action)
{
    public override string ToString()=>"Application rule (path omitted)";
    internal bool Valid{
        get{
            try{
                if(Path is null||Path.Length<7||System.Text.Encoding.UTF8.GetByteCount(Path)>1024||Path.Any(char.IsControl)||Path[1]!=':'||Path[2]!='\\'||!char.IsAsciiLetter(Path[0])||Path[2..].IndexOfAny(['\0','\r','\n','\t','/',':','*','?','"','<','>','|','%'])>=0||!Path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||System.IO.Path.GetFullPath(Path)!=Path||Action is not("direct" or "vpn" or "block"))return false;
                return Path[3..].Split('\\').All(p=>p.Length>0&&p is not("." or "..")&&p.Trim()==p&&!p.EndsWith('.'));
            }catch{return false;}
        }
    }
    [JsonIgnore] public string Display=>System.IO.Path.GetFileName(Path)+" — "+(Action=="direct"?"Напрямую":Action=="vpn"?"Через VPN":"Блокировать")+Environment.NewLine+Path;
}

internal sealed record SystemRoutingPresets(
    [property:JsonPropertyName("russianDirect")] bool RussianDirect=true,
    [property:JsonPropertyName("lanDirect")] bool LANDirect=true,
    [property:JsonPropertyName("youtubeVPN")] bool YouTubeVPN=true,
    [property:JsonPropertyName("pushVPN")] bool PushVPN=true,
    [property:JsonPropertyName("connectivityDirect")] bool ConnectivityDirect=true,
    [property:JsonPropertyName("blockBitTorrent")] bool BlockBitTorrent=true,
    [property:JsonPropertyName("splitDNS")] bool SplitDNS=true);

internal sealed record RoutingCatalog([property:JsonPropertyName("sha256")]string SHA256,[property:JsonPropertyName("gzip")]string Gzip);

internal sealed record SystemRoutingSettings
{
    [JsonPropertyName("publicationRevision"),JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)] public long PublicationRevision {get;init;}
    [JsonPropertyName("catalog"),JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] public RoutingCatalog? Catalog {get;init;}
    [JsonPropertyName("v")] public int V {get;init;}=1;
    [JsonPropertyName("enabled")] public bool Enabled {get;init;}
    [JsonPropertyName("presets")] public SystemRoutingPresets Presets {get;init;}=new();
    [JsonPropertyName("rules")] public List<DomainRule> Rules {get;init;}=[];
    [JsonPropertyName("directDNS")] public List<string> DirectDNS {get;init;}=["77.88.8.8","77.88.8.1"];
    [JsonPropertyName("appRules"),JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] public List<SystemAppRule>? AppRules {get;init;}
    public override string ToString()=>"SystemRoutingSettings (domains omitted)";
    // Engine validates the authoritative IDNA/PSL and reserved-address policy.
    internal bool Valid=>V==1&&PublicationRevision is >=0 and <=9007199254740991&&(Catalog is null||Catalog.SHA256 is{Length:64}&&Catalog.Gzip is{Length:<=170000})&&Presets is not null&&Rules is not null&&new RoutingPolicy(1,Rules).Valid&&DirectDNS is not null&&DirectDNS.Count is >=1 and <=4&&DirectDNS.Distinct(StringComparer.Ordinal).Count()==DirectDNS.Count&&DirectDNS.All(s=>s is not null&&s.Length<=15&&IPAddress.TryParse(s,out var ip)&&ip.AddressFamily==AddressFamily.InterNetwork&&ip.ToString()==s)&&(AppRules is null||AppRules.Count<=64&&AppRules.All(r=>r is{Valid:true})&&AppRules.Select(r=>r.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()==AppRules.Count);
}

internal sealed record SystemRoutingReport(bool Requested,bool Active,bool Handshake,ulong Rx,ulong Tx,long EgressAt=0,ulong DirectFlows=0,ulong VPNFlows=0,ulong BlockedFlows=0,ulong DNSQueries=0,ulong DNSErrors=0,string? SetupStage=null,string? LastError=null,bool LocalDNSReady=false,bool MDNSConfigured=false,int AppRules=0,ulong UnknownAppFlows=0,long PublicationRevision=0,string? CatalogSHA256=null);
