using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FreeTurn.Windows;

internal sealed record ProfileEdits(string Name,string Peer,string CallLink,int Streams,int StreamsPerCredential,string DnsMode,string DnsServers,bool ManualCaptcha,string Provider="vk",string Transport="tcp",string ObfProfile="rtpopus3",string ObfKey="",int Timing=0,string ProxyMode="udp",string Listen="127.0.0.1:9000",bool Bond=false,string KcpJson="")
{
    public override string ToString()=>"ProfileEdits (private fields omitted)";
}

// Edit a clone of the complete share object. Never reconstruct the connection
// from a reduced UI model, which would silently lose keys/PSK/CID/extensions.
internal sealed class ShareDocument
{
    private readonly JsonObject original;
    internal ProfileEdits Values { get; }
    internal string WireGuard => original["wg"]?.GetValue<string>()??"";
    // Display/preflight hint only; the engine validates every field/value.
    internal bool IsAmneziaWG => WireGuard.Split('\n').Any(line=>
        ("|Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies|").Contains("|"+line.Split('=')[0].Trim()+"|",StringComparison.Ordinal));
    internal ShareDocument(string share)
    {
        try{
            if(share.Length>96*1024||!share.StartsWith("freeturn://",StringComparison.Ordinal))throw new IOException();
            var encoded=share["freeturn://".Length..];
            if(encoded.Length==0||encoded.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-'&&c!='_'))throw new IOException();
            var text=encoded.Replace('-','+').Replace('_','/');text=text.PadRight((text.Length+3)/4*4,'=');
            var raw=Convert.FromBase64String(text);
            if(raw.Length>65536||Encode(raw)!=encoded)throw new IOException();
            using var document=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=8});Unique(document.RootElement);
            original=JsonNode.Parse(raw)!.AsObject();
            if(original["v"]?.GetValue<int>()!=1)throw new IOException();
            Values=new(Text("name"),Text("peer"),Text("vk"),Number("n",Text("provider")=="direct"?1:6),Number("spc",3),Text("dns","auto"),Text("dnss"),original["mcap"]?.GetValue<bool>()??false,Text("provider","vk"),Text("transport","tcp"),Text("obf","none"),Text("key"),Number("timing",0),Text("mode","udp"),Text("listen","127.0.0.1:9000"),original["bond"]?.GetValue<bool>()??false,original["kcp"]?.ToJsonString()??"");
        }catch{throw new IOException("PROFILE_DOCUMENT_INVALID");}
    }
    internal string Build(ProfileEdits values,string? changedWireGuard=null)
    {
        try{
            if(string.IsNullOrWhiteSpace(values.Name)||values.Name.Length>128||values.Name.Any(char.IsControl)||string.IsNullOrWhiteSpace(values.Peer)||values.Streams is <1 or >32||values.StreamsPerCredential is <1 or >16||values.DnsMode is not ("auto" or "plain" or "doh"))throw new IOException();
            var copy=(JsonObject)original.DeepClone();
            copy["name"]=values.Name.Trim();copy["peer"]=values.Peer.Trim();copy["vk"]=values.CallLink.Trim();
            copy["n"]=values.Streams;copy["spc"]=values.StreamsPerCredential;copy["dns"]=values.DnsMode;copy["dnss"]=values.DnsServers.Trim();copy["mcap"]=values.ManualCaptcha;
            if(values.Provider is not ("vk" or "direct")||values.Transport is not ("tcp" or "udp")||values.ObfProfile is not ("none" or "rtpopus" or "rtpopus2" or "rtpopus3")||values.Timing is <0 or >1000)throw new IOException();
            copy["provider"]=values.Provider;copy["transport"]=values.Transport;copy["obf"]=values.ObfProfile;copy["key"]=values.ObfKey;copy["timing"]=values.Timing;
            if(values.ProxyMode is not ("udp" or "tcp"))throw new IOException();copy["mode"]=values.ProxyMode;copy["listen"]=values.Listen.Trim();copy["bond"]=values.Bond;
            if(values.KcpJson!=Values.KcpJson){if(string.IsNullOrWhiteSpace(values.KcpJson))copy.Remove("kcp");else{using var kcp=JsonDocument.Parse(values.KcpJson,new(){MaxDepth=4});Unique(kcp.RootElement);copy["kcp"]=JsonNode.Parse(values.KcpJson)!.AsObject();}}
            if(changedWireGuard is not null)copy["wg"]=changedWireGuard;
            var raw=Encoding.UTF8.GetBytes(copy.ToJsonString());if(raw.Length>65536)throw new IOException();
            return "freeturn://"+Encode(raw);
        }catch{throw new IOException("PROFILE_DOCUMENT_INVALID");}
    }
    private string Text(string key,string fallback="")=>original[key]?.GetValue<string>()??fallback;
    private int Number(string key,int fallback)=>original[key]?.GetValue<int>() is int value&&value!=0?value:fallback;
    private static string Encode(byte[] raw)=>Convert.ToBase64String(raw).TrimEnd('=').Replace('+','-').Replace('/','_');
    internal static void Unique(JsonElement element)
    {
        if(element.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);foreach(var property in element.EnumerateObject()){if(!names.Add(property.Name))throw new IOException();Unique(property.Value);}}
        else if(element.ValueKind==JsonValueKind.Array)foreach(var child in element.EnumerateArray())Unique(child);
    }
}
