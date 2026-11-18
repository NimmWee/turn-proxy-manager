using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FreeTurn.Windows;
internal static class CatalogBackup
{
    internal static byte[] Encode(ProfileSnapshot snapshot)=>JsonSerializer.SerializeToUtf8Bytes(new{format="freeturn-windows-catalog",v=1,catalog=snapshot});
    internal static ProfileSnapshot Decode(byte[] raw)
    {
        try{
            if(raw.Length>BackupCrypto.MaxPlaintext)throw new IOException();
            using var document=JsonDocument.Parse(raw,new(){MaxDepth=16});ShareDocument.Unique(document.RootElement);var root=document.RootElement;
            if(root.TryGetProperty("format",out var format)){
                if(format.GetString()!="freeturn-windows-catalog"||root.GetProperty("v").GetInt32()!=1)throw new IOException();
                return root.GetProperty("catalog").Deserialize<ProfileSnapshot>(new JsonSerializerOptions{UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow})??throw new IOException();
            }
            return FromAndroid(raw,root);
        }catch{throw new IOException("BACKUP_PAYLOAD_INVALID");}
    }
    private static ProfileSnapshot FromAndroid(byte[] raw,JsonElement root)
    {
        if(root.GetProperty("v").GetInt32()!=4)throw new IOException();
        var own=String(root,"ownClientId");if(!ValidCid(own))throw new IOException();
        var profiles=new List<SavedProfile>();
        foreach(var server in root.GetProperty("servers").EnumerateArray()){
            if(profiles.Count>=256)throw new IOException();
            var client=server.GetProperty("client");var opts=server.GetProperty("opts");var cid=String(client,"clientId");if(cid=="")cid=own;if(!ValidCid(cid))throw new IOException();
            var share=new JsonObject{["v"]=1,["name"]=String(server,"name"),["provider"]=String(client,"provider","vk"),["peer"]=String(client,"serverAddress"),["transport"]=Bool(client,"useUdp")?"udp":"tcp",["mode"]=String(opts,"proxyMode","udp"),["bond"]=Bool(client,"bond"),["obf"]=String(opts,"obfProfile","none"),["key"]=String(opts,"obfKey"),["timing"]=Number(opts,"obfTimingMs",0),["n"]=Number(client,"threads",12),["spc"]=Number(client,"streamsPerCred",12),["cid"]=cid,["listen"]=String(client,"localPort","127.0.0.1:9000"),["dns"]=String(client,"dnsMode","auto"),["dnss"]=String(client,"customDns"),["mcap"]=Bool(client,"manualCaptcha"),["vk"]=String(client,"callLink"),["wg"]=String(client,"wireGuardConfig")};
            var wireGuardActive=String(client,"tunnelTransport")=="wireguard"&&String(client,"wireGuardConfig")!="";
            if(!wireGuardActive)share["wg"]="";
            if(wireGuardActive){share["mode"]="udp";share["bond"]=false;}
            if(share["mode"]!.GetValue<string>()!="tcp")share["bond"]=false;
            if(share["provider"]!.GetValue<string>()=="direct")share["n"]=1;
            if(share["obf"]!.GetValue<string>() is "none" or ""){share["key"]="";share["timing"]=0;}
            if(opts.TryGetProperty("kcp",out var kcp)&&String(opts,"proxyMode","udp")=="tcp"&&!wireGuardActive){
                var mapped=new JsonObject();foreach(var p in kcp.EnumerateObject())mapped[p.Name.ToLowerInvariant()]=JsonNode.Parse(p.Value.GetRawText());share["kcp"]=mapped;
            }
            var name=String(server,"name");if(string.IsNullOrWhiteSpace(name))name="Сервер Android";
            var link="freeturn://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(share.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
            if(!Guid.TryParse(String(server,"id"),out var id)||id==Guid.Empty)throw new IOException();
            Models.SshConfig? ssh=null;if(server.TryGetProperty("ssh",out var sshSource)){ssh=new(){Ip=String(sshSource,"ip"),Port=Number(sshSource,"port",22),Username=String(sshSource,"username","root"),Password=String(sshSource,"password"),AuthType=String(sshSource,"authType","PASSWORD"),SshKey=String(sshSource,"sshKey"),HostFingerprint=String(sshSource,"hostFingerprint"),RootMode=String(sshSource,"rootMode","ROOT"),SudoPassword=String(sshSource,"sudoPassword")};}
            profiles.Add(new(id,name,link,ssh));
        }
        return new(1,null,profiles,false,Encoding.UTF8.GetString(raw));
    }
    private static string String(JsonElement o,string key,string fallback="")=>o.TryGetProperty(key,out var value)?value.GetString()??fallback:fallback;
    private static bool Bool(JsonElement o,string key)=>o.TryGetProperty(key,out var value)&&value.GetBoolean();
    private static int Number(JsonElement o,string key,int fallback)=>o.TryGetProperty(key,out var value)?value.GetInt32():fallback;
    private static bool ValidCid(string value)=>value.Length==32&&value.All(Uri.IsHexDigit);
}
