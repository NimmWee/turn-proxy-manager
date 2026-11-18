using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal sealed record SystemGeoIPInfo(string Provider,string Release,string Country,string License,string Attribution,string URL,string SourceSHA256,int IPv4Prefixes)
{
    internal bool Valid=>Provider=="DB-IP Lite"&&Country=="RU"&&License=="CC-BY-4.0"&&Attribution=="IP Geolocation by DB-IP"&&URL=="https://db-ip.com/"&&DateTime.TryParseExact(Release,"yyyy-MM",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.None,out _)&&SourceSHA256 is{Length:64}&&SourceSHA256.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')&&IPv4Prefixes is >0 and <=200000;
    internal string Description=>!Valid?"База IP не прошла проверку.":"База IP в этом пакете: DB-IP Lite, "+DateTime.ParseExact(Release,"yyyy-MM",System.Globalization.CultureInfo.InvariantCulture).ToString("MMMM yyyy",System.Globalization.CultureInfo.GetCultureInfo("ru-RU"))+". Диапазонов RU: "+IPv4Prefixes.ToString("N0",System.Globalization.CultureInfo.GetCultureInfo("ru-RU"))+". Геолокация приблизительная.";
}

internal sealed record SystemRoutingResult(bool Ok,SystemRoutingSettings Policy,RoutingDecision? Decision,bool Active,bool NetworkChanged,bool RuntimeIntegrated,bool GvisorCompiled,string Scope,SystemGeoIPInfo? GeoIP=null);

internal static class SystemRoutingCheck
{
    internal static async Task<SystemRoutingResult> Run(SystemRoutingSettings policy,string? host=null,string? ip=null,string? application=null)
    {
        if(!policy.Valid||host?.Length>1024||ip?.Length>45)throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");
        var engine=Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe");
        if(!File.Exists(engine))throw new IOException("ENGINE_MISSING");
        var input=JsonSerializer.Serialize(new{policy,host=host??"",ip=ip??"",application=application??""});
        if(Encoding.UTF8.GetByteCount(input)>512*1024)throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");
        using var process=new Process{StartInfo=new ProcessStartInfo(engine,"--check-system-routing"){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,
            StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false)
        }};
        process.Start();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
        try{
            var output=ReadBounded(process.StandardOutput,timeout.Token);var error=ReadBounded(process.StandardError,timeout.Token);
            await process.StandardInput.WriteAsync(input.AsMemory(),timeout.Token);process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);var raw=await output;await error;
            if(process.ExitCode!=0)throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");
            var result=JsonSerializer.Deserialize<SystemRoutingResult>(raw,new JsonSerializerOptions{PropertyNameCaseInsensitive=true});
            if(result is not{Ok:true,Active:false,NetworkChanged:false,Scope:"system-routing-preview",GeoIP:{Valid:true}}||!result.Policy.Valid||result.Policy.PublicationRevision!=policy.PublicationRevision||result.Policy.Catalog!=policy.Catalog||result.Policy.Enabled!=policy.Enabled||result.Policy.Presets!=policy.Presets||!result.Policy.DirectDNS.SequenceEqual(policy.DirectDNS))throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");
            if(policy.Enabled&&(!result.GvisorCompiled||!result.RuntimeIntegrated))throw new IOException("SYSTEM_ROUTING_BUILD_REQUIRED");
            if(!(result.Policy.AppRules??[]).SequenceEqual(policy.AppRules??[]))throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");
            return result;
        }catch{if(!process.HasExited)process.Kill();throw new IOException("SYSTEM_ROUTING_CHECK_FAILED");}
    }
    private static async Task<string> ReadBounded(StreamReader reader,CancellationToken token)
    {
        var result=new StringBuilder();var chunk=new char[2048];
        while(true){var n=await reader.ReadAsync(chunk.AsMemory(),token);if(n==0)return result.ToString();if(result.Length+n>512*1024)throw new IOException("REPLY_TOO_LARGE");result.Append(chunk,0,n);}
    }
}
