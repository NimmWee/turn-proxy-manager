using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal static class ManagedUpdateBuilder
{
 private sealed record Reply(bool Ok,string Share,string ETag,long Revision){public override string ToString()=>"Managed builder reply (private fields omitted)";}
 internal static async Task<ManagedConfig> Build(SavedProfile profile,string manifest,string etag,long minimumRevision)
 {
  var m=profile.Managed??throw new IOException("MANAGED_CONFIG_INVALID");
  if(!m.Valid||manifest is null||Encoding.UTF8.GetByteCount(manifest)>65536)throw new IOException("MANAGED_CONFIG_INVALID");
  using var doc=JsonDocument.Parse(manifest,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);
  var input=JsonSerializer.Serialize(new{manifest=doc.RootElement,current_share=profile.Share,device_id=m.DeviceId,public_key=m.PublicKey,origin=m.Origin,etag,min_revision=minimumRevision});
  if(Encoding.UTF8.GetByteCount(input)>256*1024)throw new IOException("MANAGED_CONFIG_INVALID");
  var engine=Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe");if(!File.Exists(engine))throw new IOException("ENGINE_MISSING");
  using var process=new Process{StartInfo=new ProcessStartInfo(engine,"--build-managed"){
   UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,
   StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false,true)
  }};
  process.Start();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
  try{
   var output=ReadBounded(process.StandardOutput,timeout.Token);var errors=ReadBounded(process.StandardError,timeout.Token);
   await process.StandardInput.WriteAsync(input.AsMemory(),timeout.Token);process.StandardInput.Close();await process.WaitForExitAsync(timeout.Token);
   var raw=await output;await errors;
   if(process.ExitCode!=0)throw new IOException();
   var result=JsonSerializer.Deserialize<Reply>(raw,new JsonSerializerOptions{PropertyNameCaseInsensitive=true})??throw new IOException();
   var config=new ManagedConfig(manifest,result.Share,result.ETag,result.Revision);
   if(!result.Ok||!config.Valid||result.ETag!=etag||result.Revision<minimumRevision||result.Revision!=doc.RootElement.GetProperty("revision").GetInt64())throw new IOException();
   return config;
  }catch{if(!process.HasExited)process.Kill();throw new IOException("MANAGED_CONFIG_INVALID");}
 }
 private static async Task<string> ReadBounded(StreamReader reader,CancellationToken token)
 {
  var text=new StringBuilder();var buffer=new char[2048];
  while(true){var n=await reader.ReadAsync(buffer.AsMemory(),token);if(n==0)return text.ToString();if(text.Length+n>256*1024)throw new IOException();text.Append(buffer,0,n);}
 }
 internal static async Task<ManagedConfig> Verify(SavedProfile p,ManagedConfig config,long minimumRevision)
 {
  if(!config.Valid)throw new IOException("MANAGED_CONFIG_INVALID");
  var verified=await Build(p,config.Manifest,config.ETag,minimumRevision);
  if(verified!=config)throw new IOException("MANAGED_CONFIG_INVALID");return verified;
 }
}
