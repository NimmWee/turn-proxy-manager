using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal static class EnrollmentEngine
{
 internal static async Task<EnrollmentKey> NewKey(string origin)
 {
  if(!EnrollmentLink.PublicOrigin(origin))throw new IOException("MANAGED_ENROLLMENT_INVALID");
  using var reply=await Request("--new-enrollment-key",new{origin});var root=reply.RootElement;
  var key=new EnrollmentKey(root.GetProperty("private_key").GetString()!,root.GetProperty("public_key").GetString()!);
  if(!key.Valid)throw new IOException("MANAGED_ENROLLMENT_INVALID");return key;
 }
 internal static async Task Verify(EnrollmentAttempt attempt)
 {
  if(!attempt.Valid)throw new IOException("MANAGED_ENROLLMENT_INVALID");
  using var result=await Request("--check-enrollment-key",new{origin=attempt.Origin,private_key=attempt.PrivateKey,public_key=attempt.PublicKey});
 }
 internal static async Task<ManagedConfig> BuildInitial(EnrollmentAttempt attempt,string manifest,string etag)
 {
  if(!attempt.Valid||attempt.DeviceId is null||Encoding.UTF8.GetByteCount(manifest)>65536)throw new IOException("MANAGED_ENROLLMENT_INVALID");
  using var document=JsonDocument.Parse(manifest,new(){MaxDepth=8});ShareDocument.Unique(document.RootElement);
  using var reply=await Request("--build-enrollment",new{manifest=document.RootElement,origin=attempt.Origin,private_key=attempt.PrivateKey,public_key=attempt.PublicKey,device_id=attempt.DeviceId,client_id=attempt.ClientId,etag,min_revision=attempt.Revision});
  var r=reply.RootElement;var config=new ManagedConfig(manifest,r.GetProperty("share").GetString()!,r.GetProperty("etag").GetString()!,r.GetProperty("revision").GetInt64());
  if(!config.Valid||config.ETag!=etag||config.Revision<attempt.Revision||config.Revision!=document.RootElement.GetProperty("revision").GetInt64())throw new IOException("MANAGED_CONFIG_INVALID");return config;
 }
 private static async Task<JsonDocument> Request(string operation,object payload)
 {
  var input=JsonSerializer.Serialize(payload);if(Encoding.UTF8.GetByteCount(input)>256*1024)throw new IOException("MANAGED_ENROLLMENT_INVALID");
  var engine=Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe");if(!File.Exists(engine))throw new IOException("ENGINE_MISSING");
  using var p=new Process{StartInfo=new ProcessStartInfo(engine,operation){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false,true)}};
  p.Start();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
  try{
   var output=Read(p.StandardOutput,timeout.Token);var errors=Read(p.StandardError,timeout.Token);
   await p.StandardInput.WriteAsync(input.AsMemory(),timeout.Token);p.StandardInput.Close();await p.WaitForExitAsync(timeout.Token);
   var text=await output;await errors;var reply=JsonDocument.Parse(text,new(){MaxDepth=8});
   if(p.ExitCode!=0||!reply.RootElement.GetProperty("ok").GetBoolean()){reply.Dispose();throw new IOException();}return reply;
  }catch{if(!p.HasExited)p.Kill();throw new IOException("MANAGED_ENROLLMENT_INVALID");}
 }
 private static async Task<string> Read(StreamReader reader,CancellationToken token)
 {
  var text=new StringBuilder();var buffer=new char[2048];
  while(true){var n=await reader.ReadAsync(buffer.AsMemory(),token);if(n==0)return text.ToString();if(text.Length+n>256*1024)throw new IOException();text.Append(buffer,0,n);}
 }
}
