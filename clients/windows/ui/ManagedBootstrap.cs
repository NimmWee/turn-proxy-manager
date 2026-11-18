using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace FreeTurn.Windows;

internal sealed record ManagedBootstrap(
 [property:JsonPropertyName("version")]int Version,
 [property:JsonPropertyName("format")]string Format,
 [property:JsonPropertyName("device_id")]string DeviceId,
 [property:JsonPropertyName("public_key")]string PublicKey,
 [property:JsonPropertyName("origin")]string Origin,
 [property:JsonPropertyName("internal_api_ip")]string InternalAPIIP,
 [property:JsonPropertyName("claim_nonce")]string ClaimNonce,
 [property:JsonPropertyName("expires_at")]string ExpiresAt,
 [property:JsonPropertyName("share")]string Share)
{
 public override string ToString()=>"ManagedBootstrap (private fields omitted)";
 internal static ManagedBootstrap Parse(string raw)
 {
  try{
   if(Encoding.UTF8.GetByteCount(raw)>96*1024)throw new IOException();
   using var doc=JsonDocument.Parse(raw,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);
   if(doc.RootElement.EnumerateObject().Count()!=9)throw new IOException();
   var b=JsonSerializer.Deserialize<ManagedBootstrap>(raw,new JsonSerializerOptions{UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow})??throw new IOException();
   if(b.Version!=1||b.Format!="ftm-bootstrap"||!ManagedCredential.ValidIdentity(b.DeviceId,b.PublicKey,b.Origin,b.InternalAPIIP)||!ManagedCredential.ValidToken(b.ClaimNonce,"ftmb1_")||!ManagedCredential.ValidExpiry(b.ExpiresAt)||b.Share is null||b.Share.Length>65536)throw new IOException();
   _=new ShareDocument(b.Share);return b;
  }catch{throw new IOException("MANAGED_BOOTSTRAP_INVALID");}
 }
 internal static Task VerifySaved(SavedProfile profile)
 {
  var m=profile.Managed??throw new IOException("MANAGED_BOOTSTRAP_INVALID");
  return Verify(JsonSerializer.Serialize(new ManagedBootstrap(1,"ftm-bootstrap",m.DeviceId,m.PublicKey,m.Origin,m.InternalAPIIP,m.ClaimNonce??"ftmb1_"+new string('A',43),m.ExpiresAt,profile.Share)));
 }
 internal static async Task Verify(string raw)
 {
  _=Parse(raw);
  var engine=Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe");if(!File.Exists(engine))throw new IOException("ENGINE_MISSING");
  using var process=new Process{StartInfo=new ProcessStartInfo(engine,"--check-bootstrap"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false)}};
  using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));process.Start();
  try{
   var output=ReadBounded(process.StandardOutput,timeout.Token);var error=ReadBounded(process.StandardError,timeout.Token);
   await process.StandardInput.WriteAsync(raw.AsMemory(),timeout.Token);process.StandardInput.Close();await process.WaitForExitAsync(timeout.Token);
   var reply=await output;await error;
   using var result=JsonDocument.Parse(reply);if(process.ExitCode!=0||result.RootElement.GetProperty("ok").GetBoolean()!=true)throw new IOException();
  }catch{if(!process.HasExited)process.Kill();throw new IOException("MANAGED_BOOTSTRAP_INVALID");}
 }
 private static async Task<string> ReadBounded(StreamReader reader,CancellationToken token)
 {
  var result=new StringBuilder();var buffer=new char[512];
  while(true){var n=await reader.ReadAsync(buffer.AsMemory(),token);if(n==0)return result.ToString();if(result.Length+n>2048)throw new IOException();result.Append(buffer,0,n);}
 }
}

internal sealed record ManagedCredential(string DeviceId,string PublicKey,string Origin,string InternalAPIIP,string? ClaimNonce,string ExpiresAt,string DeviceToken,bool Registered=false,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedConfig? Applied=null,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedConfig? Pending=null,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]string? PreviousShare=null,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedConfig? Previous=null,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)]long SeenRevision=0,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)]bool AccessDenied=false,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]string? EnrollmentSourceHash=null,
 [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedKnownGood? KnownGood=null)
{
 public override string ToString()=>"ManagedCredential (private fields omitted)";
 internal static bool ValidToken(string? token,string prefix)=>token is not null&&token.Length==prefix.Length+43&&Regex.IsMatch(token,"\\A"+prefix+"[A-Za-z0-9_-]{43}\\z",RegexOptions.CultureInvariant);
 internal static bool ValidIdentity(string? id,string? key,string? origin,string? internalIP)
 {
  if(id is null||!Guid.TryParseExact(id,"D",out var uuid)||uuid==Guid.Empty||uuid.ToString("D")!=id||key is null||origin is null||internalIP!="10.77.43.1")return false;
  try{var bytes=Convert.FromBase64String(key);if(bytes.Length!=32||Convert.ToBase64String(bytes)!=key)return false;}catch{return false;}
  return origin.StartsWith("https://",StringComparison.Ordinal)&&IPAddress.TryParse(origin[8..],out var ip)&&ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork&&"https://"+ip.ToString()==origin;
 }
 internal static bool ValidExpiry(string? expiry)=>expiry is not null&&expiry.Length<=40&&DateTimeOffset.TryParse(expiry,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out _);
 internal bool Valid=>ValidIdentity(DeviceId,PublicKey,Origin,InternalAPIIP)&&ValidExpiry(ExpiresAt)&&ValidToken(DeviceToken,"ftmd1_")&&(Registered?ClaimNonce is null:ValidToken(ClaimNonce,"ftmb1_"))&&SeenRevision>=0&&(Applied is null||Applied.Valid&&Applied.Revision<=SeenRevision)&&(Pending is null||Pending.Valid&&Pending.Revision<=SeenRevision)&&(Previous is null||Previous.Valid&&Previous.Revision<=SeenRevision&&PreviousShare is not null)&&(PreviousShare is null||PreviousShare.Length<=96*1024&&PreviousShare.StartsWith("freeturn://",StringComparison.Ordinal))&&(Registered||Applied is null&&Pending is null&&PreviousShare is null&&SeenRevision==0&&!AccessDenied)&&(KnownGood is null||Registered&&KnownGood.Valid&&(KnownGood.Config is null||KnownGood.Config.Revision<=SeenRevision))&&(EnrollmentSourceHash is null||Registered&&EnrollmentAttempt.Hash(EnrollmentSourceHash,64));
 internal static string NewToken()=>"ftmd1_"+Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
 internal static string Digest(string token){if(!ValidToken(token,"ftmd1_"))throw new IOException("MANAGED_BOOTSTRAP_INVALID");return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes("ftm/credential/device/"+token))).ToLowerInvariant();}
}
