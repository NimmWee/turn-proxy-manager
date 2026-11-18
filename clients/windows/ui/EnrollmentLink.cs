using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FreeTurn.Windows;

internal sealed record EnrollmentLink(
 [property:JsonPropertyName("version")]int Version,
 [property:JsonPropertyName("format")]string Format,
 [property:JsonPropertyName("origin")]string Origin,
 [property:JsonPropertyName("user_token")]string UserToken)
{
 internal const string Scheme="ftm-enroll://";
 public override string ToString()=>"EnrollmentLink (private fields omitted)";
 internal string SourceHash=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("ftm/enrollment/source/v1\n"+Origin+"\n"+UserToken))).ToLowerInvariant();
 internal string ToUri()=>Scheme+Encode(JsonSerializer.SerializeToUtf8Bytes(this));
 private static string Encode(byte[] raw)=>Convert.ToBase64String(raw).TrimEnd('=').Replace('+','-').Replace('/','_');
 internal static bool LooksLike(string input){
  if(input.StartsWith(Scheme,StringComparison.Ordinal))return true;
  try{using var doc=JsonDocument.Parse(input,new(){MaxDepth=8});return doc.RootElement.TryGetProperty("format",out var f)&&f.GetString()=="ftm-enrollment";}catch{return false;}
 }
 internal static EnrollmentLink Parse(string input)
 {
  try{
   input=input.Trim();if(input.Length>8192)throw new IOException();
   if(input.StartsWith(Scheme,StringComparison.Ordinal)){
    var encoded=input[Scheme.Length..];if(encoded.Length==0||encoded.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-'&&c!='_'))throw new IOException();
    var text=encoded.Replace('-','+').Replace('_','/');text=text.PadRight((text.Length+3)/4*4,'=');var raw=Convert.FromBase64String(text);
    if(Encode(raw)!=encoded)throw new IOException();input=new UTF8Encoding(false,true).GetString(raw);
   }
   if(Encoding.UTF8.GetByteCount(input)>4096)throw new IOException();
   using var doc=JsonDocument.Parse(input,new(){MaxDepth=4});ShareDocument.Unique(doc.RootElement);if(doc.RootElement.EnumerateObject().Count()!=4)throw new IOException();
   var value=JsonSerializer.Deserialize<EnrollmentLink>(input,new JsonSerializerOptions{UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow})??throw new IOException();
   if(value.Version!=1||value.Format!="ftm-enrollment"||!PublicOrigin(value.Origin)||!ManagedCredential.ValidToken(value.UserToken,"ftmu1_"))throw new IOException();
   return value;
  }catch{throw new IOException("MANAGED_ENROLLMENT_INVALID");}
 }
 internal static bool PublicOrigin(string? origin)
 {
  if(origin is null||!origin.StartsWith("https://",StringComparison.Ordinal)||!IPAddress.TryParse(origin[8..],out var ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||"https://"+ip.ToString()!=origin)return false;
  var bytes=ip.GetAddressBytes();uint address=((uint)bytes[0]<<24)|((uint)bytes[1]<<16)|((uint)bytes[2]<<8)|bytes[3];
  foreach(var block in new[]{"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4","168.63.129.16/32"}){
   var parts=block.Split('/');var p=IPAddress.Parse(parts[0]).GetAddressBytes();uint network=((uint)p[0]<<24)|((uint)p[1]<<16)|((uint)p[2]<<8)|p[3];var shift=32-int.Parse(parts[1]);if(address>>shift==network>>shift)return false;
  }
  return true;
 }
}
