using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal static class ManagedClient
{
 internal static async Task<byte[]> ReadBody(HttpResponseMessage response,CancellationToken token)
 {
  if(response.Content.Headers.ContentLength>65536)throw new IOException("MANAGED_RESPONSE_INVALID");
  using var stream=await response.Content.ReadAsStreamAsync(token);using var data=new MemoryStream();var buffer=new byte[4096];
  while(true){var n=await stream.ReadAsync(buffer,token);if(n==0)break;if(data.Length+n>65536)throw new IOException("MANAGED_RESPONSE_INVALID");data.Write(buffer,0,n);}
  return data.ToArray();
 }
 internal static IPEndPoint InternalTarget(ManagedCredential m,string host,int port)
 {
  if(!m.Valid||new Uri(m.Origin).Host!=host||port!=443)throw new IOException("MANAGED_ORIGIN_REJECTED");
  return new IPEndPoint(IPAddress.Parse("10.77.43.1"),443);
 }
 internal static SocketsHttpHandler CreateTransport(ManagedCredential m)
 {
  if(!m.Valid)throw new IOException("MANAGED_BOOTSTRAP_INVALID");
  return new SocketsHttpHandler{
   AllowAutoRedirect=false,UseProxy=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(5),MaxResponseHeadersLength=16,
   ConnectCallback=async(ctx,token)=>{
    var target=InternalTarget(m,ctx.DnsEndPoint.Host,ctx.DnsEndPoint.Port);
    var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
    try{await socket.ConnectAsync(target,token);return new NetworkStream(socket,true);}
    catch{socket.Dispose();throw;}
   }
  };
 }
 // The UI supplies authenticated connected state. No startup/import background
 // network, public fallback, redirect, certificate override or privileged bypass.
 internal static async Task Claim(ProfileCatalog catalog,Guid id,bool connected,HttpMessageHandler? syntheticHandler=null,Func<SavedProfile,Task>? verify=null,Func<Task>? ensureCurrent=null)
 {
  if(!connected)throw new IOException("MANAGED_CONNECT_FIRST");
  var p=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==id)??throw new IOException("PROFILE_NOT_FOUND");
  var m=p.Managed??throw new IOException("MANAGED_BOOTSTRAP_INVALID");
  if(!m.Valid)throw new IOException("MANAGED_BOOTSTRAP_INVALID");if(m.Registered)return;
  await (verify??ManagedBootstrap.VerifySaved)(p);
  using var client=syntheticHandler is null?new HttpClient(CreateTransport(m)):new HttpClient(syntheticHandler,false);
  client.Timeout=TimeSpan.FromSeconds(15);
  using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
  async Task Current(){
   timeout.Token.ThrowIfCancellationRequested();if(ensureCurrent is not null)await ensureCurrent();timeout.Token.ThrowIfCancellationRequested();
   var latest=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==id);
   if(latest is null||latest.Share!=p.Share||latest.Managed!=m)throw new IOException("MANAGED_STORAGE_CHANGED");
  }
  using var request=new HttpRequestMessage(HttpMethod.Post,m.Origin+"/api/client/v1/bootstrap/claim"){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
  request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",m.ClaimNonce);request.Headers.Accept.Add(new("application/json"));
  request.Content=new StringContent(JsonSerializer.Serialize(new{device_id=m.DeviceId,device_token_hash=ManagedCredential.Digest(m.DeviceToken)}),Encoding.UTF8,"application/json");
  try{
   await Current();
   // A prior POST may have committed even when its response was lost. The
   // stable device token is the authority here; expiry applies only to a new POST.
   using(var knownRequest=new HttpRequestMessage(HttpMethod.Get,m.Origin+"/api/client/v1/status"){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact}){
    knownRequest.Headers.Authorization=new AuthenticationHeaderValue("Bearer",m.DeviceToken);knownRequest.Headers.Accept.Add(new("application/json"));
    using var known=await client.SendAsync(knownRequest,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
    await Current();
    if(known.StatusCode==HttpStatusCode.OK){
     var bytes=await ReadBody(known,timeout.Token);var active=KnownActive(bytes,m);await Current();
     if(!active)throw new IOException("MANAGED_ACTIVATION_PENDING");
     catalog.MarkManagedRegistered(id,m,p.Share);return;
    }
    if(known.StatusCode!=HttpStatusCode.Unauthorized)throw new IOException(known.StatusCode switch{HttpStatusCode.Forbidden=>"MANAGED_ACCESS_REJECTED",HttpStatusCode.TooManyRequests=>"MANAGED_RATE_LIMITED",_=>"MANAGED_SERVER_REJECTED"});
   }
   await Current();
   if(DateTimeOffset.Parse(m.ExpiresAt,System.Globalization.CultureInfo.InvariantCulture)<=DateTimeOffset.UtcNow)throw new IOException("MANAGED_BOOTSTRAP_EXPIRED");
   using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
   if(response.StatusCode!=HttpStatusCode.OK)throw new IOException(response.StatusCode switch{HttpStatusCode.Gone=>"MANAGED_BOOTSTRAP_EXPIRED",HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden=>"MANAGED_ACCESS_REJECTED",HttpStatusCode.TooManyRequests=>"MANAGED_RATE_LIMITED",_=>"MANAGED_SERVER_REJECTED"});
   var data=await ReadBody(response,timeout.Token);ValidateClaimAck(data,m);await Current();
   catalog.MarkManagedRegistered(id,m,p.Share);
  }catch(IOException e)when(e.Message.StartsWith("MANAGED_",StringComparison.Ordinal)){throw;}
  catch(OperationCanceledException)when(!timeout.IsCancellationRequested){throw new IOException("MANAGED_SESSION_CHANGED");}
  catch{throw new IOException("MANAGED_NETWORK_FAILED");}
 }
 private static bool KnownActive(byte[] data,ManagedCredential m)
 {
  try{
   using var doc=JsonDocument.Parse(data,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);var value=doc.RootElement;
   if(value.EnumerateObject().Count()!=5||value.GetProperty("device_id").GetString()!=m.DeviceId||value.GetProperty("revision").GetInt64()<1)throw new IOException();
   var state=value.GetProperty("state").GetString();var ready=value.GetProperty("ready").GetBoolean();var retry=value.GetProperty("retry_after_seconds").GetInt32();
   if(state is not("active" or "pending" or "error")||ready!=(state=="active")||retry<0||retry>3600)throw new IOException();return ready;
  }catch{throw new IOException("MANAGED_RESPONSE_INVALID");}
 }
 private static void ValidateClaimAck(byte[] data,ManagedCredential m)
 {
  try{
   using var doc=JsonDocument.Parse(data,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);var value=doc.RootElement;
   if(value.GetProperty("device_id").GetString()!=m.DeviceId||value.GetProperty("state").GetString()!="active"||!value.GetProperty("ready").GetBoolean())throw new IOException();
  }catch{throw new IOException("MANAGED_RESPONSE_INVALID");}
 }
}
