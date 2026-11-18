using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FreeTurn.Windows;

internal static class EnrollmentClient
{
 internal static async Task<EnrollmentAttempt> Begin(ProfileCatalog catalog,EnrollmentLink source,string name,Func<string,Task<EnrollmentKey>>? generate=null)
 {
  _=EnrollmentLink.Parse(JsonSerializer.Serialize(source));var data=catalog.Read();
  if(data.Profiles.Any(p=>p.Managed is{} m&&m.Origin==source.Origin&&m.EnrollmentSourceHash==source.SourceHash))throw new IOException("MANAGED_ALREADY_ENROLLED");
  var old=data.Enrollments?.FirstOrDefault(e=>e.Origin==source.Origin&&e.SourceHash==source.SourceHash);if(old is not null)return old;
  if(string.IsNullOrWhiteSpace(name)||name.Trim().Length>128||name.Any(char.IsControl))throw new IOException("MANAGED_ENROLLMENT_INVALID");
  var key=await(generate??EnrollmentEngine.NewKey)(source.Origin);return catalog.StartEnrollment(source,name,key);
 }
 internal static IPEndPoint Target(string origin,bool viaVpn,string host,int port)
 {
  if(!EnrollmentLink.PublicOrigin(origin)||new Uri(origin).Host!=host||port!=443)throw new IOException("MANAGED_ORIGIN_REJECTED");
  return new(IPAddress.Parse(viaVpn?"10.77.43.1":host),443);
 }
 internal static SocketsHttpHandler CreateTransport(string origin,bool viaVpn)
 {
  if(!EnrollmentLink.PublicOrigin(origin))throw new IOException("MANAGED_ENROLLMENT_INVALID");
  return new(){AllowAutoRedirect=false,UseProxy=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(5),MaxResponseHeadersLength=16,
   ConnectCallback=async(ctx,token)=>{
    var target=Target(origin,viaVpn,ctx.DnsEndPoint.Host,ctx.DnsEndPoint.Port);var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
    try{await socket.ConnectAsync(target,token);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}
   }};
 }
 internal static async Task<SavedProfile?> Continue(ProfileCatalog catalog,Guid id,bool viaVpn,bool connected,HttpMessageHandler? syntheticHandler=null,
  Func<EnrollmentAttempt,Task>? verify=null,Func<EnrollmentAttempt,string,string,Task<ManagedConfig>>? build=null,Action<string>? progress=null)
 {
  if(viaVpn&&!connected)throw new IOException("MANAGED_CONNECT_FIRST");
  var data=catalog.Read();var attempt=data.Enrollments?.SingleOrDefault(e=>e.RequestId==id)??throw new IOException("MANAGED_ENROLLMENT_NOT_FOUND");
  await(verify??EnrollmentEngine.Verify)(attempt);
  var completed=data.Profiles.FirstOrDefault(p=>p.Managed is{} m&&m.Origin==attempt.Origin&&m.EnrollmentSourceHash==attempt.SourceHash&&m.PublicKey==attempt.PublicKey&&m.DeviceToken==attempt.DeviceToken);
  if(completed is not null){await ManagedBootstrap.VerifySaved(completed);return catalog.FinishRestoredEnrollment(attempt,completed);}
  using var client=syntheticHandler is null?new HttpClient(CreateTransport(attempt.Origin,viaVpn)):new HttpClient(syntheticHandler,false);client.Timeout=TimeSpan.FromSeconds(15);
  try{
   if(attempt.DeviceId is null&&attempt.Attempted){
    progress?.Invoke("recover");using var known=await Send(client,attempt.Origin,"status",attempt.DeviceToken,null);
    if(known.StatusCode==HttpStatusCode.OK){var(bytes,_)=await Read(known);using var doc=JsonDocument.Parse(bytes,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);var value=doc.RootElement;
     var device=Text(value,"device_id");var revision=Revision(value);var state=Text(value,"state");if(!EnrollmentAttempt.Identifier(device)||state is not("active" or "pending" or "error")||value.GetProperty("ready").GetBoolean()!=(state=="active"))throw new IOException("MANAGED_RESPONSE_INVALID");
     attempt=catalog.AcknowledgeEnrollment(attempt,device,revision);
    }else if(known.StatusCode!=HttpStatusCode.Unauthorized)throw Failure(known.StatusCode);
   }
   if(attempt.DeviceId is null){
    attempt=catalog.MarkEnrollmentStarted(attempt);progress?.Invoke("register");
    using var response=await Send(client,attempt.Origin,"enroll",attempt.UserToken!,new{name=attempt.Name,platform="windows",public_key=attempt.PublicKey,client_id=attempt.ClientId,device_token_hash=ManagedCredential.Digest(attempt.DeviceToken),request_id=attempt.RequestId.ToString("D")});
    if(response.StatusCode is not(HttpStatusCode.OK or HttpStatusCode.Accepted))throw Failure(response.StatusCode);
    var(raw,_)=await Read(response);using var doc=JsonDocument.Parse(raw,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);var value=doc.RootElement;
    var device=Text(value,"device_id");var revision=Revision(value);var state=Text(value,"state");
    if(!EnrollmentAttempt.Identifier(device)||!EnrollmentAttempt.Identifier(Text(value,"subscription_id"))||value.GetProperty("subscription_version").GetInt64()<1||state is not("active" or "pending" or "error")||(response.StatusCode==HttpStatusCode.OK)!=(state=="active"))throw new IOException("MANAGED_RESPONSE_INVALID");
    var ip=IPAddress.Parse(Text(value,"ip")).GetAddressBytes();if(ip.Length!=4||ip[0]!=10||ip[1]!=77||ip[2]!=43||ip[3]<2||ip[3]==255)throw new IOException("MANAGED_RESPONSE_INVALID");
    attempt=catalog.AcknowledgeEnrollment(attempt,device,revision);
   }
   progress?.Invoke("download");using var configuration=await Send(client,attempt.Origin,"subscription",attempt.DeviceToken,null);
   if(configuration.StatusCode is not(HttpStatusCode.OK or HttpStatusCode.Accepted))throw Failure(configuration.StatusCode);
   var(body,etag)=await Read(configuration);
   if(configuration.StatusCode==HttpStatusCode.Accepted){
    using var doc=JsonDocument.Parse(body,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);var v=doc.RootElement;
    if(Text(v,"device_id")!=attempt.DeviceId||Revision(v)<attempt.Revision||v.GetProperty("ready").GetBoolean()||Text(v,"state") is not("pending" or "error"))throw new IOException("MANAGED_RESPONSE_INVALID");
    progress?.Invoke(Text(v,"state")=="error"?"server_error":"pending");return null;
   }
   if(etag is null)throw new IOException("MANAGED_RESPONSE_INVALID");
   progress?.Invoke("validate");var manifest=new UTF8Encoding(false,true).GetString(body);var config=await(build??EnrollmentEngine.BuildInitial)(attempt,manifest,etag);
   var profile=catalog.CompleteEnrollment(attempt,config);progress?.Invoke("ready");return profile;
  }catch(IOException e)when(e.Message.StartsWith("MANAGED_",StringComparison.Ordinal)){throw;}
  catch{throw new IOException("MANAGED_NETWORK_FAILED");}
 }
 private static string Text(JsonElement value,string key)=>value.GetProperty(key).GetString()??throw new IOException("MANAGED_RESPONSE_INVALID");
 private static long Revision(JsonElement value){var revision=value.GetProperty("revision").GetInt64();if(revision<1)throw new IOException("MANAGED_RESPONSE_INVALID");return revision;}
 private static IOException Failure(HttpStatusCode code)=>new(code switch{HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden=>"MANAGED_ACCESS_REJECTED",HttpStatusCode.Conflict=>"MANAGED_ENROLLMENT_CONFLICT",HttpStatusCode.TooManyRequests=>"MANAGED_RATE_LIMITED",_=>"MANAGED_SERVER_REJECTED"});
 private static async Task<HttpResponseMessage> Send(HttpClient client,string origin,string operation,string token,object? payload)
 {
  using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
  using var request=new HttpRequestMessage(payload is null?HttpMethod.Get:HttpMethod.Post,origin+"/api/client/v1/"+operation){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
  request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);request.Headers.Accept.Add(new("application/json"));
  if(payload is not null)request.Content=new StringContent(JsonSerializer.Serialize(payload),Encoding.UTF8,"application/json");
  return await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
 }
 private static async Task<(byte[] Body,string? ETag)> Read(HttpResponseMessage response)
 {
  using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));return(await ManagedClient.ReadBody(response,timeout.Token),response.Headers.ETag?.ToString());
 }
}
