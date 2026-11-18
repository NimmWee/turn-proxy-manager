using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreeTurn.Windows;

internal static class EnrollmentNetworkChecks
{
 internal static async Task Run(string directory,EnrollmentLink source,EnrollmentKey pair,bool engine,bool serverCommitted)
 {
  var catalog=new ProfileCatalog(directory);var generated=0;
  Task<EnrollmentKey> Generate(string _){generated++;return Task.FromResult(pair);}
  var attempt=await EnrollmentClient.Begin(catalog,source,"Windows retry",Generate);
  if(await EnrollmentClient.Begin(catalog,source,"Changed name",Generate)!=attempt||generated!=1)throw new Exception("Enrollment resumed by generating another identity");
  var posts=0;var known=false;var ready=false;string? sentBody=null;
  const string device="11111111-2222-3333-4444-555555555555";
  using var handler=new Fake(async request=>{
   var saved=catalog.Read().Enrollments!.Single();if(!saved.Attempted||!saved.SameIdentity(attempt))throw new Exception("Network before durable enrollment identity");
   if(request.RequestUri!.Host!="8.8.8.8"||request.RequestUri.Query!=""||request.Version!=HttpVersion.Version11||request.VersionPolicy!=HttpVersionPolicy.RequestVersionExact)throw new Exception("Enrollment HTTP destination/version changed");
   var path=request.RequestUri.AbsolutePath;
   if(path.EndsWith("/enroll",StringComparison.Ordinal)){
    posts++;var body=await request.Content!.ReadAsStringAsync();using var parsed=JsonDocument.Parse(body);var r=parsed.RootElement;
    if(request.Headers.Authorization?.Parameter!=source.UserToken||r.EnumerateObject().Count()!=6||r.GetProperty("name").GetString()!=attempt.Name||r.GetProperty("platform").GetString()!="windows"||r.GetProperty("public_key").GetString()!=attempt.PublicKey||r.GetProperty("client_id").GetString()!=attempt.ClientId||r.GetProperty("request_id").GetString()!=attempt.RequestId.ToString("D")||r.GetProperty("device_token_hash").GetString()!=Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes("ftm/credential/device/"+attempt.DeviceToken))).ToLowerInvariant()||body.Contains(attempt.PrivateKey)||body.Contains(attempt.DeviceToken)||body.Contains(source.UserToken))throw new Exception("Enrollment leaked credentials or changed idempotency binding");
    if(sentBody is not null&&sentBody!=body)throw new Exception("Lost-response retry changed POST body");sentBody=body;
    if(posts==1){known=serverCommitted;throw new HttpRequestException("SYNTHETIC_RESPONSE_LOST");}
    if(serverCommitted)throw new Exception("Rotated user token retried instead of device-token recovery");
    known=true;return Json(HttpStatusCode.Accepted,new{device_id=device,subscription_id="22222222-2222-3333-4444-555555555555",subscription_version=1,revision=1,state="pending",ip="10.77.43.9"});
   }
   if(request.Headers.Authorization?.Parameter!=attempt.DeviceToken||request.Content is not null)throw new Exception("Resume sent user token/private key instead of device authorization");
   if(path.EndsWith("/status",StringComparison.Ordinal))return known?Json(HttpStatusCode.OK,new{device_id=device,state="pending",revision=1,ready=false,retry_after_seconds=5}):new(HttpStatusCode.Unauthorized);
   if(!path.EndsWith("/subscription",StringComparison.Ordinal))throw new Exception("Unexpected enrollment endpoint");
   if(!ready)return Json(HttpStatusCode.Accepted,new{device_id=device,state="pending",revision=1,ready=false,retry_after_seconds=5});
   var manifest=Manifest(saved);var response=new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(manifest)};response.Headers.ETag=new EntityTagHeaderValue(ETag(manifest));return response;
  });
  Func<EnrollmentAttempt,Task> verify=engine?EnrollmentEngine.Verify:_=>Task.CompletedTask;
  Func<EnrollmentAttempt,string,string,Task<ManagedConfig>> builder=engine?EnrollmentEngine.BuildInitial:FakeBuild;
  var gate=false;try{await EnrollmentClient.Continue(catalog,attempt.RequestId,true,false,handler,verify,builder);}catch(IOException){gate=true;}if(!gate||posts!=0)throw new Exception("Internal enrollment ignored connected gate");
  try{await EnrollmentClient.Continue(catalog,attempt.RequestId,false,false,handler,verify,builder);}catch(IOException){}
  if(posts!=1||catalog.Read().Enrollments!.Single().DeviceId is not null)throw new Exception("Lost response altered local acknowledgment");
  catalog=new ProfileCatalog(directory); // new process/catalog view after restart
  if(await EnrollmentClient.Continue(catalog,attempt.RequestId,false,false,handler,verify,builder)is not null)throw new Exception("Pending server returned a fake ready profile");
  var pending=catalog.Read().Enrollments!.Single();if(pending.UserToken is not null||pending.DeviceId!=device||pending.PrivateKey!=attempt.PrivateKey||posts!=(serverCommitted?1:2))throw new Exception("Resume failed to recover token/key/idempotency");
  ready=true;var completed=await EnrollmentClient.Continue(catalog,attempt.RequestId,false,false,handler,verify,builder)??throw new Exception("Ready configuration not committed");
  var snapshot=catalog.Read();if(snapshot.Enrollments is not null||snapshot.Profiles.Count!=1||snapshot.ActiveId is not null||completed.Managed!.DeviceToken!=attempt.DeviceToken||completed.Managed.EnrollmentSourceHash!=source.SourceHash||!new ShareDocument(completed.Share).WireGuard.Contains("PrivateKey = "+attempt.PrivateKey,StringComparison.Ordinal))throw new Exception("First profile commit lost identity or auto-selected VPN");
  var duplicate=false;try{await EnrollmentClient.Begin(catalog,source,"Duplicate",Generate);}catch(IOException){duplicate=true;}if(!duplicate||generated!=1)throw new Exception("Completed subscription created another device on this PC");
  Console.WriteLine(engine?"PASS: fake enrollment HTTP lost response/restart/202→ready with actual Go keys+manifest, stable private key/CID/UUID/token; no live HTTPS/VPN":"PASS: fake enrollment HTTP lost response/restart/202→ready, stable private key/CID/UUID/token (synthetic builder)");
 }
 private static HttpResponseMessage Json(HttpStatusCode code,object value)=>new(code){Content=new StringContent(JsonSerializer.Serialize(value))};
 private sealed class Fake(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler{protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request);}
 private static string Manifest(EnrollmentAttempt a){
  var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));
  var node=JsonSerializer.SerializeToNode(new{schema_version=1,format="ftm-managed",device_id=a.DeviceId,revision=2,name=a.Name,platform="windows",wireguard=new{client_public_key=a.PublicKey,addresses=new[]{"10.77.43.9/32"},server_public_key=key,preshared_key=key,allowed_ips=new[]{"0.0.0.0/0","::/0"},dns=new[]{"1.1.1.1","8.8.8.8"},mtu=1280,local_endpoint="127.0.0.1:9000",persistent_keepalive=25,ipv6_policy="block"},freeturn=new{v=1,provider="vk",peer="8.8.8.8:5000",transport="tcp",mode="udp",obf="rtpopus3",key=new string('a',64),n=6,spc=3,cid=a.ClientId,dns="auto",mcap=false,vk="https://vk.com/call/join/SYNTHETIC"},management=new{origin=a.Origin,api_path="/api/client/v1/",internal_api_ip="10.77.43.1",tls_server_name="8.8.8.8",refresh_seconds=1800}})!;
  return Sort(node).ToJsonString(new(){Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
 }
 private static string ETag(string raw)=>"\""+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant()+"\"";
 private static JsonNode Sort(JsonNode node)=>node switch{JsonObject o=>new JsonObject(o.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>new KeyValuePair<string,JsonNode?>(p.Key,p.Value is null?null:Sort(p.Value)))),JsonArray a=>new JsonArray(a.Select(p=>p is null?null:Sort(p)).ToArray()),_=>node.DeepClone()};
 private static Task<ManagedConfig> FakeBuild(EnrollmentAttempt a,string raw,string etag){
  var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));var m=JsonNode.Parse(raw)!;
  var wg=$"[Interface]\nPrivateKey = {a.PrivateKey}\nAddress = 10.77.43.9/32\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1280\n[Peer]\nPublicKey = {key}\nPresharedKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n";
  var ft=m["freeturn"]!.DeepClone();ft["name"]=a.Name;ft["wg"]=wg;var share="freeturn://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(ft.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');return Task.FromResult(new ManagedConfig(raw,share,etag,2));
 }
}
