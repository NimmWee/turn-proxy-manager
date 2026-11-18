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

internal static class SubscriptionChecks
{
 internal static async Task Network(ProfileCatalog catalog,Guid id,bool engine)
 {
  var initial=catalog.Read().Profiles.Single(p=>p.Id==id);var m=initial.Managed!;
  var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));
  var root=JsonSerializer.SerializeToNode(new{
   schema_version=1,format="ftm-managed",device_id=m.DeviceId,revision=3,name="Managed updated",platform="windows",
   wireguard=new{client_public_key=m.PublicKey,addresses=new[]{"10.77.43.9/32"},server_public_key=key,preshared_key=key,allowed_ips=new[]{"0.0.0.0/0","::/0"},dns=new[]{"1.1.1.1","8.8.8.8"},mtu=1280,local_endpoint="127.0.0.1:9000",persistent_keepalive=25,ipv6_policy="block"},
   freeturn=new{v=1,provider="vk",peer="8.8.8.8:5001",transport="tcp",mode="udp",obf="rtpopus3",key=new string('a',64),n=6,spc=3,cid=new string('b',32),dns="auto",mcap=false,vk="https://vk.com/call/join/SYNTHETIC"},
   management=new{origin=m.Origin,api_path="/api/client/v1/",internal_api_ip="10.77.43.1",tls_server_name="8.8.8.8",refresh_seconds=1800}
  })!;
  var manifest=Sort(root).ToJsonString(new(){Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
  var etag="\""+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(manifest))).ToLowerInvariant()+"\"";
  var encoded=initial.Share["freeturn://".Length..].Replace('-','+').Replace('_','/');encoded=encoded.PadRight((encoded.Length+3)/4*4,'=');
  var native=JsonNode.Parse(Convert.FromBase64String(encoded))!;native["peer"]="8.8.8.8:5001";
  var fakeShare="freeturn://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(native.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
  Func<SavedProfile,Task> verify=engine?ManagedBootstrap.VerifySaved:_=>Task.CompletedTask;
  Func<SavedProfile,string,string,long,Task<ManagedConfig>> build=engine?ManagedUpdateBuilder.Build:(_,raw,tag,_)=>Task.FromResult(new ManagedConfig(raw,fakeShare,tag,3));
  var calls=0;HttpStatusCode code=HttpStatusCode.OK;string tag=etag;var oversized=false;
  using var handler=new Fake(request=>{
   calls++;if(request.Method!=HttpMethod.Get||request.Content is not null||request.RequestUri!.AbsoluteUri!=m.Origin+"/api/client/v1/subscription"||request.Headers.Authorization?.Parameter!=m.DeviceToken||request.Version!=HttpVersion.Version11||request.VersionPolicy!=HttpVersionPolicy.RequestVersionExact)throw new Exception("Subscription request leaked identity or changed transport");
   if(code==HttpStatusCode.NotModified&&request.Headers.IfNoneMatch.Single().ToString()!=etag)throw new Exception("Conditional request lost validated ETag");
   var response=new HttpResponseMessage(code);response.Headers.ETag=new EntityTagHeaderValue(tag);
   if(code==HttpStatusCode.OK){response.Content=new StringContent(manifest);if(oversized)response.Content.Headers.ContentLength=65537;}
   return response;
  });
  var blocked=false;try{await ManagedSubscription.Refresh(catalog,id,false,handler,verify,build);}catch(IOException){blocked=true;}if(!blocked||calls!=0)throw new Exception("Subscription request before connected gate");
  if(await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build)!=ManagedRefresh.Staged)throw new Exception("Update was not staged");
  var staged=catalog.Read().Profiles.Single(p=>p.Id==id);
  if(staged.Share!=initial.Share||staged.Managed!.Pending is not{} pending||staged.Managed.DeviceToken!=m.DeviceToken||!new ShareDocument(pending.Share).WireGuard.Contains("PrivateKey = "+key,StringComparison.Ordinal))throw new Exception("Update replaced active profile/private key/token");
  var backup=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(catalog.Read()),"SYNTHETIC_BACKUP_PASSWORD"),"SYNTHETIC_BACKUP_PASSWORD"));
  if(backup.Profiles.Single().Managed!.Pending!=pending)throw new Exception("Encrypted backup lost pending update");
  catalog.Merge(new ProfileSnapshot(1,null,[initial]));if(catalog.Read().Profiles.Single().Managed!.Pending!=pending)throw new Exception("Old restore erased revision/candidate");
  code=HttpStatusCode.NotModified;if(await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build)!=ManagedRefresh.Unchanged)throw new Exception("Validated304 failed");
  code=HttpStatusCode.Accepted;if(await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build)!=ManagedRefresh.Pending||catalog.Read().Profiles.Single().Share!=initial.Share)throw new Exception("Pending response replaced working config");
  foreach(var failure in new[]{HttpStatusCode.Redirect,HttpStatusCode.InternalServerError,HttpStatusCode.OK}){
   code=failure;oversized=failure==HttpStatusCode.OK;var refused=false;try{await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build);}catch(IOException){refused=true;}
   if(!refused||catalog.Read().Profiles.Single().Share!=initial.Share)throw new Exception("Bad/oversized/redirect response changed working config");
  }
  oversized=false;code=HttpStatusCode.Forbidden;try{await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build);}catch(IOException){}
  if(!catalog.Read().Profiles.Single().Managed!.AccessDenied)throw new Exception("403 did not persist access refusal");
  code=HttpStatusCode.NotModified;tag="\""+new string('b',64)+"\"";
  try{await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build);}catch(IOException){}
  if(!catalog.Read().Profiles.Single().Managed!.AccessDenied)throw new Exception("Wrong304 cleared access refusal");
  tag=etag;code=HttpStatusCode.OK;await ManagedSubscription.Refresh(catalog,id,true,handler,verify,build);
  if(catalog.Read().Profiles.Single().Managed!.AccessDenied)throw new Exception("Authenticated update did not clear access refusal");
  if(engine){await ManagedSubscription.Apply(catalog,id);if(catalog.Read().Profiles.Single().Share==initial.Share)throw new Exception("Explicit apply did not select candidate");await ManagedSubscription.Rollback(catalog,id);if(catalog.Read().Profiles.Single().Share!=initial.Share)throw new Exception("Explicit rollback lost original profile bytes");}
  Console.WriteLine(engine?"PASS: synthetic HTTP subscription200/202/304/refusal/bounds + actual C#→Go builder, DPAPI staging/apply/rollback/key and backup preservation; live HTTPS/VPN NOT RUN":"PASS: synthetic HTTP subscription200/202/304/refusal/bounds preserve working config (synthetic builder; live HTTPS/VPN NOT RUN)");
 }
 private static JsonNode Sort(JsonNode node)=>node switch{JsonObject o=>new JsonObject(o.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>new KeyValuePair<string,JsonNode?>(p.Key,p.Value is null?null:Sort(p.Value)))),JsonArray a=>new JsonArray(a.Select(p=>p is null?null:Sort(p)).ToArray()),_=>node.DeepClone()};
 private sealed class Fake(Func<HttpRequestMessage,HttpResponseMessage> send):HttpMessageHandler{protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(send(request));}
 internal static void Storage(ProfileCatalog catalog,Guid id)
 {
  var initial=catalog.Read().Profiles.Single(p=>p.Id==id);var token=initial.Managed!.DeviceToken;
  // Storage scenario uses synthetic builder results, not a claimed manifest/TLS
  // validation. HTTP+actual Go builder are checked separately.
  var config=new ManagedConfig("{}",initial.Share,"\""+new string('a',64)+"\"",2);
  catalog.StageManaged(initial,config);
  var staged=catalog.Read().Profiles.Single(p=>p.Id==id);
  if(staged.Share!=initial.Share||staged.Managed!.Pending!=config||staged.Managed.SeenRevision!=2||staged.Managed.DeviceToken!=token)throw new Exception("Staging replaced active share/key/token");
  var stale=false;try{catalog.ApplyManaged(initial,config);}catch(IOException){stale=true;}if(!stale)throw new Exception("Stale asynchronous apply overwrote updated metadata");
  catalog.ApplyManaged(staged,config);
  var applied=catalog.Read().Profiles.Single(p=>p.Id==id);
  if(applied.Managed!.Pending!=null||applied.Managed.PreviousShare!=initial.Share||applied.Managed.Applied!=config)throw new Exception("Explicit apply lost rollback snapshot");
  catalog.RollbackManaged(applied);
  var rolled=catalog.Read().Profiles.Single(p=>p.Id==id);
  if(rolled.Share!=initial.Share||rolled.Managed!.SeenRevision!=2||rolled.Managed.DeviceToken!=token)throw new Exception("Rollback changed identity or lowered revision fence");
  catalog.DenyManaged(rolled);var denied=catalog.Read().Profiles.Single(p=>p.Id==id);
  var blocked=false;try{catalog.ApplyManaged(denied,config);}catch(IOException){blocked=true;}if(!blocked||!denied.Managed!.AccessDenied||denied.Share!=initial.Share)throw new Exception("Revoked credential could silently reuse cached update");
  catalog.ConfirmManagedUnchanged(denied); // HTTP layer must validate304 first.
  if(catalog.Read().Profiles.Single(p=>p.Id==id).Managed!.AccessDenied)throw new Exception("Successful authenticated refresh could not clear access flag");
  Console.WriteLine("PASS: managed staging/apply/rollback/revision fence/stale commit/revoke guard preserve DPAPI keys and token (synthetic config)");
 }
}
