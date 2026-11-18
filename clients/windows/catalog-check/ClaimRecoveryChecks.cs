using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using FreeTurn.Windows;

internal static class ClaimRecoveryChecks
{
 internal static async Task Run(string root,ManagedBootstrap bootstrap,bool engine)
 {
  var catalog=new ProfileCatalog(Path.Combine(root,"claim-lost"));var initial=catalog.AddBootstrap(bootstrap,true);var token=initial.Managed!.DeviceToken;
  var bound=false;var posts=0;var gets=0;
  using var handler=new Fake(async request=>{
   if(request.Method==HttpMethod.Get){gets++;if(request.RequestUri!.AbsolutePath!="/api/client/v1/status"||request.Headers.Authorization?.Parameter!=token||request.Content is not null)throw new Exception("Status leaked nonce/used wrong token");return bound?Status(bootstrap.DeviceId):new(HttpStatusCode.Unauthorized);}
   posts++;if(request.RequestUri!.AbsolutePath!="/api/client/v1/bootstrap/claim"||request.Headers.Authorization?.Parameter!=bootstrap.ClaimNonce)throw new Exception("Claim boundary wrong");
   var body=await request.Content!.ReadAsStringAsync();if(body.Contains(token)||!body.Contains(ManagedCredential.Digest(token)))throw new Exception("Claim changed token hash");bound=true;throw new HttpRequestException("SYNTHETIC_LOST_RESPONSE_PRIVATE");
  });
  Func<SavedProfile,Task> verify=engine?ManagedBootstrap.VerifySaved:_=>Task.CompletedTask;
  try{await ManagedClient.Claim(catalog,initial.Id,true,handler,verify);}catch(IOException e)when(e.Message=="MANAGED_NETWORK_FAILED"){}
  if(!bound||posts!=1||catalog.Read().Profiles.Single().Managed!.Registered)throw new Exception("Lost POST scenario not preserved");
  var backup=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));
  var expired=backup.Profiles.Single() with{Managed=backup.Profiles.Single().Managed! with{ExpiresAt=DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O")}};
  var restored=new ProfileCatalog(Path.Combine(root,"claim-restored"));restored.Merge(backup with{Profiles=[expired]});restored.Select(expired.Id);
  try{await ManagedClient.Claim(restored,expired.Id,true,handler,verify);}catch(IOException e){throw new Exception("Lost response after expiry was not recovered: "+e.Message);}
  var recovered=restored.Read();var p=recovered.Profiles.Single();
  if(!p.Managed!.Registered||p.Managed.ClaimNonce is not null||p.Managed.DeviceToken!=token||p.Share!=initial.Share||p.Managed.PublicKey!=initial.Managed.PublicKey||recovered.ActiveId!=p.Id||posts!=1||gets!=2)throw new Exception("Recovery rotated keys/token/selection or repeated POST");
  await ManagedClient.Claim(restored,p.Id,true,handler,verify);
  if(posts!=1||gets!=2)throw new Exception("Registered claim performed HTTP again");
  await RefusalChecks(root,bootstrap,verify,engine);
  Console.WriteLine(engine?"PASS: lost claim→DPAPI backup/restart→expired nonce→device status recovery with actual Go key binding; no live HTTPS/VPN":"PASS: synthetic lost claim→DPAPI backup/restart→expired nonce→status recovery preserves keys/token/selection and avoids repeated POST");
 }
 private static async Task RefusalChecks(string root,ManagedBootstrap bootstrap,Func<SavedProfile,Task> verify,bool engine)
 {
  var index=0;
  (ProfileCatalog Catalog,SavedProfile Profile) Fixture(bool expired=false){
   var c=new ProfileCatalog(Path.Combine(root,"claim-refusal-"+(index++)));
   return(c,c.AddBootstrap(bootstrap with{ExpiresAt=DateTimeOffset.UtcNow.AddMinutes(expired?-1:10).ToString("O")},true));
  }
  async Task Expect(string code,Func<Task> action){
   try{await action();throw new Exception("Claim unexpectedly succeeded");}
   catch(IOException e)when(e.Message==code){}
  }
  void Unchanged(ProfileCatalog c,SavedProfile p){var s=c.Read();if(s.ActiveId!=p.Id||s.Profiles.Count!=1||s.Profiles[0]!=p)throw new Exception("Refused claim changed private profile/selection");}
  var cases=new (Func<HttpResponseMessage> Reply,string Code,bool Expired)[]{
   (()=>new(HttpStatusCode.Unauthorized),"MANAGED_BOOTSTRAP_EXPIRED",true),
   (()=>new(HttpStatusCode.Forbidden),"MANAGED_ACCESS_REJECTED",false),
   (()=>new(HttpStatusCode.TooManyRequests),"MANAGED_RATE_LIMITED",false),
   (()=>new(HttpStatusCode.ServiceUnavailable),"MANAGED_SERVER_REJECTED",false),
   (()=>new(HttpStatusCode.Found){Headers={Location=new Uri("https://example.com/redirect")}},"MANAGED_SERVER_REJECTED",false),
   (()=>throw new HttpRequestException("PRIVATE_TRANSPORT_DETAIL"),"MANAGED_NETWORK_FAILED",false),
   (()=>new(HttpStatusCode.OK){Content=new StringContent("{")},"MANAGED_RESPONSE_INVALID",false),
   (()=>new(HttpStatusCode.OK){Content=new StringContent(new string('x',65537))},"MANAGED_RESPONSE_INVALID",false),
   (()=>Status("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),"MANAGED_RESPONSE_INVALID",false),
   (()=>new(HttpStatusCode.OK){Content=new StringContent("{\"device_id\":\""+bootstrap.DeviceId+"\",\"state\":\"active\",\"revision\":1,\"ready\":true,\"ready\":true,\"retry_after_seconds\":0}")},"MANAGED_RESPONSE_INVALID",false),
   (()=>Status(bootstrap.DeviceId,"active",false),"MANAGED_RESPONSE_INVALID",false),
   (()=>Status(bootstrap.DeviceId,"pending",false),"MANAGED_ACTIVATION_PENDING",true),
   (()=>Status(bootstrap.DeviceId,"error",false),"MANAGED_ACTIVATION_PENDING",true)
  };
  foreach(var test in cases){
   var(c,p)=Fixture(test.Expired);var calls=0;
   using var h=new Fake(r=>{calls++;if(r.Method!=HttpMethod.Get)throw new Exception("Refusal retried nonce POST");return Task.FromResult(test.Reply());});
   await Expect(test.Code,()=>ManagedClient.Claim(c,p.Id,true,h,verify));
   if(calls!=1)throw new Exception("Refusal HTTP count wrong");Unchanged(c,p);
  }
  {
   var(c,p)=Fixture();var gets=0;var posts=0;
   using var h=new Fake(async r=>{
    if(r.Method==HttpMethod.Get){gets++;return new(HttpStatusCode.Unauthorized);}
    posts++;var body=await r.Content!.ReadAsStringAsync();
    if(r.Headers.Authorization?.Parameter!=p.Managed!.ClaimNonce||!body.Contains(ManagedCredential.Digest(p.Managed.DeviceToken))||body.Contains(p.Managed.DeviceToken))throw new Exception("Fresh claim credential changed");
    return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{device_id=bootstrap.DeviceId,subscription_id="synthetic",subscription_version=1,revision=1,state="active",ready=true}))};
   });
   await ManagedClient.Claim(c,p.Id,true,h,verify);var saved=c.Read();var after=saved.Profiles.Single();
   if(gets!=1||posts!=1||saved.ActiveId!=p.Id||after!=p with{Managed=p.Managed! with{Registered=true,ClaimNonce=null}})throw new Exception("Fresh claim altered identity/selection or repeated request");
  }
  // Same authenticated runtime is required before HTTP, after GET, before POST,
  // and after the claim response. In-flight server commits remain recoverable.
  for(var checkpoint=1;checkpoint<=4;checkpoint++){
   var(c,p)=Fixture();var checks=0;var postsSeen=0;
   using var h=new Fake(r=>{if(r.Method==HttpMethod.Get)return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));postsSeen++;return Task.FromResult(Status(bootstrap.DeviceId));});
   Task Guard(){if(++checks==checkpoint)throw new IOException("MANAGED_SESSION_CHANGED");return Task.CompletedTask;}
   await Expect("MANAGED_SESSION_CHANGED",()=>ManagedClient.Claim(c,p.Id,true,h,verify,Guard));
   if(postsSeen!=(checkpoint==4?1:0))throw new Exception("Stale session sent nonce POST");Unchanged(c,p);
  }
  {
   var(c,p)=Fixture();using var h=new Fake(r=>{c.Delete(p.Id);return Task.FromResult(Status(bootstrap.DeviceId));});
   await Expect("MANAGED_STORAGE_CHANGED",()=>ManagedClient.Claim(c,p.Id,true,h,verify));
   if(c.Read().Profiles.Count!=0)throw new Exception("Late claim resurrected deleted profile");
  }
  {
   var c=new ProfileCatalog(Path.Combine(root,"claim-expiry-during-status"));
   var p=c.AddBootstrap(bootstrap with{ExpiresAt=DateTimeOffset.UtcNow.AddSeconds(2).ToString("O")},true);
   using var h=new Fake(async r=>{if(r.Method!=HttpMethod.Get)throw new Exception("Expired in-flight request sent POST");await Task.Delay(2100);return new(HttpStatusCode.Unauthorized);});
   await Expect("MANAGED_BOOTSTRAP_EXPIRED",()=>ManagedClient.Claim(c,p.Id,true,h,verify));Unchanged(c,p);
  }
  if(engine){
   var c=new ProfileCatalog(Path.Combine(root,"claim-wrong-key"));
   var p=c.AddBootstrap(bootstrap with{PublicKey=Convert.ToBase64String(Enumerable.Repeat((byte)77,32).ToArray())},true);var calls=0;
   using var h=new Fake(r=>{calls++;return Task.FromResult(Status(bootstrap.DeviceId));});
   await Expect("MANAGED_BOOTSTRAP_INVALID",()=>ManagedClient.Claim(c,p.Id,true,h,verify));
   if(calls!=0)throw new Exception("Wrong local key reached HTTP");Unchanged(c,p);
  }
  Console.WriteLine("PASS: claim refuses expiry/forbidden/rate-limit/redirect/network/invalid/pending, stale runtime and catalog; no nonce retry or private data changes");
 }
 internal static HttpResponseMessage Status(string device,string state="active",bool ready=true)=>new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{device_id=device,state,revision=1,ready,retry_after_seconds=ready?0:5}))};
 private sealed class Fake(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request);}
}
