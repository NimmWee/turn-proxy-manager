using FreeTurn.Windows;
using System.IO;
using System.Net;
using System.Net.Http;

internal static class TransportChecks
{
 internal static async Task Flow(ProfileCatalog catalog,SavedProfile p)
 {
  catalog.SetAutoTransport(true);var saved=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));if(!saved.AutoTransport)throw new Exception("Backup lost auto transport");
  catalog.Merge(saved with{AutoTransport=false});if(!catalog.Read().AutoTransport)throw new Exception("Merge disabled transport preference");
  catalog.Merge(saved with{AutoTransport=false},true);if(catalog.Read().AutoTransport)throw new Exception("Explicit restore lost transport preference");
  var now=TimeSpan.Zero;var id=ProfileIdentity.Of(p.Share);var calls=0;var messages=new List<string>();
  var r=new ServiceReply(true,null,"handshake",true,"connected",true,10,20,null,false,["runtime-profile-identity-v1","transport-path-v1"],Kind:"wireguard",TunnelActive:true,ConfiguredProfileIdentity:id,RuntimeProfileIdentity:id,ConnectionId:123,LastAttemptId:123,AutoPaths:true,RuntimePath:"direct");
  var live=r with{State="connected"};var oldLease=new RuntimeLease(p.Id,id,123);
  using(var handler=new Fake(_=>{live=live with{PathEpoch=1,RuntimePath="relay"};return new(HttpStatusCode.Forbidden);})){try{
   await ManagedSubscription.Refresh(catalog,p.Id,true,handler,_=>Task.CompletedTask,ensureCurrent:()=>oldLease.Matches(live)?Task.CompletedTask:throw new OperationCanceledException());
  }catch(IOException){}if(catalog.Read().Profiles.Single().Managed!.AccessDenied)throw new Exception("Old-path HTTP denial changed profile");}
  using(var manager=new TransportManager(catalog,()=>Task.FromResult(r),(lease,path)=>{calls++;if(lease.PathEpoch!=0||path!="relay")throw new Exception("Wrong transport request");return Task.FromResult(r with{State="switching",PathPending=true});},messages.Add,()=>{},()=>{},()=>now)){
   manager.Begin(p,r);for(var n=1;n<=30;n++){now=TimeSpan.FromSeconds(n);manager.Observe(r,true);}await manager.Running;
   if(calls!=1||!manager.HasIntent)throw new Exception("Transport manager did not send one request");
   now+=TimeSpan.FromSeconds(1);manager.Observe(r with{PathPending=true},true);if(calls!=1)throw new Exception("Pending request repeated");
   manager.Cancel();now+=TimeSpan.FromMinutes(2);manager.Observe(r,true);if(calls!=1||manager.HasIntent)throw new Exception("Cancelled manager resumed");
  }
  now=TimeSpan.Zero;var delayed=new TaskCompletionSource<ServiceReply>();
  using(var manager=new TransportManager(catalog,()=>delayed.Task,(_,_)=>throw new Exception("Cancelled transport wrote IPC"),messages.Add,()=>{},()=>{},()=>now)){
   manager.Begin(p,r);for(var n=1;n<=30;n++){now=TimeSpan.FromSeconds(n);manager.Observe(r,true);}manager.Cancel();delayed.SetResult(r);await manager.Running;
  }
  now=TimeSpan.Zero;
  using(var manager=new TransportManager(catalog,()=>Task.FromResult(r with{State="connected"}),(_,_)=>throw new Exception("Recovered transport changed"),messages.Add,()=>{},()=>{},()=>now)){
   manager.Begin(p,r);for(var n=1;n<=30;n++){now=TimeSpan.FromSeconds(n);manager.Observe(r,true);}await manager.Running;
   if(!manager.HasIntent)throw new Exception("Recovered transport lost intent");
  }
  var withPath=p with{Managed=p.Managed! with{KnownGood=new(p.Share,null,DateTimeOffset.UtcNow.ToString("O"),"relay")}};
  if(CatalogBackup.Decode(CatalogBackup.Encode(new ProfileSnapshot(1,null,[withPath]))).Profiles.Single().Managed!.KnownGood!.Path!="relay")throw new Exception("Backup lost proven path");
  Console.WriteLine("PASS: synthetic transport IPC single-flight/cancel/healthy recheck and DPAPI/backup preferences/proven path; no live network");
 }
 private sealed class Fake(Func<HttpRequestMessage,HttpResponseMessage> send):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(send(request));}
 internal static void Policy()
 {
  var id=new string('a',64);var lease=new RuntimeLease(Guid.NewGuid(),id,123);
  var r=new ServiceReply(true,null,"handshake",true,"connected",true,10,20,null,false,["runtime-profile-identity-v1","transport-path-v1"],Kind:"wireguard",TunnelActive:true,ConfiguredProfileIdentity:id,RuntimeProfileIdentity:id,ConnectionId:123,LastAttemptId:123,AutoPaths:true,RuntimePath:"direct");
  var policy=new TransportPolicy(lease,"direct",TimeSpan.Zero);
  for(var n=1;n<30;n++)if(policy.Observe(r,TimeSpan.FromSeconds(n))!=TransportDecision.Wait)throw new Exception("Direct failed too early");
  if(policy.Observe(r,TimeSpan.FromSeconds(30))!=TransportDecision.Switch)throw new Exception("Direct timeout did not request relay");
  policy.Requested();if(policy.Observe(r with{PathPending=true},TimeSpan.FromSeconds(31))!=TransportDecision.Wait)throw new Exception("Pending switch repeated");
  r=r with{PathEpoch=1,RuntimePath="relay"};if(policy.Observe(r,TimeSpan.FromSeconds(32))!=TransportDecision.Wait)throw new Exception("Own epoch ack refused");
  for(var n=33;n<=250;n++)if(policy.Observe(r with{State="captcha",Captcha="http://127.0.0.1:8765/"},TimeSpan.FromSeconds(n))!=TransportDecision.Wait)throw new Exception("Captcha switched path");
  for(var n=251;n<310;n++)if(policy.Observe(r,TimeSpan.FromSeconds(n))!=TransportDecision.Wait)throw new Exception("Relay failed too early");
  if(policy.Observe(r,TimeSpan.FromSeconds(310))!=TransportDecision.Switch)throw new Exception("Relay timeout did not request direct");
  policy.Requested();r=r with{PathEpoch=2,RuntimePath="direct"};policy.Observe(r,TimeSpan.FromSeconds(311));
  for(var n=312;n<341;n++)if(policy.Observe(r,TimeSpan.FromSeconds(n))!=TransportDecision.Wait)throw new Exception("Final path failed too early");
  if(policy.Observe(r,TimeSpan.FromSeconds(341))!=TransportDecision.Exhausted)throw new Exception("Budget not exhausted");
  foreach(var bad in new[]{r with{LastAttemptId=124},r with{AutoPaths=false},r with{PathEpoch=1},r with{DiagnosticError="VK_AUTH_FAILED"}})
   if(new TransportPolicy(lease,"direct",TimeSpan.Zero).Observe(bad,TimeSpan.FromSeconds(1))!=TransportDecision.Cancel)throw new Exception("Foreign/auth path eligible");
  var healthy=r with{PathEpoch=0,RuntimePath="direct",State="connected"};var stable=new TransportPolicy(lease,"direct",TimeSpan.Zero);
  for(var n=1;n<500;n++)if(stable.Observe(healthy,TimeSpan.FromSeconds(n))!=TransportDecision.Wait)throw new Exception("Healthy transport flapped");
  if(new TransportPolicy(lease,"direct",TimeSpan.Zero).Observe(healthy with{State="handshake"},TimeSpan.FromHours(1))!=TransportDecision.Wait)throw new Exception("Sleep consumed budget");
  if(lease.Matches(healthy with{PathEpoch=1}))throw new Exception("Lease accepted old path proof");
  var proof=new ManagedProofWindow();proof.Observe(healthy,TimeSpan.Zero);if(proof.Observe(healthy with{PathEpoch=1},TimeSpan.FromSeconds(5)))throw new Exception("Proof window mixed paths");
  Console.WriteLine("PASS: synthetic Direct/Relay timers/budget/CAPTCHA/sleep/auth/healthy hysteresis/path proof isolation; live transport NOT RUN");
 }
}
