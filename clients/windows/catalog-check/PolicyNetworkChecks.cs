using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using FreeTurn.Windows;
internal static class PolicyNetworkChecks{
 sealed class Fake(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler{protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>send(request);}
 internal static async Task Run(){
  var id=new string('a',64);var receipt=new ServiceReply(true,null,"starting",true,null,false,0,0,null,false,ConfiguredProfileIdentity:id,LastAttemptId:12);
  var r=receipt with{State="connected",RuntimeProfileIdentity=id,ConnectionId=12,TunnelActive=true,PathEpoch=1};var lease=new RuntimeLease(Guid.NewGuid(),id,12);
  var p=new NetworkRecoveryPolicy();p.Begin(lease,new string('b',64));
  if(p.Request(r,new(true,new string('b',64))) is not null)throw new Exception("Own TUN event triggered network restart");
  if(p.Request(r,new(false,"")) is not null||p.Request(r with{Captcha="synthetic"},new(true,new string('c',64))) is not null)throw new Exception("No-uplink/CAPTCHA restart");
  p.Suspend();if(p.Request(r,new(true,new string('c',64))) is not null)throw new Exception("Restart during suspend");p.Resume();
  if(p.Request(r,new(true,new string('b',64)))?.PathEpoch!=1)throw new Exception("Resume/epoch not preserved");
  p.Requested();p.Accepted(receipt with{LastAttemptId=13},new string('c',64));var newer=r with{LastAttemptId=13,ConnectionId=13,PathEpoch=0};
  if(p.Request(newer,new(true,new string('c',64))) is not null)throw new Exception("Reconnect loop after accepted handover");
  for(int n=1;n<5;n++)p.Requested();if(p.Request(newer,new(true,new string('d',64))) is not null)throw new Exception("Retry budget exceeded");
  p.Stop();if(p.Request(newer,new(true,new string('d',64))) is not null)throw new Exception("Manual stop restored intent");
  p.Begin(lease,new string('b',64));if(p.Request(r with{LastAttemptId=99},new(true,new string('c',64))) is not null||p.Lease is not null)throw new Exception("Foreign attempt accepted");
  var root=Path.Combine(Path.GetTempPath(),"ftm-policy-network-"+Guid.NewGuid().ToString("N"));
  try{
   var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));
   var share="freeturn://"+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{v=1,name="Synthetic",provider="vk",peer="8.8.8.8:5000",key=new string('a',64),cid=new string('b',32),vk="https://vk.com/call/join/SYNTHETIC"})).TrimEnd('=').Replace('+','-').Replace('/','_');
   var m=new ManagedCredential("11111111-2222-3333-4444-555555555555",key,"https://8.8.8.8","10.77.43.1",null,DateTimeOffset.UtcNow.AddHours(1).ToString("O"),"ftmd1_"+new string('A',43),true);
   var saved=new SavedProfile(Guid.NewGuid(),"Synthetic",share,Managed:m);var catalog=new ProfileCatalog(root);catalog.Merge(new(1,saved.Id,[saved]));saved=catalog.Read().Profiles.Single();
   var body=new RoutingPolicyBody(new(),[new("example.com","direct",true)],["77.88.8.8"]);var bundle=new RoutingPublication(1,1,body,null);
   catalog.StageRouting(saved,bundle);var current=catalog.Read().Profiles.Single();var rejected=false;
   try{catalog.StageRouting(current,bundle with{Policy=body with{Rules=[new("other.example.com","direct",true)]}});}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Same-revision substitution accepted");
   rejected=false;try{catalog.StageRouting(current,bundle with{Revision=0});}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Policy downgrade accepted");
   rejected=false;try{catalog.StageRouting(saved,bundle with{Revision=2});}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Stale policy write accepted");
   catalog.StageRouting(current,bundle with{Revision=2});var latest=catalog.Read().Profiles.Single();
   if(latest.Routing?.Previous?.Revision!=1||latest.Share!=share||latest.Managed!.DeviceToken!=m.DeviceToken||latest.Routing.Current.Settings(new(){Enabled=true,AppRules=[new(@"C:\Apps\Browser.exe","block")]}).AppRules?.Count!=1)throw new Exception("Policy update lost history/keys/app settings");
   var backup=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));if(backup.Profiles.Single().Routing?.Current.Revision!=2)throw new Exception("Routing backup lost revision fence");
   // Exercise bearer/capability/internal origin and actual child validator with a
   // fake HTTPS response. No socket, service or network configuration is used.
   using var handler=new Fake(request=>{
    if(request.RequestUri!.AbsoluteUri!="https://8.8.8.8/api/client/v1/routing"||request.Headers.Authorization?.Parameter!=m.DeviceToken||!request.Headers.Contains("X-FreeTurn-Capability"))throw new Exception("Routing delivery authority lost");
    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(bundle with{Revision=3}))});
   });
   await ManagedRouting.Refresh(catalog,saved.Id,syntheticHandler:handler,verify:_=>Task.CompletedTask);
   if(catalog.Read().Profiles.Single().Routing?.Current.Revision!=3)throw new Exception("Delivered routing not staged");
   using var oldServer=new Fake(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
   if(await ManagedRouting.Refresh(catalog,saved.Id,syntheticHandler:oldServer,verify:_=>Task.CompletedTask))throw new Exception("Old server changed policy");
   var before=File.ReadAllBytes(Path.Combine(root,"profiles.dpapi"));using var tampered=new Fake(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(bundle with{Revision=4,Catalog=new(new string('0',64),"invalid")}))}));
   rejected=false;try{await ManagedRouting.Refresh(catalog,saved.Id,syntheticHandler:tampered,verify:_=>Task.CompletedTask);}catch(IOException){rejected=true;}if(!rejected||!before.SequenceEqual(File.ReadAllBytes(Path.Combine(root,"profiles.dpapi"))))throw new Exception("Tampered catalogue changed DPAPI state");
  }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
  Console.WriteLine("PASS: policy replay/stale/tamper refusal, DPAPI key/history/backup, fake HTTP→actual engine staging; network/sleep/attempt/budget/manual-stop decisions. WFP/network/VPN E2E NOT RUN");
 }
}
