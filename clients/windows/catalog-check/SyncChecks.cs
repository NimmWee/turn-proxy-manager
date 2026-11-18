using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using FreeTurn.Windows;

internal static class SyncChecks
{
 internal static async Task Run(ProfileCatalog catalog,Guid id)
 {
  if(ProfileIdentity.Of(" freeturn://SYNTHETIC \r\n")!="67ba0bd705841a5fb85085e6e8d9837a17aebcc300a6c86d6986743bf68bb1a9")throw new Exception("C#/Go identity contract mismatch");
  var p=catalog.Read().Profiles.Single(x=>x.Id==id);var digest=ProfileIdentity.Of(p.Share);
  var reply=new ServiceReply(true,null,"connected",true,"connected",true,1,1,null,false,["runtime-profile-identity-v1"],Kind:"wireguard",TunnelActive:true,RuntimeProfileIdentity:digest,ConnectionId:123);
  var lease=RuntimeLease.Find(catalog.Read() with{ActiveId=null},reply)??throw new Exception("Selected row incorrectly required for runtime match");
  foreach(var bad in new[]{reply with{ConnectionId=0},reply with{Capabilities=[]},reply with{RuntimeProfileIdentity=new string('b',64)},reply with{State="handshake"},reply with{TunnelActive=false},reply with{Kind="tcp-forwarder"}})
   if(RuntimeLease.Find(catalog.Read(),bad)is not null)throw new Exception("Unsafe runtime eligible for sync");
  if(lease.Matches(reply with{ConnectionId=124}))throw new Exception("Reconnect retained old lease");
  var before=catalog.Read();
  foreach(var code in new[]{HttpStatusCode.OK,HttpStatusCode.Forbidden,HttpStatusCode.NotModified}){
   using var cancel=new CancellationTokenSource();
   using var handler=new Fake(_=>{cancel.Cancel();return new(code){Content=new StringContent("{}")};});
   try{await ManagedSubscription.Refresh(catalog,id,true,handler,_=>Task.CompletedTask,(_,raw,tag,_)=>Task.FromResult(new ManagedConfig(raw,p.Share,tag,1)),cancel.Token);throw new Exception("Canceled response accepted");}catch(OperationCanceledException){}
   if(catalog.Read().Profiles.Single()!=p)throw new Exception("Canceled HTTP wrote managed metadata/denial");
  }
  var valid=true;
  using(var handler=new Fake(_=>{valid=false;return new(HttpStatusCode.Forbidden);})){try{
   await ManagedSubscription.Refresh(catalog,id,true,handler,_=>Task.CompletedTask,ensureCurrent:()=>valid?Task.CompletedTask:throw new OperationCanceledException());
  }catch(IOException){}if(catalog.Read().Profiles.Single()!=p)throw new Exception("Old-session denial persisted");}
  using(var cancel=new CancellationTokenSource())
  using(var handler=new Fake(_=>{var r=new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("{}")};r.Headers.ETag=new EntityTagHeaderValue("\""+new string('a',64)+"\"");return r;})){
   try{await ManagedSubscription.Refresh(catalog,id,true,handler,_=>Task.CompletedTask,async(_,raw,tag,_)=>{await Task.Yield();cancel.Cancel();return new(raw,p.Share,tag,1);},cancel.Token);throw new Exception("Canceled builder output accepted");}catch(OperationCanceledException){}
   if(catalog.Read().Profiles.Single()!=p)throw new Exception("Cancellation after validation wrote candidate");
  }
  using(var handler=new Fake(_=>{var r=new HttpResponseMessage(HttpStatusCode.TooManyRequests);r.Headers.RetryAfter=new RetryConditionHeaderValue(TimeSpan.FromDays(4));return r;})){
   try{await ManagedSubscription.Refresh(catalog,id,true,handler,_=>Task.CompletedTask);throw new Exception("429 ignored");}catch(ManagedRetryException e){if(e.Delay!=TimeSpan.FromDays(1))throw new Exception("Retry-After unbounded");}
  }
  catalog.SetManagedAutoSync(true);
  var backup=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));if(!backup.ManagedAutoSync)throw new Exception("Backup lost sync preference");
  catalog.Merge(backup with{ManagedAutoSync=false});if(!catalog.Read().ManagedAutoSync)throw new Exception("Merge silently disabled existing preference");
  catalog.Merge(backup with{ManagedAutoSync=false},true);if(catalog.Read().ManagedAutoSync)throw new Exception("Explicit preference restore ignored sync setting");
  catalog.Merge(backup,true);
  var now=DateTimeOffset.UtcNow;var schedule=new ManagedSyncSchedule(now);schedule.Failed(now);if(schedule.Next!=now.AddSeconds(60))throw new Exception("First backoff wrong");
  for(var n=0;n<20;n++)schedule.Failed(now);if(schedule.Next!=now.AddMinutes(15))throw new Exception("Backoff not bounded");
  schedule.Succeeded(now,false);if(schedule.Next!=now.AddMinutes(30))throw new Exception("Normal interval wrong");
  var calls=0;var reports=new List<string>();var running=new TaskCompletionSource<ManagedRefresh>();
  using(var sync=new ManagedSync(catalog,()=>Task.FromResult(reply),_=>throw new Exception("Unexpected stop"),reports.Add,()=>now,async(_,token,ensure)=>{calls++;await ensure();return await running.Task.WaitAsync(token);})){
   sync.Observe(reply,true);if(calls!=0)throw new Exception("Sync started immediately on load");
   now=now.AddSeconds(15);sync.Observe(reply,true);sync.Observe(reply,true);if(calls!=1)throw new Exception("Sync not single-flight");
   sync.Observe(reply with{ConnectionId=124},true);await sync.Running;if(reports.Count!=0)throw new Exception("Cancellation produced failure spam");
   sync.Observe(reply,true);if(calls!=1)throw new Exception("Canceled job retried without backoff");
  }
  now=now.AddHours(1);RuntimeLease? stopped=null;
  using(var sync=new ManagedSync(catalog,()=>Task.FromResult(reply),x=>{stopped=x;return Task.FromResult(reply with{Ok=false,Error="CONNECTION_CHANGED"});},reports.Add,()=>now,(_,_,_)=>throw new IOException("MANAGED_ACCESS_REJECTED"))){
   sync.Observe(reply,true);now=now.AddSeconds(15);sync.Observe(reply,true);await sync.Running;
   if(stopped!=lease||reports.Last().Contains("соединение отключено"))throw new Exception("Revocation stopped wrong lease or claimed unconfirmed stop");
  }
  catalog.SetManagedAutoSync(false);
  using(var sync=new ManagedSync(catalog,()=>throw new Exception("Disabled sync queried service"),_=>throw new Exception("Disabled sync stopped service"),reports.Add,()=>now,(_,_,_)=>throw new Exception("Disabled sync used HTTP"))){sync.Observe(reply,true);now=now.AddHours(2);sync.Observe(reply,true);await sync.Running;}
  Console.WriteLine("PASS: synthetic runtime identity/session gate, canceled/stale HTTP no writes, bounded sync/single-flight/backoff/Retry-After, conditional revoke target and backup preference; live VPN NOT RUN");
 }
 private sealed class Fake(Func<HttpRequestMessage,HttpResponseMessage> send):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(send(request));}
}
