using System.IO;
using FreeTurn.Windows;

internal static class LkgChecks
{
 internal static async Task Flow(ProfileCatalog catalog,Guid id,bool engine)
 {
  var p=catalog.Read().Profiles.Single(x=>x.Id==id);var identity=ProfileIdentity.Of(p.Share);
  var now=TimeSpan.Zero;var messages=new List<string>();var starts=0;
  var current=new ServiceReply(true,null,"connected",true,"connected",true,10,20,null,false,["runtime-profile-identity-v1","managed-recovery-v1"],Kind:"wireguard",TunnelActive:true,RuntimeProfileIdentity:identity,ConnectionId:123,ConfiguredProfileIdentity:identity,LastAttemptId:123);
  Func<SavedProfile,string,ManagedConfig?,Task>? verifier=engine?null:(_,_,_)=>Task.CompletedTask;
  using(var monitor=new ManagedRecovery(catalog,()=>Task.FromResult(current),(_,_)=>throw new Exception("Promotion called recovery"),messages.Add,()=>starts++,()=>now,verifier)){
   monitor.Observe(current,true);now=TimeSpan.FromSeconds(5);monitor.Observe(current,true);await monitor.Running;
   if(catalog.Read().Profiles.Single().Managed!.KnownGood?.Share!=p.Share||starts!=0)throw new Exception("Runtime proof did not promote without recovery");
  }
  var good=catalog.Read().Profiles.Single();var candidate=new ManagedConfig("{}",new ShareDocument(p.Share).Build(new ShareDocument(p.Share).Values with{Name="Synthetic failed update"}),"\""+new string('c',64)+"\"",4);
  catalog.StageManaged(good,candidate);catalog.ApplyManaged(catalog.Read().Profiles.Single(),candidate);var trial=catalog.Read().Profiles.Single();
  var failed=current with{State="error",Handshake=false,ConfiguredProfileIdentity=ProfileIdentity.Of(trial.Share),RuntimeProfileIdentity=ProfileIdentity.Of(trial.Share),ConnectionId=124,LastAttemptId=124};
  var calls=0;
  using(var monitor=new ManagedRecovery(catalog,()=>Task.FromResult(failed),async(lease,share)=>{await Task.Yield();calls++;if(lease.Attempt!=124||share!=p.Share||catalog.Read().Profiles.Single().Share!=share)throw new Exception("IPC before durable return or wrong target");return current with{State="starting",LastAttemptId=125};},messages.Add,()=>starts++,()=>now,verifier)){
   monitor.Begin(trial,failed with{Ok=true});monitor.Observe(failed,true);await monitor.Running;monitor.Observe(failed,true);await monitor.Running;
   if(calls!=1||starts!=1||catalog.Read().Profiles.Single().Managed!.SeenRevision!=4)throw new Exception("Recovery looped or lost revision");
  }
  // A cancelled async validation must not overwrite the catalog or send IPC.
  var restored=catalog.Read().Profiles.Single();catalog.ApplyManaged(restored,candidate);trial=catalog.Read().Profiles.Single();
  var validation=new TaskCompletionSource();
  using(var monitor=new ManagedRecovery(catalog,()=>Task.FromResult(failed),(_,_)=>throw new Exception("Canceled recovery used IPC"),messages.Add,()=>{},()=>now,(_,_,_)=>validation.Task)){
   monitor.Begin(trial,failed);monitor.Observe(failed,true);monitor.Cancel();validation.SetResult();await monitor.Running;
   if(catalog.Read().Profiles.Single()!=trial)throw new Exception("Canceled recovery wrote catalog");
  }
  using(var monitor=new ManagedRecovery(catalog,()=>Task.FromResult(current with{LastAttemptId=999}),(_,_)=>throw new Exception("Foreign runtime recovered"),messages.Add,()=>{},()=>now,(_,_,_)=>Task.CompletedTask)){
   monitor.Begin(trial,failed);monitor.Observe(failed,true);await monitor.Running;if(catalog.Read().Profiles.Single()!=trial)throw new Exception("Foreign runtime changed catalog");
  }
  var blockedValidation=new TaskCompletionSource();
  using(var monitor=new ManagedRecovery(catalog,()=>Task.FromResult(failed),(_,_)=>throw new Exception("Revoked device recovered"),messages.Add,()=>{},()=>now,(_,_,_)=>blockedValidation.Task)){
   monitor.Begin(trial,failed);monitor.Observe(failed,true);catalog.DenyManaged(trial);blockedValidation.SetResult();await monitor.Running;
   var denied=catalog.Read().Profiles.Single();if(denied.Share!=trial.Share||!denied.Managed!.AccessDenied||denied.Managed.DeviceToken!=p.Managed!.DeviceToken)throw new Exception("Revocation during validation lost identity/keys");
  }
  Console.WriteLine(engine?"PASS: synthetic runtime promotion/recovery/cancellation/foreign attempt with actual Go LKG key verification; real VPN NOT RUN":"PASS: synthetic runtime promotion/one recovery/durable-before-IPC/cancellation/foreign-attempt guards; real VPN NOT RUN");
 }
 internal static void Policy(ServiceReply proof,Guid id)
 {
  var lease=new RuntimeLease(id,proof.RuntimeProfileIdentity!,proof.ConnectionId);
  var window=new ManagedProofWindow();
  if(window.Observe(proof,TimeSpan.Zero)||window.Observe(proof,TimeSpan.FromSeconds(1))||!window.Observe(proof,TimeSpan.FromSeconds(5)))throw new Exception("LKG proof stability window wrong");
  window.Reset();window.Observe(proof,TimeSpan.Zero);if(window.Observe(proof with{ConnectionId=124},TimeSpan.FromSeconds(5)))throw new Exception("Mixed sessions formed LKG proof");
  var waiting=proof with{State="tunnel_unverified",Handshake=false};
  var trial=new ManagedTrial(lease,TimeSpan.Zero);
  for(var n=1;n<=110;n++)if(trial.Observe(waiting,TimeSpan.FromSeconds(n))!=TrialDecision.Wait)throw new Exception("Trial timed out too early");
  for(var n=111;n<=500;n++)if(trial.Observe(waiting with{State="captcha",Captcha="http://127.0.0.1:1234/"},TimeSpan.FromSeconds(n))!=TrialDecision.Wait)throw new Exception("Captcha caused rollback");
  if(trial.Observe(waiting,TimeSpan.FromSeconds(505))!=TrialDecision.Wait||trial.Observe(waiting,TimeSpan.FromSeconds(510))!=TrialDecision.Return)throw new Exception("Captcha pause lost remaining trial time");
  foreach(var bad in new[]{waiting with{LastAttemptId=124},waiting with{LastAttemptId=0},waiting with{ConfiguredProfileIdentity=new string('b',64)},waiting with{DiagnosticError="VK_AUTH_FAILED",State="error"}})
   if(new ManagedTrial(lease,TimeSpan.Zero).Observe(bad,TimeSpan.FromSeconds(1))!=TrialDecision.Cancel)throw new Exception("Foreign/cancelled/auth trial could recover");
  if(new ManagedTrial(lease,TimeSpan.Zero).Observe(waiting,TimeSpan.FromHours(1))!=TrialDecision.Wait)throw new Exception("Sleep counted as failed trial");
 }
 internal static void Storage(ProfileCatalog catalog,Guid id)
 {
  var p=catalog.Read().Profiles.Single(x=>x.Id==id);var hash=ProfileIdentity.Of(p.Share);
  var proof=new ServiceReply(true,null,"connected",true,"connected",true,100,200,null,false,["runtime-profile-identity-v1","managed-recovery-v1"],Kind:"wireguard",TunnelActive:true,RuntimeProfileIdentity:hash,ConnectionId:123,ConfiguredProfileIdentity:hash,LastAttemptId:123);
  Policy(proof,id);
  foreach(var bad in new[]{proof with{Handshake=false},proof with{Rx=0},proof with{State="handshake"},proof with{RuntimeProfileIdentity=new string('b',64)}}){
   var rejected=false;try{catalog.MarkManagedGood(p,bad,DateTimeOffset.UtcNow);}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Unproven config recorded as good");
  }
  catalog.MarkManagedGood(p,proof,DateTimeOffset.UtcNow);
  var good=catalog.Read().Profiles.Single(x=>x.Id==id);
  if(good.Managed!.KnownGood?.Share!=p.Share||good.Managed.DeviceToken!=p.Managed!.DeviceToken)throw new Exception("LKG lost key/token");
  var backup=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));if(backup.Profiles.Single().Managed!.KnownGood!=good.Managed.KnownGood)throw new Exception("Backup lost LKG");
  var candidate=new ManagedConfig("{}",new ShareDocument(p.Share).Build(new ShareDocument(p.Share).Values with{Name="Synthetic trial"}),"\""+new string('c',64)+"\"",4);
  catalog.StageManaged(good,candidate);var staged=catalog.Read().Profiles.Single();catalog.ApplyManaged(staged,candidate);var trial=catalog.Read().Profiles.Single();
  catalog.ReturnManagedGood(trial);var returned=catalog.Read().Profiles.Single();
  if(returned.Share!=p.Share||returned.Managed!.KnownGood!=good.Managed.KnownGood||returned.Managed.SeenRevision!=4||returned.Managed.DeviceToken!=p.Managed.DeviceToken||returned.Managed.PreviousShare!=trial.Share||returned.Managed.Pending!=candidate)throw new Exception("Return lost candidate/revision/token/good share");
  catalog.DenyManaged(returned);var denied=catalog.Read().Profiles.Single();var blocked=false;try{catalog.ReturnManagedGood(denied);}catch(IOException){blocked=true;}if(!blocked)throw new Exception("Revoked profile returned to old config");
  Console.WriteLine("PASS: synthetic LKG proof/refusal/DPAPI/backup and return preserve candidate/key/token/revision; actual VPN proof NOT RUN");
 }
}
