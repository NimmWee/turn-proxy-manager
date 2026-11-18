using System.Diagnostics;
using System.IO;

namespace FreeTurn.Windows;

// UI-dispatcher owner. Recovery intent exists only after this window's accepted
// manual Connect; neither backup nor application startup can restore it.
internal sealed class ManagedRecovery(
 ProfileCatalog catalog,Func<Task<ServiceReply>> status,Func<RuntimeLease,string,Task<ServiceReply>> recover,
 Action<string> report,Action recovering,Func<TimeSpan>? clock=null,
 Func<SavedProfile,string,ManagedConfig?,Task>? verify=null):IDisposable
{
 private readonly long origin=Stopwatch.GetTimestamp();
 private readonly ManagedProofWindow proof=new();
 private (string?,ulong,ulong) observed;
 private SavedProfile? candidate,trialProfile;
 private ManagedTrial? trial;
 private long generation;
 private bool disposed,returning;
 private TimeSpan retryProof;
 private TimeSpan Now=>clock?.Invoke()??Stopwatch.GetElapsedTime(origin);
 internal bool Busy=>returning;
 internal bool HasTrial=>trial is not null;
 internal Task Running {get;private set;}=Task.CompletedTask;
 internal void Cancel(){generation++;trial=null;trialProfile=null;candidate=null;observed=default;proof.Reset();}
 internal void Begin(SavedProfile? profile,ServiceReply receipt)
 {
  Cancel();
  if(disposed||profile?.Managed is not{Registered:true,AccessDenied:false,KnownGood:{} good,Applied:not null}||
   good.Share==profile.Share||!receipt.Ok||receipt.ConfiguredProfileIdentity!=ProfileIdentity.Of(profile.Share)||receipt.LastAttemptId==0)return;
  trialProfile=profile;trial=new(new(profile.Id,receipt.ConfiguredProfileIdentity!,receipt.LastAttemptId,receipt.PathEpoch),Now);
 }
 internal void Observe(ServiceReply r,bool allowed,bool pathsPending=false,bool pathsExhausted=false)
 {
  if(disposed)return;
  if(!allowed){Cancel();return;}
  if(!Running.IsCompleted)return;
  if(trial is{} active){
   var decision=active.Observe(r,Now,pathsPending,pathsExhausted);
   if(decision==TrialDecision.Cancel){trial=null;trialProfile=null;}
   else if(decision==TrialDecision.Return){var expected=trialProfile!;trial=null;trialProfile=null;returning=true;Running=Return(expected,active.Lease,generation);return;}
  }
  if(!ManagedProofWindow.Proven(r)){proof.Reset();return;}
  if(Now<retryProof)return;
  var key=(r.RuntimeProfileIdentity,r.ConnectionId,r.PathEpoch);
  if(key!=observed){
   observed=key;proof.Reset();candidate=null;
   try{var data=catalog.Read();var lease=RuntimeLease.Find(data,r);if(lease is not null)candidate=data.Profiles.Single(p=>p.Id==lease.ProfileId);}catch{return;}
   if(candidate?.Managed is{} m&&m.KnownGood is{} good&&good.Share==candidate.Share&&good.Config==m.Applied&&good.Path==r.RuntimePath)candidate=null;
  }
  if(candidate is null||!proof.Observe(r,Now))return;
  var selected=candidate;candidate=null;Running=Promote(selected,new(selected.Id,r.RuntimeProfileIdentity!,r.ConnectionId,r.PathEpoch),generation);
 }
 private async Task Verify(SavedProfile p,string share,ManagedConfig? config)
 {
  if(verify is not null){await verify(p,share,config);return;}
  await ManagedBootstrap.VerifySaved(p with{Share=share});
  if(config is not null)await ManagedUpdateBuilder.Verify(p,config,config.Revision);
 }
 private void Current(long expected){if(disposed||generation!=expected)throw new OperationCanceledException();}
 private async Task Promote(SavedProfile p,RuntimeLease lease,long expected)
 {
  try{
   await Verify(p,p.Share,p.Managed!.Applied);Current(expected);
   var fresh=await status();Current(expected);
   if(!lease.Matches(fresh)||!ManagedProofWindow.Proven(fresh))throw new OperationCanceledException();
   catalog.MarkManagedGood(p,fresh,DateTimeOffset.UtcNow);
   if(trial?.Lease==lease){trial=null;trialProfile=null;}
   report("Профиль: handshake и выход в интернет подтверждены. Рабочая конфигурация сохранена для возврата.");
  }catch(OperationCanceledException){if(generation==expected){retryProof=Now+TimeSpan.FromSeconds(5);observed=default;}}
  catch{if(generation==expected){retryProof=Now+TimeSpan.FromSeconds(30);observed=default;report("Профиль: рабочее соединение есть, сохранить подтверждение не удалось. Конфигурация не заменялась.");}}
 }
 private SavedProfile ExpectedTrial(SavedProfile original,RuntimeLease lease)
 {
  var p=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==original.Id)??throw new IOException("MANAGED_STORAGE_CHANGED");
  var m=p.Managed;var old=original.Managed!;
  if(m is null||!m.Registered||m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");
  if(ProfileIdentity.Of(p.Share)!=lease.Identity||m.KnownGood!=old.KnownGood||m.DeviceToken!=old.DeviceToken||m.PublicKey!=old.PublicKey||m.DeviceId!=old.DeviceId||m.Origin!=old.Origin)throw new IOException("MANAGED_STORAGE_CHANGED");
  return p;
 }
 internal static bool CanReturn(ServiceReply r,RuntimeLease lease)=>r.Ok&&!r.PathPending&&r.PathEpoch==lease.PathEpoch&&r.Capabilities?.Contains("managed-recovery-v1")==true&&r.LastAttemptId==lease.Attempt&&
  r.ConfiguredProfileIdentity==lease.Identity&&r.State is not ("connected" or "captcha" or "stopping")&&string.IsNullOrEmpty(r.Captcha)&&
  (!r.TunnelActive?r.State is "stopped" or "error":r.RuntimeProfileIdentity==lease.Identity&&r.ConnectionId==lease.Attempt);
 private async Task Return(SavedProfile original,RuntimeLease lease,long expected)
 {
  try{
   recovering();report("Профиль: новое подключение не подтвердилось. Проверяем сохранённую рабочую конфигурацию…");
   var p=ExpectedTrial(original,lease);var good=p.Managed!.KnownGood??throw new IOException("MANAGED_NO_ROLLBACK");
   await Verify(p,good.Share,good.Config);Current(expected);
   var fresh=await status();Current(expected);
   if(!CanReturn(fresh,lease))throw new OperationCanceledException();
   p=ExpectedTrial(original,lease);var restored=catalog.ReturnManagedGood(p);
   var result=await recover(lease,restored.Share);
   if(!result.Ok||result.ConfiguredProfileIdentity!=ProfileIdentity.Of(restored.Share)||result.LastAttemptId==0||result.LastAttemptId==lease.Attempt)throw new IOException("MANAGED_RECOVERY_FAILED");
   report("Профиль: предыдущая рабочая конфигурация возвращена, подключение запущено. Ожидаем проверки интернета; повторного автоматического возврата не будет.");
  }catch(OperationCanceledException){report("Профиль: автоматический возврат отменён — состояние соединения изменилось.");}
  catch(IOException e)when(e.Message=="MANAGED_ACCESS_REJECTED"){report("Профиль: доступ отклонён, автоматический возврат запрещён. Ключи сохранены.");}
  catch{report("Профиль: автоматический возврат не завершён. Конфигурации сохранены; проверьте VPN и повторите подключение вручную.");}
  finally{returning=false;observed=default;candidate=null;proof.Reset();}
 }
 public void Dispose(){disposed=true;Cancel();}
}
