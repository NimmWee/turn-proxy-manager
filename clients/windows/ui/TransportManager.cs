using System.Diagnostics;
using System.IO;

namespace FreeTurn.Windows;

internal sealed class TransportManager(ProfileCatalog catalog,Func<Task<ServiceReply>> status,
 Func<RuntimeLease,string,Task<ServiceReply>> change,Action<string> report,Action switching,Action stopped,
 Func<TimeSpan>? clock=null):IDisposable
{
 private readonly long origin=Stopwatch.GetTimestamp();
 private TimeSpan Now=>clock?.Invoke()??Stopwatch.GetElapsedTime(origin);
 private TransportPolicy? policy;
 private RuntimeLease? exhausted;
 private long generation;
 private bool disposed;
 internal bool HasIntent=>policy is not null;
 internal bool Exhausted=>exhausted is not null;
 internal Task Running {get;private set;}=Task.CompletedTask;
 internal bool Busy=>!Running.IsCompleted;
 internal void Cancel(){generation++;policy=null;exhausted=null;}
 internal void Begin(SavedProfile? profile,ServiceReply receipt)
 {
  Cancel();if(disposed||!receipt.Ok||!receipt.AutoPaths||receipt.LastAttemptId==0||!ProfileIdentity.Valid(receipt.ConfiguredProfileIdentity)||receipt.RuntimePath!="direct"||receipt.PathEpoch!=0)return;
  policy=new(new(profile?.Id??Guid.Empty,receipt.ConfiguredProfileIdentity!,receipt.LastAttemptId),"direct",Now);
 }
 internal void Observe(ServiceReply r,bool allowed)
 {
  if(disposed)return;if(!allowed){Cancel();return;}
  if(exhausted is{} old&&(r.LastAttemptId!=old.Attempt||r.ConfiguredProfileIdentity!=old.Identity)){Cancel();return;}
  if(policy is not{} active||Busy)return;
  var decision=active.Observe(r,Now);
  if(decision==TransportDecision.Cancel){Cancel();stopped();report("Транспорт: автоматический выбор остановлен. Проверьте состояние VPN; новые попытки начнутся только по вашему действию.");}
  else if(decision==TransportDecision.Exhausted){exhausted=active.Lease;policy=null;stopped();report("Транспорт: лимит переключений исчерпан, интернет не подтверждён. Сохраняем текущий туннель; требуется восстановление профиля или ручное действие.");}
  else if(decision==TransportDecision.Switch){active.Requested();Running=Switch(active,active.Lease,active.Target,generation);}
 }
 private async Task Switch(TransportPolicy active,RuntimeLease lease,string target,long expected)
 {
  try{
   switching();report("Транспорт: "+(target=="relay"?"Direct недоступен, пробуем VK Relay…":"Relay недоступен, пробуем Direct…"));
   if(lease.ProfileId!=Guid.Empty){var p=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==lease.ProfileId);if(p is null||ProfileIdentity.Of(p.Share)!=lease.Identity||p.Managed is{AccessDenied:true})throw new IOException("CONNECTION_CHANGED");}
   var fresh=await status();if(disposed||generation!=expected||policy!=active)throw new OperationCanceledException();
   if(active.Scope(fresh)&&fresh.PathEpoch==lease.PathEpoch&&ManagedProofWindow.Proven(fresh)){active.Recovered();report("Транспорт: текущий путь восстановился. Сохраняем работающее соединение.");return;}
   if(!active.Scope(fresh)||fresh.PathEpoch!=lease.PathEpoch||fresh.PathPending||fresh.State is "connected" or "captcha"||!string.IsNullOrEmpty(fresh.Captcha))throw new OperationCanceledException();
   var reply=await change(lease,target);
   if(!reply.Ok)throw new IOException("CONNECTION_CHANGED");
   report("Транспорт: запрос переключения принят. WireGuard и маршруты сохраняются; ожидаем проверки интернета.");
  }catch{if(generation==expected){Cancel();stopped();report("Транспорт: переключение не подтверждено. Автоматические попытки остановлены; состояние VPN будет проверено заново.");}}
 }
 public void Dispose(){disposed=true;Cancel();}
}
