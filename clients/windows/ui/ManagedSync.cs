using System.IO;

namespace FreeTurn.Windows;

internal sealed class ManagedSyncSchedule(DateTimeOffset now)
{
 internal DateTimeOffset Next {get;private set;}=now.AddSeconds(15);
 private int failures;
 internal void Started(DateTimeOffset now)=>Next=now.AddMinutes(30);
 internal void Succeeded(DateTimeOffset now,bool pending){failures=0;Next=now.AddMinutes(pending?1:30);}
 internal void Failed(DateTimeOffset now,TimeSpan? retry=null){failures=Math.Min(5,failures+1);Next=now+(retry??TimeSpan.FromSeconds(Math.Min(900,30*Math.Pow(2,failures))));}
}

// Owned by the UI dispatcher: catalog writes, Observe and completion are serialized.
// This stages updates only; no installation, elevation, connect or live config apply.
internal sealed class ManagedSync(
 ProfileCatalog catalog,Func<Task<ServiceReply>> status,Func<RuntimeLease,Task<ServiceReply>> stop,
 Action<string> report,Func<DateTimeOffset>? clock=null,
 Func<Guid,CancellationToken,Func<Task>,Task<ManagedRefresh>>? refresh=null):IDisposable
{
 private readonly Dictionary<(Guid,string),ManagedSyncSchedule> schedules=[];
 private RuntimeLease? current;
 private CancellationTokenSource? cancellation;
 private DateTimeOffset inspectAfter;
 private bool disposed;
 internal Task Running {get;private set;}=Task.CompletedTask;
 private DateTimeOffset Now=>(clock??(()=>DateTimeOffset.UtcNow))();
 internal void Cancel(){current=null;inspectAfter=DateTimeOffset.MinValue;cancellation?.Cancel();}
 internal void Observe(ServiceReply? reply,bool allowed)
 {
  if(disposed)return;
  if(!allowed||reply is null||!RuntimeLease.Usable(reply)){Cancel();return;}
  // Status is polled frequently for the UI. Do not decrypt/hash the entire
  // catalog on each tick; every request/commit still rechecks durable state.
  if(current is{} active&&active.Matches(reply)&&(!Running.IsCompleted||schedules.TryGetValue((active.ProfileId,active.Identity),out var held)&&Now<held.Next))return;
  if(current is null&&Now<inspectAfter)return;
  inspectAfter=Now.AddSeconds(5);
  ProfileSnapshot data;
  try{data=catalog.Read();}catch{Cancel();inspectAfter=Now.AddMinutes(1);report("Подписка: каталог не прочитан. Фоновая проверка отложена, состояние VPN не менялось.");return;}
  var lease=data.ManagedAutoSync?RuntimeLease.Find(data,reply):null;
  if(lease!=current){Cancel();current=lease;}
  if(lease is null||!Running.IsCompleted)return;
  var key=(lease.ProfileId,lease.Identity);
  if(!schedules.TryGetValue(key,out var schedule)){
   // Bounded to the catalog limit; remove obsolete correlation keys on churn.
   if(schedules.Count>=256)schedules.Clear();
   schedules[key]=schedule=new(Now);
  }
  if(Now<schedule.Next)return;
  schedule.Started(Now);cancellation=new();Running=Run(lease,schedule,cancellation);
 }
 private async Task Run(RuntimeLease lease,ManagedSyncSchedule schedule,CancellationTokenSource source)
 {
  async Task EnsureCurrent(){
   source.Token.ThrowIfCancellationRequested();
   var reply=await status();var data=catalog.Read();
   source.Token.ThrowIfCancellationRequested();
   if(disposed||current!=lease||!data.ManagedAutoSync||RuntimeLease.Find(data,reply)!=lease){source.Cancel();source.Token.ThrowIfCancellationRequested();}
  }
  try{
   var result=await (refresh is null?ManagedSubscription.Refresh(catalog,lease.ProfileId,true,cancellation:source.Token,ensureCurrent:EnsureCurrent):refresh(lease.ProfileId,source.Token,EnsureCurrent));
   if(refresh is null&&result!=ManagedRefresh.Pending)await ManagedRouting.Refresh(catalog,lease.ProfileId,source.Token,EnsureCurrent);
   schedule.Succeeded(Now,result==ManagedRefresh.Pending);
   if(result==ManagedRefresh.Staged)report("Подписка: обновление проверено и сохранено. Выберите его в управлении доступом; текущий VPN продолжает работать.");
  }catch(OperationCanceledException){schedule.Failed(Now);}
  catch(IOException e)when(e.Message=="MANAGED_ACCESS_REJECTED"){
   schedule.Failed(Now);
   // Denial is already durable. The broker rechecks this exact runtime under its
   // action mutex; a reconnect, even with identical keys, cannot be stopped here.
   try{var result=await stop(lease);report(result.Ok?"Подписка: сервер отозвал доступ, соответствующее соединение отключено. Ключи сохранены.":"Подписка: доступ отозван. Остановка прежнего сеанса не подтверждена; проверьте состояние VPN.");}
   catch{report("Подписка: доступ отозван. Не удалось подтвердить остановку VPN. Ключи сохранены.");}
  }
  catch(Exception e){schedule.Failed(Now,e is ManagedRetryException retry?retry.Delay:null);report("Подписка: проверка отложена. Текущая конфигурация сохранена; следующая попытка будет позже.");}
  finally{if(ReferenceEquals(cancellation,source))cancellation=null;source.Dispose();}
 }
 public void Dispose(){disposed=true;Cancel();}
}
