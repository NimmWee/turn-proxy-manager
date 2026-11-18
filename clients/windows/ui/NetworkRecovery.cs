using System.Diagnostics;
using System.IO;
using System.Text.Json;
namespace FreeTurn.Windows;
internal sealed record PhysicalNetwork(bool Available,string Fingerprint);
internal sealed class NetworkRecoveryPolicy{
 internal RuntimeLease? Lease{get;private set;}
 internal string? Fingerprint{get;private set;}
 internal int Attempts{get;private set;}
 internal bool Suspended{get;private set;}
 private bool forced;
 internal void Begin(RuntimeLease lease,string? fingerprint){Lease=lease;Fingerprint=fingerprint;Attempts=0;forced=false;Suspended=false;}
 internal void Stop(){Lease=null;forced=false;Attempts=0;}
 internal void Suspend(){Suspended=true;}
 internal void Resume(){Suspended=false;if(Lease is not null)forced=true;}
 internal bool Current(ServiceReply r)=>Lease is{} l&&r.Ok&&r.ConfiguredProfileIdentity==l.Identity&&r.LastAttemptId==l.Attempt;
 internal RuntimeLease? Request(ServiceReply r,PhysicalNetwork network){
  if(!Current(r)){Stop();return null;}
  if(Suspended||Attempts>=5||!network.Available||network.Fingerprint.Length!=64||r.Captcha is{Length:>0}||r.State is "captcha" or "stopping"||r.PathPending)return null;
  if(Fingerprint is null){Fingerprint=network.Fingerprint;if(!forced)return null;}
  if(!forced&&Fingerprint==network.Fingerprint&&!(r.State is "stopped" or "error"&&!r.TunnelActive))return null;
  return Lease! with{PathEpoch=r.PathEpoch};
 }
 internal void Requested(){Attempts++;}
 internal void Accepted(ServiceReply receipt,string fingerprint){
  if(!receipt.Ok||Lease is not{} l||receipt.ConfiguredProfileIdentity!=l.Identity||receipt.LastAttemptId==0){Stop();return;}
  Lease=l with{Attempt=receipt.LastAttemptId,PathEpoch=receipt.PathEpoch};Fingerprint=fingerprint;forced=false;
 }
}
internal sealed class NetworkRecovery(Func<Task<ServiceReply>> status,Func<RuntimeLease,Task<ServiceReply>> reconnect,Action<string> report,Action preparing,Func<RuntimeLease,bool> catalogCurrent):IDisposable{
 private readonly NetworkRecoveryPolicy policy=new();private bool disposed;private long generation;
 private readonly long origin=Stopwatch.GetTimestamp();private TimeSpan due;
 private TimeSpan Now=>Stopwatch.GetElapsedTime(origin);
 internal bool Busy=>!Running.IsCompleted;
 internal bool HasIntent=>policy.Lease is not null;
 internal bool Suspended=>policy.Suspended;
 internal Task Running{get;private set;}=Task.CompletedTask;
 internal void Stop(){generation++;policy.Stop();}
 internal async Task Begin(RuntimeLease lease){Stop();var epoch=generation;PhysicalNetwork? n=null;try{n=await Probe();}catch{}if(disposed||epoch!=generation)return;policy.Begin(lease,n is{Available:true}?n.Fingerprint:null);due=Now+TimeSpan.FromSeconds(5);}
 internal void Signal(){if(policy.Lease is not null)due=Now+TimeSpan.FromSeconds(3);}
 internal void Suspend(){policy.Suspend();}
 internal void Resume(){policy.Resume();Signal();}
 internal void Observe(ServiceReply r,bool allowed){
  if(disposed||Busy||!allowed||policy.Suspended||policy.Lease is null||Now<due)return;
  due=Now+TimeSpan.FromSeconds(15);Running=Run(r,generation);
 }
 private async Task Run(ServiceReply r,long expected){
  try{
   var network=await Probe();if(disposed||generation!=expected)return;
   var lease=policy.Request(r,network);if(lease is null)return;
   var fresh=await status();if(disposed||generation!=expected||!policy.Current(fresh)||!catalogCurrent(lease))return;
   // Epoch may have advanced while a status/physical probe awaited.
   lease=policy.Request(fresh,network);if(lease is null)return;
   policy.Requested();preparing();report("Сеть изменилась: восстанавливаем прежний профиль, попытка "+policy.Attempts+"/5…");
   var receipt=await reconnect(lease);if(disposed||generation!=expected)return;
   if(!receipt.Ok){if(receipt.Error=="CONNECTION_CHANGED")Stop();else report(policy.Attempts>=5?"Автоматические попытки исчерпаны. Подключитесь вручную.":"Восстановление сети отложено. Проверьте доступность канала и повторите подключение вручную.");due=Now+TimeSpan.FromSeconds(15);return;}
   policy.Accepted(receipt,network.Fingerprint);report("Повторный запуск на новом канале принят. Ожидаем свежий handshake и проверку интернета. Текущий Direct/Relay сохранён.");
  }catch{if(generation==expected){due=Now+TimeSpan.FromSeconds(15);report("Проверить физическую сеть пока не удалось. Профиль и ключи сохранены.");}}
 }
 internal static async Task<PhysicalNetwork> Probe(){
  using var p=new Process{StartInfo=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe"),"--network-state"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}};p.Start();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(8));
  try{var buffer=new char[1024];var count=await p.StandardOutput.ReadBlockAsync(buffer.AsMemory(),timeout.Token);await p.WaitForExitAsync(timeout.Token);if(count==1024||p.ExitCode!=0)throw new IOException();var result=JsonSerializer.Deserialize<PhysicalNetwork>(new string(buffer,0,count),new JsonSerializerOptions{PropertyNameCaseInsensitive=true});return result is not null&&(!result.Available||ProfileIdentity.Valid(result.Fingerprint))?result:throw new IOException();}catch{if(!p.HasExited)p.Kill();throw;}
 }
 public void Dispose(){disposed=true;Stop();}
}
