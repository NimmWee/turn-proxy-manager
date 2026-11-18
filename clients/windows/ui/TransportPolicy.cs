namespace FreeTurn.Windows;

internal enum TransportDecision {Wait,Switch,Cancel,Exhausted}
internal sealed class TransportPolicy(RuntimeLease lease,string path,TimeSpan now)
{
 internal RuntimeLease Lease {get;private set;}=lease;
 internal string Path {get;private set;}=path;
 internal string Target=>Path=="direct"?"relay":"direct";
 private TimeSpan last=now,elapsed,pendingTime,unknown;
 private bool requested;
 internal void Requested(){requested=true;pendingTime=TimeSpan.Zero;}
 internal void Recovered(){requested=false;elapsed=TimeSpan.Zero;pendingTime=TimeSpan.Zero;}
 internal bool Scope(ServiceReply r)=>r.Ok&&r.AutoPaths&&r.Capabilities?.Contains("transport-path-v1")==true&&r.LastAttemptId==Lease.Attempt&&r.ConfiguredProfileIdentity==Lease.Identity;
 internal TransportDecision Observe(ServiceReply r,TimeSpan now)
 {
  if(!Scope(r)||!r.TunnelActive||r.DiagnosticError is "VK_AUTH_FAILED" or "VK_RATE_LIMIT" or "VK_LINK_INVALID" or "CAPTCHA_TIMEOUT" or "PATH_STATE_INVALID")return TransportDecision.Cancel;
  var delta=now-last;last=now;if(delta<TimeSpan.Zero||delta>TimeSpan.FromSeconds(10))delta=TimeSpan.Zero;
  if(r.PathEpoch!=Lease.PathEpoch){
   if(!requested||r.PathEpoch!=Lease.PathEpoch+1||r.PathEpoch>2||r.RuntimePath!=Target)return TransportDecision.Cancel;
   Lease=Lease with{PathEpoch=r.PathEpoch};Path=r.RuntimePath!;requested=false;elapsed=TimeSpan.Zero;return TransportDecision.Wait;
  }
  if(requested||r.PathPending){pendingTime+=delta;return pendingTime>TimeSpan.FromSeconds(60)?TransportDecision.Cancel:TransportDecision.Wait;}
  if(r.RuntimePath!=Path)return TransportDecision.Cancel;
  if(r.State=="captcha"||!string.IsNullOrEmpty(r.Captcha)||r.State=="stopping")return TransportDecision.Wait;
  if(ManagedProofWindow.Proven(r)){elapsed=TimeSpan.Zero;return TransportDecision.Wait;}
  if(r.RuntimeProfileIdentity!=Lease.Identity||r.ConnectionId!=Lease.Attempt){unknown+=delta;return unknown>TimeSpan.FromSeconds(60)?TransportDecision.Cancel:TransportDecision.Wait;}
  unknown=TimeSpan.Zero;
  elapsed+=delta;var limit=Path=="direct"?30:60;
  if(elapsed<TimeSpan.FromSeconds(limit)&&!(r.State=="error"&&elapsed>=TimeSpan.FromSeconds(5)))return TransportDecision.Wait;
  return Lease.PathEpoch>=2?TransportDecision.Exhausted:TransportDecision.Switch;
 }
}
