namespace FreeTurn.Windows;

internal sealed class ManagedProofWindow
{
 private (string?,ulong,ulong) session;
 private TimeSpan first,last;
 private bool started;
 internal void Reset()=>started=false;
 internal static bool Proven(ServiceReply r)=>RuntimeLease.Usable(r)&&r.Handshake&&r.Rx>0&&r.Tx>0;
 internal bool Observe(ServiceReply r,TimeSpan now)
 {
  if(!Proven(r)){Reset();return false;}
  var key=(r.RuntimeProfileIdentity,r.ConnectionId,r.PathEpoch);
  if(!started||key!=session||now<last||now-last>TimeSpan.FromSeconds(5)){session=key;first=now;started=true;}
  last=now;return now-first>=TimeSpan.FromSeconds(5);
 }
}

internal enum TrialDecision {Wait,Cancel,Return}
internal sealed class ManagedTrial(RuntimeLease lease,TimeSpan now)
{
 internal RuntimeLease Lease {get;private set;}=lease;
 private TimeSpan last=now,elapsed;
 internal TrialDecision Observe(ServiceReply r,TimeSpan now,bool pathsPending=false,bool pathsExhausted=false)
 {
  if(!r.Ok||r.Capabilities?.Contains("managed-recovery-v1")!=true||r.ConfiguredProfileIdentity!=Lease.Identity||r.LastAttemptId!=Lease.Attempt)return TrialDecision.Cancel;
  if(r.DiagnosticError is "VK_AUTH_FAILED" or "VK_RATE_LIMIT" or "VK_LINK_INVALID" or "CAPTCHA_TIMEOUT")return TrialDecision.Cancel;
  if(r.AutoPaths&&r.PathEpoch>=Lease.PathEpoch&&r.PathEpoch<=2)Lease=Lease with{PathEpoch=r.PathEpoch};
  else if(r.PathEpoch!=Lease.PathEpoch)return TrialDecision.Cancel;
  if(pathsPending){last=now;elapsed=TimeSpan.Zero;return TrialDecision.Wait;}
  if(pathsExhausted)elapsed=TimeSpan.FromSeconds(120);
  var delta=now-last;last=now;
  if(r.State=="captcha"||!string.IsNullOrEmpty(r.Captcha)||r.State=="stopping"||r.State=="connected")return TrialDecision.Wait;
  if(delta<TimeSpan.Zero||delta>TimeSpan.FromSeconds(10))return TrialDecision.Wait;
  elapsed+=delta;
  return r.State is "error" or "stopped"||elapsed>=TimeSpan.FromSeconds(120)?TrialDecision.Return:TrialDecision.Wait;
 }
}
