using System.IO;

namespace FreeTurn.Windows;

internal sealed partial class ProfileCatalog
{
 internal void MarkManagedGood(SavedProfile expected,ServiceReply proof,DateTimeOffset now)
 {
  var(data,index,m)=ExpectedManaged(expected);
  var lease=new RuntimeLease(expected.Id,ProfileIdentity.Of(expected.Share),proof.ConnectionId,proof.PathEpoch);
  if(!m.Registered||m.AccessDenied||!lease.Matches(proof)||!proof.Handshake||proof.Rx==0||proof.Tx==0)throw new IOException("MANAGED_PROOF_REQUIRED");
  if(m.KnownGood is{} good&&good.Share==expected.Share&&good.Config==m.Applied&&good.Path==proof.RuntimePath)return;
  data.Profiles[index]=data.Profiles[index] with{Managed=m with{KnownGood=new(expected.Share,m.Applied,now.ToString("O"),proof.RuntimePath)}};Write(data);
 }
 internal SavedProfile ReturnManagedGood(SavedProfile expected)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(!m.Registered||m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");
  var good=m.KnownGood;if(good is null||!good.Valid||good.Share==expected.Share)throw new IOException("MANAGED_NO_ROLLBACK");
  var returned=expected with{Share=good.Share,Managed=m with{Applied=good.Config,Pending=m.Pending??m.Applied,PreviousShare=expected.Share,Previous=m.Applied}};
  data.Profiles[index]=returned;Write(data);return returned;
 }
 private (ProfileSnapshot Data,int Index,ManagedCredential Credential) ExpectedManaged(SavedProfile expected)
 {
  var data=Read();var index=data.Profiles.FindIndex(p=>p.Id==expected.Id);
  if(index<0||data.Profiles[index].Managed is not{} m||m!=expected.Managed||data.Profiles[index].Share!=expected.Share)throw new IOException("MANAGED_STORAGE_CHANGED");
  return(data,index,m);
 }
 internal void StageManaged(SavedProfile expected,ManagedConfig candidate)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(!m.Registered||!candidate.Valid||candidate.Revision<m.SeenRevision)throw new IOException("MANAGED_CONFIG_INVALID");
  data.Profiles[index]=data.Profiles[index] with{Managed=m with{Pending=candidate,SeenRevision=Math.Max(m.SeenRevision,candidate.Revision),AccessDenied=false}};Write(data);
 }
 internal void ConfirmManagedUnchanged(SavedProfile expected)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(m.Pending is null&&m.Applied is null)throw new IOException("MANAGED_CONFIG_INVALID");
  if(m.AccessDenied){data.Profiles[index]=data.Profiles[index] with{Managed=m with{AccessDenied=false}};Write(data);}
 }
 internal void DenyManaged(SavedProfile expected)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(!m.Registered)throw new IOException("MANAGED_CONFIG_INVALID");
  if(!m.AccessDenied){data.Profiles[index]=data.Profiles[index] with{Managed=m with{AccessDenied=true}};Write(data);}
 }
 internal void ApplyManaged(SavedProfile expected,ManagedConfig verified)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");
  if(m.Pending is null||verified!=m.Pending||!verified.Valid)throw new IOException("MANAGED_CONFIG_INVALID");
  data.Profiles[index]=data.Profiles[index] with{Share=verified.Share,Managed=m with{Applied=verified,Pending=null,PreviousShare=expected.Share,Previous=m.Applied}};Write(data);
 }
 internal void RollbackManaged(SavedProfile expected)
 {
  var(data,index,m)=ExpectedManaged(expected);
  if(m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");
  if(m.PreviousShare is null)throw new IOException("MANAGED_NO_ROLLBACK");
  data.Profiles[index]=data.Profiles[index] with{Share=m.PreviousShare,Managed=m with{Applied=m.Previous,Pending=m.Pending??m.Applied,PreviousShare=null,Previous=null}};Write(data);
 }
}
