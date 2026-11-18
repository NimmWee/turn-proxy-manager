using System.Security.Cryptography;
using System.Text;

namespace FreeTurn.Windows;

internal static class ProfileIdentity
{
 internal static string Of(string share)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("FreeTurn profile identity v1\0"+share.Trim()))).ToLowerInvariant();
 internal static bool Valid(string? value)=>value is {Length:64}&&value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal sealed record RuntimeLease(Guid ProfileId,string Identity,ulong Attempt,ulong PathEpoch=0)
{
 internal static bool Usable(ServiceReply r)=>r.Ok&&!r.PathPending&&r.State=="connected"&&r.TunnelActive&&r.Kind=="wireguard"&&
  r.Capabilities?.Contains("runtime-profile-identity-v1")==true&&ProfileIdentity.Valid(r.RuntimeProfileIdentity)&&r.ConnectionId!=0;
 internal bool Matches(ServiceReply r)=>Usable(r)&&ProfileIdentity.Valid(Identity)&&Attempt!=0&&
  r.RuntimeProfileIdentity==Identity&&r.ConnectionId==Attempt&&r.PathEpoch==PathEpoch;
 internal static RuntimeLease? Find(ProfileSnapshot catalog,ServiceReply r)
 {
  if(!Usable(r))return null;
  var candidates=catalog.Profiles.Where(p=>p.Managed is{Registered:true,AccessDenied:false}&&ProfileIdentity.Of(p.Share)==r.RuntimeProfileIdentity).ToArray();
  if(candidates.Length!=1)return null;
  var lease=new RuntimeLease(candidates[0].Id,r.RuntimeProfileIdentity!,r.ConnectionId,r.PathEpoch);return lease.Matches(r)?lease:null;
 }
 public override string ToString()=>"RuntimeLease (private correlation omitted)";
}
