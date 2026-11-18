using System.Text.RegularExpressions;

namespace FreeTurn.Windows;

internal sealed record EnrollmentKey(string PrivateKey,string PublicKey)
{
 public override string ToString()=>"EnrollmentKey (private fields omitted)";
 internal static bool Key(string? value){try{return value is not null&&Convert.FromBase64String(value) is{Length:32} raw&&raw.Any(b=>b!=0)&&Convert.ToBase64String(raw)==value;}catch{return false;}}
 internal bool Valid=>Key(PrivateKey)&&Key(PublicKey);
}
internal sealed record EnrollmentAttempt(Guid RequestId,string Name,string Origin,string SourceHash,string? UserToken,string PrivateKey,string PublicKey,string ClientId,string DeviceToken,string? DeviceId=null,long Revision=0,bool Attempted=false)
{
 public override string ToString()=>"EnrollmentAttempt (private fields omitted)";
 internal static bool Hash(string? v,int length)=>v is not null&&v.Length==length&&Regex.IsMatch(v,"\\A[a-f0-9]+\\z");
 internal static bool Identifier(string? v)=>v is not null&&Guid.TryParseExact(v,"D",out var id)&&id!=Guid.Empty&&id.ToString("D")==v;
 internal bool Valid=>RequestId!=Guid.Empty&&!string.IsNullOrWhiteSpace(Name)&&Name.Length<=128&&!Name.Any(char.IsControl)&&EnrollmentLink.PublicOrigin(Origin)&&Hash(SourceHash,64)&&new EnrollmentKey(PrivateKey,PublicKey).Valid&&Hash(ClientId,32)&&ManagedCredential.ValidToken(DeviceToken,"ftmd1_")&&(DeviceId is null?Revision==0&&ManagedCredential.ValidToken(UserToken,"ftmu1_")&&new EnrollmentLink(1,"ftm-enrollment",Origin,UserToken!).SourceHash==SourceHash:Identifier(DeviceId)&&Revision>=1&&UserToken is null);
 internal bool SameIdentity(EnrollmentAttempt other)=>RequestId==other.RequestId&&Name==other.Name&&Origin==other.Origin&&SourceHash==other.SourceHash&&PrivateKey==other.PrivateKey&&PublicKey==other.PublicKey&&ClientId==other.ClientId&&DeviceToken==other.DeviceToken;
}
