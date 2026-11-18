using System.IO;
using System.Security.Cryptography;

namespace FreeTurn.Windows;

internal sealed partial class ProfileCatalog
{
 internal EnrollmentAttempt StartEnrollment(EnrollmentLink source,string name,EnrollmentKey key)
 {
  _=EnrollmentLink.Parse(System.Text.Json.JsonSerializer.Serialize(source));
  var data=Read();if(data.Profiles.Any(p=>p.Managed is{} m&&m.Origin==source.Origin&&m.EnrollmentSourceHash==source.SourceHash))throw new IOException("MANAGED_ALREADY_ENROLLED");
  var attempts=new List<EnrollmentAttempt>(data.Enrollments??[]);var existing=attempts.FirstOrDefault(e=>e.Origin==source.Origin&&e.SourceHash==source.SourceHash);if(existing is not null)return existing;
  if(attempts.Count>=16||!key.Valid)throw new IOException("MANAGED_ENROLLMENT_INVALID");
  var attempt=new EnrollmentAttempt(Guid.NewGuid(),name.Trim(),source.Origin,source.SourceHash,source.UserToken,key.PrivateKey,key.PublicKey,Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),ManagedCredential.NewToken());
  attempts.Add(attempt);Write(data with{Enrollments=attempts});return attempt;
 }
 private (ProfileSnapshot Data,List<EnrollmentAttempt> Attempts,int Index) ExpectedEnrollment(EnrollmentAttempt expected)
 {
  var data=Read();var attempts=new List<EnrollmentAttempt>(data.Enrollments??[]);var index=attempts.FindIndex(a=>a.RequestId==expected.RequestId);
  if(index<0||attempts[index]!=expected)throw new IOException("MANAGED_STORAGE_CHANGED");return(data,attempts,index);
 }
 internal EnrollmentAttempt AcknowledgeEnrollment(EnrollmentAttempt expected,string deviceId,long revision)
 {
  var(data,attempts,index)=ExpectedEnrollment(expected);
  if(!EnrollmentAttempt.Identifier(deviceId)||revision<1||expected.DeviceId is not null&&expected.DeviceId!=deviceId)throw new IOException("MANAGED_RESPONSE_INVALID");
  var acknowledged=expected with{DeviceId=deviceId,Revision=Math.Max(expected.Revision,revision),UserToken=null,Attempted=true};attempts[index]=acknowledged;Write(data with{Enrollments=attempts});return acknowledged;
 }
 internal EnrollmentAttempt MarkEnrollmentStarted(EnrollmentAttempt expected)
 {
  var(data,attempts,index)=ExpectedEnrollment(expected);if(expected.Attempted)return expected;
  var started=expected with{Attempted=true};attempts[index]=started;Write(data with{Enrollments=attempts});return started;
 }
 internal SavedProfile FinishRestoredEnrollment(EnrollmentAttempt expected,SavedProfile verified)
 {
  var(data,attempts,index)=ExpectedEnrollment(expected);var current=data.Profiles.SingleOrDefault(p=>p.Id==verified.Id);
  if(current!=verified||current?.Managed is not{} m||m.Origin!=expected.Origin||m.EnrollmentSourceHash!=expected.SourceHash||m.PublicKey!=expected.PublicKey||m.DeviceToken!=expected.DeviceToken)throw new IOException("MANAGED_ENROLLMENT_CONFLICT");
  attempts.RemoveAt(index);Write(data with{Enrollments=attempts.Count==0?null:attempts});return current;
 }
 internal SavedProfile CompleteEnrollment(EnrollmentAttempt expected,ManagedConfig config)
 {
  var(data,attempts,index)=ExpectedEnrollment(expected);
  if(expected.DeviceId is null||!config.Valid||config.Revision<expected.Revision||data.Profiles.Any(p=>p.Managed is{} m&&m.Origin==expected.Origin&&m.DeviceId==expected.DeviceId))throw new IOException("MANAGED_ENROLLMENT_CONFLICT");
  var managed=new ManagedCredential(expected.DeviceId,expected.PublicKey,expected.Origin,"10.77.43.1",null,"1970-01-01T00:00:00Z",expected.DeviceToken,Registered:true,Applied:config,SeenRevision:config.Revision,EnrollmentSourceHash:expected.SourceHash);
  var profile=new SavedProfile(Guid.NewGuid(),expected.Name,config.Share,Managed:managed);data.Profiles.Add(profile);attempts.RemoveAt(index);
  Write(data with{Enrollments=attempts.Count==0?null:attempts});return profile;
 }
 private static List<EnrollmentAttempt>? MergeEnrollments(ProfileSnapshot current,ProfileSnapshot incoming)
 {
  var attempts=new List<EnrollmentAttempt>(current.Enrollments??[]);
  foreach(var item in incoming.Enrollments??[]){
   if(current.Profiles.Any(p=>p.Managed is{} m&&m.Origin==item.Origin&&m.EnrollmentSourceHash==item.SourceHash&&m.PublicKey==item.PublicKey&&m.DeviceToken==item.DeviceToken))continue;
   var index=attempts.FindIndex(e=>e.RequestId==item.RequestId||e.Origin==item.Origin&&e.SourceHash==item.SourceHash);
   if(index<0){attempts.Add(item);continue;}
   var old=attempts[index];if(!old.SameIdentity(item)||old.DeviceId is not null&&item.DeviceId is not null&&old.DeviceId!=item.DeviceId)throw new IOException("MANAGED_ENROLLMENT_CONFLICT");
   if(old.DeviceId is null&&item.DeviceId is not null||item.Revision>old.Revision)attempts[index]=item;else if(item.Attempted&&!old.Attempted)attempts[index]=old with{Attempted=true};
  }
  return attempts.Count==0?null:attempts;
 }
}
