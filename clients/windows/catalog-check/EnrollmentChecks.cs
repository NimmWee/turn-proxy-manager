using System.IO;
using System.Text;
using System.Text.Json;
using FreeTurn.Windows;

internal static class EnrollmentChecks
{
 internal static async Task Run(bool engine=false)
 {
  var root=Path.Combine(Path.GetTempPath(),"ftm-enrollment-check-"+Guid.NewGuid().ToString("N"));
  try{
   var source=EnrollmentLink.Parse(JsonSerializer.Serialize(new{version=1,format="ftm-enrollment",origin="https://8.8.8.8",user_token="ftmu1_"+new string('A',43)}));
   if(EnrollmentLink.Parse(source.ToUri())!=source)throw new Exception("Enrollment JSON/URI roundtrip changed credential");
   foreach(var invalid in new[]{source.ToUri()+"?token=x","{\"version\":1,\"version\":1,\"format\":\"ftm-enrollment\",\"origin\":\"https://8.8.8.8\",\"user_token\":\""+source.UserToken+"\"}"}){var refused=false;try{EnrollmentLink.Parse(invalid);}catch(IOException){refused=true;}if(!refused)throw new Exception("Enrollment accepted ambiguous credential input");}
   foreach(var origin in new[]{"http://8.8.8.8","https://8.8.8.8/","https://8.8.8.8?token=x","https://127.0.0.1","https://169.254.169.254","https://10.77.43.1"}){
    var refused=false;try{EnrollmentLink.Parse(JsonSerializer.Serialize(new{version=1,format="ftm-enrollment",origin,user_token=source.UserToken}));}catch(IOException){refused=true;}if(!refused)throw new Exception("Enrollment accepted unsafe origin");
   }
   var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));
   var pair=engine?await EnrollmentEngine.NewKey(source.Origin):new EnrollmentKey(key,"m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=");
   var catalog=new ProfileCatalog(root);var first=catalog.StartEnrollment(source,"Windows test",pair);
   var again=catalog.StartEnrollment(source,"Different retry name",pair);
   if(again!=first||File.ReadAllText(Path.Combine(root,"profiles.dpapi")).Contains(first.DeviceToken)||File.ReadAllText(Path.Combine(root,"profiles.dpapi")).Contains(first.PrivateKey))throw new Exception("Enrollment retry changed identity or leaked keys");
   var restored=new ProfileCatalog(Path.Combine(root,"restored"));restored.Merge(CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read())));
   if(restored.Read().Enrollments!.Single()!=first)throw new Exception("Backup lost pending identity");
   var before=File.ReadAllBytes(Path.Combine(root,"profiles.dpapi"));var conflict=false;try{catalog.Merge(new ProfileSnapshot(1,null,[],Enrollments:[first with{DeviceToken="ftmd1_"+new string('B',43)}]));}catch(IOException){conflict=true;}if(!conflict||!File.ReadAllBytes(Path.Combine(root,"profiles.dpapi")).SequenceEqual(before))throw new Exception("Conflicting backup replaced enrollment credentials");
   var ack=catalog.AcknowledgeEnrollment(first,"11111111-2222-3333-4444-555555555555",1);
   if(ack.UserToken is not null||ack.PrivateKey!=first.PrivateKey||ack.DeviceToken!=first.DeviceToken)throw new Exception("Enrollment ack failed to clear user token or changed key");
   catalog.Merge(new ProfileSnapshot(1,null,[],Enrollments:[first]));
   if(catalog.Read().Enrollments!.Single().UserToken is not null)throw new Exception("Old restore revived enrollment user token after ack");
   using(var transport=EnrollmentClient.CreateTransport(source.Origin,false))if(transport.AllowAutoRedirect||transport.UseProxy||transport.UseCookies||transport.SslOptions.RemoteCertificateValidationCallback is not null||EnrollmentClient.Target(source.Origin,false,"8.8.8.8",443).ToString()!="8.8.8.8:443"||EnrollmentClient.Target(source.Origin,true,"8.8.8.8",443).ToString()!="10.77.43.1:443")throw new Exception("Enrollment transport escaped numeric TLS destination");
   await EnrollmentNetworkChecks.Run(Path.Combine(root,"uncommitted"),source,pair,engine,false);
   await EnrollmentNetworkChecks.Run(Path.Combine(root,"committed"),source,pair,engine,true);
   Console.WriteLine("PASS: enrollment JSON/URI/public origin, stable pending DPAPI keys/UUID/token/name, backup and ack preservation (no network)");
  }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
}
