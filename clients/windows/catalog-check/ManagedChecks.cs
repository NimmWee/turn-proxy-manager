using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using FreeTurn.Windows;

internal static class ManagedChecks
{
 internal static async Task Run(bool engine=false)
 {
  var root=Path.Combine(Path.GetTempPath(),"ftm-managed-check-"+Guid.NewGuid().ToString("N"));
  try{
   var key=Convert.ToBase64String(Encoding.ASCII.GetBytes(new string('x',32)));
   var wg=$"[Interface]\nPrivateKey = {key}\nAddress = 10.77.43.9/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = {key}\nPresharedKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n";
   var share="freeturn://"+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{v=1,name="Managed synthetic",provider="vk",peer="8.8.8.8:5000",mode="udp",transport="tcp",obf="rtpopus3",key=new string('a',64),cid=new string('b',32),n=6,spc=3,vk="https://vk.com/call/join/SYNTHETIC",wg})).TrimEnd('=').Replace('+','-').Replace('/','_');
   var json=JsonSerializer.Serialize(new{version=1,format="ftm-bootstrap",device_id="11111111-2222-3333-4444-555555555555",public_key="m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=",origin="https://8.8.8.8",internal_api_ip="10.77.43.1",claim_nonce="ftmb1_"+new string('A',43),expires_at=DateTimeOffset.UtcNow.AddMinutes(20).ToString("O"),share});
   var bootstrap=ManagedBootstrap.Parse(json);
   if(ManagedCredential.ValidToken(bootstrap.ClaimNonce+"\n","ftmb1_"))throw new Exception("Credential accepted header control character");
   if(engine)await ManagedBootstrap.Verify(json);
   await ClaimRecoveryChecks.Run(root,bootstrap,engine);
   var catalog=new ProfileCatalog(root);var p=catalog.AddBootstrap(bootstrap,true);var token=p.Managed!.DeviceToken;
   if(catalog.AddBootstrap(bootstrap,true).Managed!.DeviceToken!=token||catalog.Read().Profiles.Count!=1||File.ReadAllText(Path.Combine(root,"profiles.dpapi")).Contains(token))throw new Exception("Managed retry/storage leaked or rotated token");
   var badClone=false;try{catalog.Clone(p.Id);}catch(IOException){badClone=true;}if(!badClone)throw new Exception("Managed clone duplicated credentials");
   var badEdit=false;try{catalog.Replace(p.Id,"Edited",share);}catch(IOException){badEdit=true;}if(!badEdit)throw new Exception("Managed editor could alter key-bound identity");
   var attempts=0;var bound=false;var digest=ManagedCredential.Digest(token);
   using var handler=new Fake(async request=>{
    if(request.Method==HttpMethod.Get)return bound?ClaimRecoveryChecks.Status(bootstrap.DeviceId):new(HttpStatusCode.Unauthorized);
    attempts++;var saved=catalog.Read().Profiles.Single().Managed!;
    if(saved.DeviceToken!=token||request.RequestUri!.AbsoluteUri!="https://8.8.8.8/api/client/v1/bootstrap/claim"||request.Headers.Authorization?.Parameter!=bootstrap.ClaimNonce)throw new Exception("Claim boundary/token persistence incorrect");
    var raw=await request.Content!.ReadAsStringAsync();using var body=JsonDocument.Parse(raw);
    if(body.RootElement.GetProperty("device_token_hash").GetString()!=digest||raw.Contains(token)||raw.Contains(key))throw new Exception("Claim leaked local token/key");
    if(attempts==1){bound=true;throw new HttpRequestException("SYNTHETIC_PRIVATE_ERROR");}
    return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{device_id=bootstrap.DeviceId,state="active",ready=true}))};
   });
   Func<SavedProfile,Task> verifier=engine?ManagedBootstrap.VerifySaved:_=>Task.CompletedTask;
   var gateDenied=false;try{await ManagedClient.Claim(catalog,p.Id,false,handler,verifier);}catch(IOException e){gateDenied=e.Message=="MANAGED_CONNECT_FIRST";}if(!gateDenied||attempts!=0)throw new Exception("Claim performed network before connected gate");
   using(var wrong=new Fake(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("{\"device_id\":\"WRONG_DEVICE\",\"state\":\"active\",\"ready\":true}")}))){
    var rejected=false;try{await ManagedClient.Claim(catalog,p.Id,true,wrong,verifier);}catch(IOException){rejected=true;}if(!rejected||catalog.Read().Profiles.Single().Managed!.Registered)throw new Exception("Claim registered wrong device");
   }
   var denied=false;try{await ManagedClient.Claim(catalog,p.Id,true,handler,verifier);}catch(IOException e){denied=e.Message=="MANAGED_NETWORK_FAILED";}
   if(!denied||catalog.Read().Profiles.Single().Managed!.DeviceToken!=token)throw new Exception("Lost response rotated credential or exposed error");
   await ManagedClient.Claim(catalog,p.Id,true,handler,verifier);
   var registered=catalog.Read().Profiles.Single();if(!registered.Managed!.Registered||registered.Managed.ClaimNonce!=null||registered.Share!=share||registered.Managed.DeviceToken!=token)throw new Exception("Claim changed keys or failed to persist registration");
   var stale=CatalogBackup.Decode(CatalogBackup.Encode(new ProfileSnapshot(1,null,[p])));catalog.Merge(stale);
   if(!catalog.Read().Profiles.Single().Managed!.Registered)throw new Exception("Restore replaced current managed credentials/state");
   var restored=new ProfileCatalog(root+"-restore");restored.Merge(CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read())));
   if(restored.Read().Profiles.Single().Managed!.DeviceToken!=token)throw new Exception("Backup lost managed token");
   var rawCatalog=new ProfileCatalog(root+"-raw");rawCatalog.Add("Original",share);rawCatalog.Merge(CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read())));
   if(rawCatalog.Read().Profiles.Count!=1||rawCatalog.Read().Profiles.Single().Managed?.DeviceToken!=token)throw new Exception("Restore lost managed credentials when raw profile already exists");
   using var transport=ManagedClient.CreateTransport(registered.Managed);
   if(ManagedClient.InternalTarget(registered.Managed,"8.8.8.8",443).ToString()!="10.77.43.1:443")throw new Exception("Managed TCP target escaped internal API");
   var wrongOrigin=false;try{ManagedClient.InternalTarget(registered.Managed,"1.1.1.1",443);}catch(IOException){wrongOrigin=true;}if(!wrongOrigin)throw new Exception("Managed callback accepted different TLS origin");
   if(transport.AllowAutoRedirect||transport.UseProxy||transport.UseCookies||transport.ConnectCallback==null||transport.SslOptions.RemoteCertificateValidationCallback!=null)throw new Exception("Managed TLS transport weakened");
   var storage=new ProfileCatalog(Path.Combine(root,"storage"));storage.Merge(catalog.Read());SubscriptionChecks.Storage(storage,p.Id);
   var lkg=new ProfileCatalog(Path.Combine(root,"lkg"));lkg.Merge(catalog.Read());LkgChecks.Storage(lkg,p.Id);
   var pathFlow=new ProfileCatalog(Path.Combine(root,"transport"));pathFlow.Merge(catalog.Read());await TransportChecks.Flow(pathFlow,pathFlow.Read().Profiles.Single());
   await SettingsChecks.Run(new ProfileCatalog(Path.Combine(root,"settings")),catalog.Read().Profiles.Single(),engine);
   var lkgFlow=new ProfileCatalog(Path.Combine(root,"lkg-flow"));lkgFlow.Merge(catalog.Read());await LkgChecks.Flow(lkgFlow,p.Id,engine);
   await SyncChecks.Run(catalog,p.Id);
   await SubscriptionChecks.Network(catalog,p.Id,engine);
   Console.WriteLine("PASS: managed DPAPI/import/retry/token-before-claim/key preservation/backup merge; synthetic HTTP lost-response claim; strict internal HTTPS transport configuration; live network NOT RUN");
  }finally{foreach(var dir in new[]{root,root+"-restore",root+"-raw"})if(Directory.Exists(dir))Directory.Delete(dir,true);}
 }
 private sealed class Fake(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request);}
}
