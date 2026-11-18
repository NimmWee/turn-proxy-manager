using System.IO;
using System.Text;
using System.Text.Json.Nodes;
using FreeTurn.Windows;

if (args is ["--read-throughput-status"])
{
    try
    {
        var status = await ServiceClient.Send("status");
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
        {
            status.Ok, status.State, status.Handshake, status.ServiceVersion, status.ConnectionId,
            status.Started, status.StageSince, status.RuntimePath, status.PathEpoch, status.Streams, status.TotalStreams,
            status.Rx, status.Tx, status.Effective,
            SystemRoutingActive = status.SystemRouting?.Active == true,
            VPNFlows = status.SystemRouting?.VPNFlows,
            DNSErrors = status.SystemRouting?.DNSErrors
        }));
        if (!status.Ok) Environment.ExitCode = 1;
    }
    catch (Exception error) when (error is IOException or OperationCanceledException or System.Text.Json.JsonException)
    {
        Console.WriteLine("{\"Ok\":false,\"Error\":\"STATUS_UNAVAILABLE\"}");
        Environment.ExitCode = 1;
    }
    return;
}

if(args.Length==1&&args[0]=="--check-policy-network"){await PolicyNetworkChecks.Run();return;}
TransportChecks.Policy();
await AppRulesChecks.Run();
await PreparationChecks.Run();
if(args.Length==1&&args[0]=="--check-enrollment-engine"){await EnrollmentChecks.Run(true);return;}
await EnrollmentChecks.Run();
if(args.Length==1&&args[0]=="--check-managed-engine"){await ManagedChecks.Run(true);return;}
await ManagedChecks.Run();
if(args.Length==1&&args[0]=="--check-system-routing-engine"){
    await AppRulesChecks.Run(true);
    var settings=new SystemRoutingSettings{Enabled=true};var result=await SystemRoutingCheck.Run(settings,"youtube.com");
    if(result.Active||result.NetworkChanged||result.Decision?.Action!="vpn"||!result.RuntimeIntegrated||result.Policy.Rules.Count!=0)throw new Exception("System routing preview contract failed");
    var custom=await SystemRoutingCheck.Run(settings with{Rules=[new("blocked.example.com","block",true)]},"sub.blocked.example.com");
    if(custom.Decision?.Action!="block")throw new Exception("System domain exception lost across C#/Go boundary");
    var country=await SystemRoutingCheck.Run(settings,"unlisted.example.com","77.88.55.55");var foreign=await SystemRoutingCheck.Run(settings,"unlisted.example.com","8.8.8.8");
    if(country.GeoIP is not{Valid:true,Release:"2026-11",IPv4Prefixes:12902}||country.Decision?.Action!="direct"||foreign.Decision?.Action!="vpn")throw new Exception("GeoIP provenance/decision mismatch across C#/Go boundary");
    Console.WriteLine("PASS: C#→Go routing+DB-IP provenance/IPv4 country decisions, preset/BLOCK priority; active=false/networkChanged=false; no service/network setup");return;
}
if(CoreJournal.Format(new(1,0,"info","SYNTHETIC_PRIVATE")) is not null||CoreJournal.Format(new(1,0,"info","TURN_READY",2))?.Contains("поток 3")!=true)throw new Exception("Journal privacy/stream mapping failed");
if(ClosePolicy.Decide(true,false,true,true,false,false,false)!=CloseAction.Ignore||ClosePolicy.Decide(true,false,true,true,false,false,true)!=CloseAction.Hide||ClosePolicy.Decide(true,false,true,true,false,true,false)!=CloseAction.ConfirmExit||ClosePolicy.Decide(true,true,true,true,false,true,true)!=CloseAction.Wait)throw new Exception("Close request could interrupt active VPN");

if(args.Length==4&&args[0]=="--ssh-loopback"){
    var result=await SshProbe.Check(new FreeTurn.Windows.Models.SshConfig{Ip="127.0.0.1",Port=int.Parse(args[1]),Username="ftm-synthetic",Password="SYNTHETIC_PASSWORD",HostFingerprint=args[2]=="none"?"":args[2]});
    if(result.State!=args[3])throw new Exception("SSH loopback state incorrect");Console.WriteLine("PASS: SSH "+result.State);return;
}

var root=Path.Combine(Path.GetTempPath(),"ftm-catalog-check-"+Guid.NewGuid().ToString("N"));
try{
    var diagnosticReply=new ServiceReply(true,null,"error",true,null,false,0,0,null,false,Stage:"SYNTHETIC_PRIVATE",DiagnosticError:"SYNTHETIC_PRIVATE",FailureStage:"turn_connect");
    var diagnosticText=ConnectionDiagnostics.Detail(diagnosticReply);if(diagnosticText.Contains("SYNTHETIC_PRIVATE")||!diagnosticText.Contains("TURN"))throw new Exception("Diagnostic output leaked an unknown code or lost safe stage");
    var now=DateTimeOffset.UtcNow;var intent=new ReconnectPolicy();if(intent.TryBegin(now))throw new Exception("Reconnect without explicit intent");intent.Started(now);if(intent.TryBegin(now))throw new Exception("Reconnect ignored backoff");for(var attempt=1;attempt<=5;attempt++)if(!intent.TryBegin(now.AddMinutes(attempt))||intent.Attempts!=attempt)throw new Exception("Reconnect attempt budget incorrect");if(intent.TryBegin(now.AddHours(1)))throw new Exception("Reconnect budget unlimited");intent.Stop();if(intent.TryBegin(now.AddHours(2)))throw new Exception("Explicit stop did not cancel retry");
    var hostKey=Encoding.UTF8.GetBytes("SYNTHETIC_SSH_HOST_KEY");if(SshTrust.Matches("",hostKey)||!SshTrust.Matches(SshTrust.Fingerprint(hostKey),hostKey)||SshTrust.Matches(SshTrust.Fingerprint(hostKey),Encoding.UTF8.GetBytes("DIFFERENT")))throw new Exception("SSH trust policy accepted unknown/changed key");
    if(LoginStartup.Command(@"C:\Program Files\FreeTurn\FreeTurn.Windows.exe")!="\"C:\\Program Files\\FreeTurn\\FreeTurn.Windows.exe\" --start-hidden")throw new Exception("Startup command quoting incorrect");
    var plain=Encoding.UTF8.GetBytes("SYNTHETIC_BACKUP_KEYS_Не терять");var password="SYNTHETIC_Пароль🔒";
    var envelope=BackupCrypto.Encrypt(plain,password);
    var independent=Encoding.UTF8.GetBytes("""{"magic":"freeturn-backup","v":1,"kdf":"pbkdf2-sha256","iter":210000,"salt":"AAECAwQFBgcICQoLDA0ODw==","iv":"EBESExQVFhcYGRob","ct":"gefMRRD01f+HcBFSTNa7zPUGRWMnwjrAs+faR/+ipDEZjXgxNzzxVwJ/o+98CrUih5AxUjCsdA=="}""");
    if(!BackupCrypto.Decrypt(independent,password).SequenceEqual(plain))throw new Exception("Independent UTF-8/PBKDF2/AES-GCM vector failed");
    if(!BackupCrypto.Decrypt(envelope,password).SequenceEqual(plain)||Encoding.UTF8.GetString(envelope).Contains("SYNTHETIC_BACKUP_KEYS"))throw new Exception("Encrypted backup roundtrip failed");
    foreach(var wrong in new[]{"wrong",password+"x"}){var denied=false;try{_ = BackupCrypto.Decrypt(envelope,wrong);}catch(IOException){denied=true;}if(!denied)throw new Exception("Wrong password accepted");}
    var tampered=JsonNode.Parse(envelope)!.AsObject();var ciphertext=Convert.FromBase64String(tampered["ct"]!.GetValue<string>());ciphertext[0]^=1;tampered["ct"]=Convert.ToBase64String(ciphertext);
    var tagDenied=false;try{_ = BackupCrypto.Decrypt(Encoding.UTF8.GetBytes(tampered.ToJsonString()),password);}catch(IOException){tagDenied=true;}if(!tagDenied)throw new Exception("Unauthenticated backup accepted");
    var catalog=new ProfileCatalog(root);var secret="freeturn://SYNTHETIC_SECRET_DO_NOT_ECHO";
    var first=catalog.Add("Сервер",secret);catalog.SetAdvancedCaptcha(true);var copy=catalog.Clone(first.Id);
    if(copy.Id==first.Id||copy.Share!=secret||catalog.Read().Profiles.Count!=2)throw new Exception("Clone lost identity or connection data");
    catalog.Rename(copy.Id,"Копия");catalog.Select(copy.Id);
    if(new ProfileCatalog(root).Read().ActiveId!=copy.Id||!catalog.Read().AdvancedCaptcha)throw new Exception("Selection/settings were not persisted");
    var path=Path.Combine(root,"profiles.dpapi");var cipher=File.ReadAllBytes(path);
    if(Encoding.UTF8.GetString(cipher).Contains("SYNTHETIC_SECRET"))throw new Exception("Plaintext persisted");
    var original=new JsonObject{["v"]=1,["name"]="Исходный",["peer"]="203.0.113.1:5000",["vk"]="https://vk.com/call/join/SYNTHETIC",["key"]="SYNTHETIC_KEY",["cid"]="SYNTHETIC_CID",["wg"]="SYNTHETIC_WG_WITH_PSK\r\n",["extension"]=new JsonObject{["opaque"]="SYNTHETIC_EXTENSION"}};
    var originalShare=Encode(original.ToJsonString());var document=new ShareDocument(originalShare);
    var incoming=new ProfileSnapshot(1,null,new List<SavedProfile>{new(Guid.NewGuid(),"Восстановленный",originalShare)});
    var restored=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(incoming),password),password));
    var beforeRestore=catalog.Read();if(catalog.Merge(restored)!=1||catalog.Read().ActiveId!=beforeRestore.ActiveId||catalog.Merge(restored)!=0)throw new Exception("Backup merge lost selection or duplicated profiles");
    catalog.Delete(restored.Profiles[0].Id);
    var routing=new RoutingPolicy(1,[new("example.com","direct",true),new("login.example.com","vpn",false),new("blocked.example.com","block",true)]);
    var keysBeforeRouting=catalog.Read().Profiles.Select(p=>p.Share).ToArray();catalog.SetProxy(new SocksSettings(1080,"synthetic","SYNTHETIC_PASSWORD",routing));
    var routingBackup=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(catalog.Read()),password),password));
    if(routingBackup.LocalProxy?.Routing?.Rules.Count!=3||routingBackup.LocalProxy.Routing.Rules[0].Action!="direct"||!catalog.Read().Profiles.Select(p=>p.Share).SequenceEqual(keysBeforeRouting))throw new Exception("Routing backup lost rules or changed keys");
    var routeRestore=new ProfileCatalog(Path.Combine(root,"route-restore"));routeRestore.Merge(routingBackup with{Profiles=[],ActiveId=null},true);if(routeRestore.Read().LocalProxy?.Routing?.Rules.Count!=3)throw new Exception("Preference restore lost routing rules");
    if(catalog.Read().SystemRouting?.Enabled==true)throw new Exception("Legacy catalog enabled new routing");
    var systemRouting=new SystemRoutingSettings{Enabled=true,Rules=routing.Rules};catalog.SetSystemRouting(systemRouting);
    var systemBackup=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(catalog.Read()),password),password));
    if(systemBackup.SystemRouting is not{Enabled:true}||systemBackup.SystemRouting.Rules.Count!=3||systemBackup.SystemRouting.DirectDNS[0]!="77.88.8.8"||!catalog.Read().Profiles.Select(p=>p.Share).SequenceEqual(keysBeforeRouting))throw new Exception("System routing backup changed keys or lost settings");
    routeRestore.Merge(systemBackup with{Profiles=[],ActiveId=null},false);if(routeRestore.Read().SystemRouting is not null)throw new Exception("Import silently changed routing preferences");
    routeRestore.Merge(systemBackup with{Profiles=[],ActiveId=null},true);if(routeRestore.Read().SystemRouting?.Enabled!=true)throw new Exception("Preference restore lost system routing");
    var beforeInvalidSettings=File.ReadAllBytes(path);try{catalog.SetSystemRouting(systemRouting with{DirectDNS=["https://example.com"]});throw new Exception("Invalid routing accepted");}catch(IOException){}if(!File.ReadAllBytes(path).SequenceEqual(beforeInvalidSettings))throw new Exception("Invalid settings overwrote catalog");
    var androidSource=new JsonObject{["v"]=4,["ownClientId"]=new string('b',32),["servers"]=new JsonArray(new JsonObject{["id"]=Guid.NewGuid().ToString(),["name"]="Android synthetic",["ssh"]=new JsonObject{["password"]="SYNTHETIC_SSH_DO_NOT_LOSE"},["client"]=new JsonObject{["provider"]="vk",["serverAddress"]="203.0.113.1:5000",["wireGuardConfig"]="SYNTHETIC_ANDROID_WG",["tunnelTransport"]="wireguard",["callLink"]="https://vk.com/call/join/SYNTHETIC"},["opts"]=new JsonObject{["obfKey"]="SYNTHETIC_ANDROID_OBF"}})};
    var androidBackup=CatalogBackup.Decode(Encoding.UTF8.GetBytes(androidSource.ToJsonString()));var androidLink=Decode(androidBackup.Profiles.Single().Share);
    if(androidLink["cid"]!.GetValue<string>()!=new string('b',32)||androidLink["wg"]!.GetValue<string>()!="SYNTHETIC_ANDROID_WG"||androidBackup.AndroidArchive!=androidSource.ToJsonString())throw new Exception("Android import changed identity or lost SSH/source fields");
    androidSource["servers"]![0]!["client"]!["tunnelTransport"]="none";var noTunnel=CatalogBackup.Decode(Encoding.UTF8.GetBytes(androidSource.ToJsonString()));if(new ShareDocument(noTunnel.Profiles.Single().Share).WireGuard!=""||!noTunnel.AndroidArchive!.Contains("SYNTHETIC_ANDROID_WG"))throw new Exception("Inactive Android WG unexpectedly enabled or keys lost");
    var archiveCatalog=new ProfileCatalog(Path.Combine(root,"archive-history"));archiveCatalog.Merge(androidBackup);archiveCatalog.Merge(noTunnel);var archived=archiveCatalog.Read();if(archived.AndroidArchive!=noTunnel.AndroidArchive||archived.AndroidArchiveHistory?.Single()!=androidBackup.AndroidArchive)throw new Exception("Second Android import lost an original archive");var archivePayload=CatalogBackup.Decode(CatalogBackup.Encode(archived));if(archivePayload.AndroidArchiveHistory?.Single()!=androidBackup.AndroidArchive)throw new Exception("Backup lost archive history");
    var mergeBefore=File.ReadAllBytes(path);var invalidIncoming=restored with{Profiles=new List<SavedProfile>{restored.Profiles[0] with{Share="freeturn://INVALID"}}};var mergeRejected=false;try{catalog.Merge(invalidIncoming);}catch(IOException){mergeRejected=true;}if(!mergeRejected||!File.ReadAllBytes(path).SequenceEqual(mergeBefore))throw new Exception("Invalid restore changed catalog");
    var edited=document.Build(document.Values with{Name="Изменённый",Peer="203.0.113.2:5000",DnsMode="doh",DnsServers="https://example.net/dns-query"});
    var editedObject=Decode(edited);
    foreach(var field in new[]{"key","cid","wg","extension"})if(!JsonNode.DeepEquals(original[field],editedObject[field]))throw new Exception("Editor lost opaque connection data");
    if(editedObject["name"]!.GetValue<string>()!="Изменённый"||editedObject["peer"]!.GetValue<string>()!="203.0.113.2:5000")throw new Exception("Editor did not apply fields");
    if(new ShareDocument(document.Build(document.Values with{Name="Проверка"},"EXPLICIT_SYNTHETIC_WG")).WireGuard!="EXPLICIT_SYNTHETIC_WG")throw new Exception("Explicit WireGuard edit lost");
    foreach(var invalid in new[]{"{\"v\":1,\"V\":1}","{\"v\":1,\"extension\":{\"x\":1,\"X\":2}}"}){
        var refused=false;try{_ = new ShareDocument(Encode(invalid));}catch(IOException e){refused=e.Message=="PROFILE_DOCUMENT_INVALID";}
        if(!refused)throw new Exception("Ambiguous profile accepted");
    }
    catalog.Replace(copy.Id,"Изменённый",edited);
    var replaced=catalog.Read();if(replaced.ActiveId!=copy.Id||replaced.Profiles.Single(p=>p.Id==copy.Id).Share!=edited||replaced.Profiles.Single(p=>p.Id==first.Id).Share!=secret)throw new Exception("Selected edit lost selection; next Connect would import null and use old SYSTEM profile");
    catalog.Select(copy.Id);catalog.Replace(first.Id,"Другой",originalShare);
    if(catalog.Read().ActiveId!=copy.Id)throw new Exception("Editing inactive entry changed selection");
    catalog.Delete(first.Id);if(catalog.Read().Profiles.Single().Share!=edited)throw new Exception("Delete changed other keys");
    cipher=File.ReadAllBytes(path);cipher[0]^=1;File.WriteAllBytes(path,cipher);
    var rejected=false;try{catalog.Add("Новый",secret);}catch(IOException){rejected=true;}
    if(!rejected||!File.ReadAllBytes(path).SequenceEqual(cipher))throw new Exception("Damaged catalog overwritten");
    Console.WriteLine("PASS: AES-GCM password/tamper refusal, backup merge/retry, routing backup/key isolation, DPAPI catalog, clone/edit key preservation, duplicate refusal, edit selection preservation, delete isolation, corruption refusal");
}finally{
    var absolute=Path.GetFullPath(root);if(!absolute.StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase))throw new Exception("Unsafe cleanup path");
    if(Directory.Exists(absolute))Directory.Delete(absolute,true);
}
static string Encode(string json)=>"freeturn://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+','-').Replace('/','_');
static JsonObject Decode(string share){var value=share["freeturn://".Length..].Replace('-','+').Replace('_','/');return JsonNode.Parse(Convert.FromBase64String(value.PadRight((value.Length+3)/4*4,'=')))!.AsObject();}
