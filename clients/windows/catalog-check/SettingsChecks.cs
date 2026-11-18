using System.Diagnostics;
using System.IO;
using System.Text.Json;
using FreeTurn.Windows;

internal static class SettingsChecks
{
 internal static async Task Run(ProfileCatalog catalog,SavedProfile fixture,bool engine)
 {
  var p=catalog.Add("Synthetic settings",fixture.Share,true);var doc=new ShareDocument(p.Share);
  var edited=doc.Build(doc.Values with{Name="Edited settings",Streams=10,StreamsPerCredential=4,Transport="udp",DnsMode="doh",DnsServers="https://1.1.1.1/dns-query",ManualCaptcha=true,Timing=17});
  catalog.Replace(p.Id,"Edited settings",edited,p.Share);
  var selected=ProfileSelection.ForConnect(catalog.Read())??throw new Exception("Edited selection lost");
  if(selected.Id!=p.Id||selected.Share!=edited||new ShareDocument(selected.Share).WireGuard!=doc.WireGuard)throw new Exception("Save lost selected edit/keys");
  var imported="";var calls=0;var version=new Version(0,18,0);
  var status=new ServiceReply(true,null,"stopped",true,null,false,0,0,null,false,["connection-stages-v1","socket-protection-v2"],ServiceVersion:"0.18.0");
  await ServicePreparation.Connect(version,selected.Share,false,false,new(()=>Task.FromResult(status),()=>throw new Exception("Unexpected setup"),share=>{imported=share;return Task.CompletedTask;},_=>{if(imported!=edited)throw new Exception("Old SYSTEM profile used");calls++;return Task.CompletedTask;}),_=>{});
  if(calls!=1)throw new Exception("Edit did not reach Connect");
  var blocked=false;try{ProfileSelection.ForConnect(catalog.Read() with{ActiveId=null});}catch(IOException){blocked=true;}if(!blocked||ProfileSelection.ForConnect(new(1,null,[]))is not null)throw new Exception("Unsafe legacy fallback or lost service-only compatibility");
  blocked=false;try{catalog.Replace(p.Id,"Stale",p.Share,p.Share);}catch(IOException){blocked=true;}if(!blocked||catalog.Read().Profiles.Single().Share!=edited)throw new Exception("Stale edit overwrote current keys/config");
  catalog.SetForceManualCaptcha(true);var backup=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));if(!backup.ForceManualCaptcha)throw new Exception("Backup lost manual mode");
  catalog.Merge(backup with{ForceManualCaptcha=false});if(!catalog.Read().ForceManualCaptcha)throw new Exception("Merge changed CAPTCHA mode");
  catalog.Merge(backup with{ForceManualCaptcha=false},true);if(catalog.Read().ForceManualCaptcha)throw new Exception("Explicit restore ignored CAPTCHA mode");
  if(engine){
   using var process=new Process{StartInfo=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe"),"--inspect-profile"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
   process.Start();var output=process.StandardOutput.ReadToEndAsync();var errors=process.StandardError.ReadToEndAsync();await process.StandardInput.WriteAsync(imported);process.StandardInput.Close();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
   try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill();throw;}
   var raw=await output;await errors;using var result=JsonDocument.Parse(raw);
   var parsed=result.RootElement.GetProperty("settings").Deserialize<EffectiveSettings>(new JsonSerializerOptions{PropertyNameCaseInsensitive=true});
   if(process.ExitCode!=0||parsed is not{Valid:true,RequestedStreams:10,StreamLimit:10,StreamsPerCredential:4,Transport:"udp",DnsMode:"doh",ManualCaptcha:true,WireGuardMTU:1280})throw new Exception("Edited parameters did not reach actual Go renderer");
   foreach(var secret in new[]{"PrivateKey","PresharedKey","clientId","call/join","obfKey"})if(raw.Contains(secret,StringComparison.OrdinalIgnoreCase))throw new Exception("Inspection exposed private fields");
  }
  Console.WriteLine(engine?"PASS: selected edit10/4→DPAPI→Connect import→actual Go effective renderer, key preservation/stale edit/selection refusal/manual backup; real VPN NOT RUN":"PASS: selected edit→DPAPI→synthetic Connect import, key preservation/stale edit/selection refusal/manual backup; real VPN NOT RUN");
  var awgWG=doc.WireGuard.Replace("[Interface]\n","[Interface]\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nH1 = 101\nH2 = 102\nH3 = 103\nH4 = 104\n",StringComparison.Ordinal);
  var awg=doc.Build(doc.Values with{Name="Synthetic AWG",Streams=8},awgWG);
  catalog.Replace(p.Id,"Synthetic AWG",awg,edited);
  var awgDoc=new ShareDocument(catalog.Read().Profiles.Single().Share);
  if(!awgDoc.IsAmneziaWG||awgDoc.WireGuard!=awgWG||awgDoc.Values.Streams!=8)throw new Exception("AWG editor/DPAPI dropped parameters or keys");
  const string password="SYNTHETIC_AWG_BACKUP_PASSWORD";
  var restored=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(catalog.Read()),password),password));
  if(new ShareDocument(restored.Profiles.Single().Share).WireGuard!=awgWG||restored.SystemRouting?.Enabled==true)throw new Exception("AWG backup changed parameters or auto-enabled backend");
  if(engine){
   using var process=new Process{StartInfo=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe"),"--inspect-profile"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
   process.Start();var output=process.StandardOutput.ReadToEndAsync();var errors=process.StandardError.ReadToEndAsync();await process.StandardInput.WriteAsync(awg);process.StandardInput.Close();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
   try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill();throw;}
   var raw=await output;await errors;using var result=JsonDocument.Parse(raw);var parsed=result.RootElement.GetProperty("settings").Deserialize<EffectiveSettings>(new JsonSerializerOptions{PropertyNameCaseInsensitive=true});
   if(process.ExitCode!=0||parsed is not{Valid:true,VPNProtocol:"amneziawg1",RequestedStreams:8,WireGuardMTU:1280})throw new Exception("AWG C#/Go protocol or effective settings mismatch");
   if(raw.Contains("101")||raw.Contains("PrivateKey")||raw.Contains("SYNTHETIC"))throw new Exception("AWG inspection exposed configuration");
  }
  Console.WriteLine("PASS: AWG1 edit→DPAPI→encrypted backup keeps original keys/extensions; backend not auto-enabled"+(engine?"; actual Go import/protocol inspection PASS":"")+"; real AWG VPN NOT RUN");
  var headerKey=Convert.ToBase64String(Enumerable.Repeat((byte)4,32).ToArray());
  var awg3WG=doc.WireGuard.Replace("[Interface]\n","[Interface]\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 100-109\nH2 = 200-209\nH3 = 300-309\nH4 = 400-409\nI1 = <b 0xd1><r 8>\nHeaderProtectionKey = "+headerKey+"\nContentPaddingAddition = 4-12\nRandomTrailers = on\n",StringComparison.Ordinal);
  var awg3=doc.Build(doc.Values with{Name="Synthetic AWG3",Streams=9},awg3WG);
  catalog.Replace(p.Id,"Synthetic AWG3",awg3,awg);
  var restored3=CatalogBackup.Decode(BackupCrypto.Decrypt(BackupCrypto.Encrypt(CatalogBackup.Encode(catalog.Read()),password),password));
  if(!new ShareDocument(awg3).IsAmneziaWG||new ShareDocument(restored3.Profiles.Single().Share).WireGuard!=awg3WG||restored3.SystemRouting?.Enabled==true)throw new Exception("AWG3 editor/backup changed private fields or backend selection");
  if(engine){
   using var process=new Process{StartInfo=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"FreeTurn.Engine.exe"),"--inspect-profile"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
   process.Start();var output=process.StandardOutput.ReadToEndAsync();var errors=process.StandardError.ReadToEndAsync();await process.StandardInput.WriteAsync(awg3);process.StandardInput.Close();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
   try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill();throw;}
   var raw=await output;await errors;using var result=JsonDocument.Parse(raw);var parsed=result.RootElement.GetProperty("settings").Deserialize<EffectiveSettings>(new JsonSerializerOptions{PropertyNameCaseInsensitive=true});
   if(process.ExitCode!=0||parsed is not{Valid:true,VPNProtocol:"amneziawg3",RequestedStreams:9}||raw.Contains(headerKey)||raw.Contains("HeaderProtectionKey")||raw.Contains("0xd1"))throw new Exception("AWG3 protocol inspection failed or exposed private parameters");
  }
  Console.WriteLine("PASS: AWG3 ranges/CPS/header key edit→DPAPI→encrypted backup preserved, no implicit backend"+(engine?"; actual Go protocol inspection redacted":"")+"; real AWG VPN NOT RUN");
 }
}
