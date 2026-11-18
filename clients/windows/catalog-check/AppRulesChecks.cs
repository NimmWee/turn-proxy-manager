using System.IO;
using System.Text.Json;
using FreeTurn.Windows;

internal static class AppRulesChecks
{
 internal static async Task Run(bool engine=false)
 {
  var original=new SystemRoutingSettings{Enabled=true,AppRules=[new(@"C:\Apps\Browser.exe","direct"),new(@"C:\Apps\Blocked.exe","block")]};
  if(!original.Valid||original.AppRules.Any(r=>r.ToString().Contains("C:")))throw new Exception("Application rule validation/redaction failed");
  foreach(var path in new[]{"app.exe",@"\\server\share\app.exe",@"C:\Apps\*.exe",@"C:\Apps\app.exe:stream",@"C:\Apps\..\app.exe"})if(new SystemAppRule(path,"direct").Valid)throw new Exception("Unsafe selector accepted");
  if((original with{AppRules=[new(@"C:\Apps\Browser.exe","vpn"),new(@"c:\apps\browser.EXE","direct")]}).Valid)throw new Exception("Duplicate app selector accepted");
  var legacy=JsonSerializer.Serialize(new SystemRoutingSettings());if(legacy.Contains("appRules"))throw new Exception("Empty app policy changed old backup shape");
  var root=Path.Combine(Path.GetTempPath(),"ftm-app-rules-"+Guid.NewGuid().ToString("N"));
  try{
   var catalog=new ProfileCatalog(root);catalog.SetSystemRouting(original);
   var restored=CatalogBackup.Decode(CatalogBackup.Encode(catalog.Read()));
   if(!restored.SystemRouting!.AppRules!.SequenceEqual(original.AppRules!)||File.ReadAllText(Path.Combine(root,"profiles.dpapi")).Contains("Browser.exe"))throw new Exception("DPAPI/backup lost or exposed application rules");
   if(engine){
    var direct=await SystemRoutingCheck.Run(original,"unknown.example.com","1.1.1.1",@"c:\apps\browser.EXE");
    var block=await SystemRoutingCheck.Run(original,"unknown.example.com","1.1.1.1",@"C:\Apps\Blocked.exe");
    var protectedAPI=await SystemRoutingCheck.Run(original,"unknown.example.com","10.77.43.1",@"C:\Apps\Browser.exe");
    if(direct.Decision?.Action!="direct"||block.Decision?.Action!="block"||protectedAPI.Decision?.Action!="vpn"||direct.Active||direct.NetworkChanged)throw new Exception("Actual app policy bridge failed");
   }
  }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
  Console.WriteLine(engine?"PASS: DPAPI/backup app rules + actual Go path/priority/inactive preview; native app/TUN E2E NOT RUN":"PASS: application rule validation/redaction, omitted empty legacy shape and DPAPI/backup preservation");
 }
}
