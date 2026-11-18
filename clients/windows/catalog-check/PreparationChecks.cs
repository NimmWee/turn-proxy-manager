using System.IO;
using FreeTurn.Windows;

internal static class PreparationChecks
{
    internal static async Task Run()
    {
        ServiceReply Ready(string version="0.8.0",bool active=false)=>new(true,null,active?"connected":"stopped",true,null,false,0,0,null,false,Capabilities:["connection-stages-v1","socket-protection-v2"],TunnelActive:active,ServiceVersion:version);
        foreach(var scenario in new[]{"current","old","missing","cancel","failed","newer","untrusted","active","retry","badAfterSetup","rootOnly"}){
            var calls=new List<string>();var upgraded=false;
            var actions=new ServicePreparation.Actions(
                ()=>{calls.Add("status");if(scenario=="untrusted")throw new IOException("UNTRUSTED_PIPE");if(scenario=="missing"&&!upgraded)throw new IOException("SERVICE_UNAVAILABLE");return Task.FromResult(Ready(scenario=="newer"?"99.0.0":(scenario is "old" or "cancel" or "failed" or "retry" or "badAfterSetup")&&(!upgraded||scenario=="badAfterSetup")?"0.7.0":"0.8.0",scenario=="active"));},
                ()=>{calls.Add("setup");if(scenario=="cancel")throw new IOException("SETUP_CANCELLED");if(scenario=="failed")throw new IOException("SETUP_ROLLED_BACK");upgraded=true;return Task.CompletedTask;},
                share=>{if(share!="SYNTHETIC_PRIVATE")throw new Exception("Profile changed");calls.Add("import");return Task.CompletedTask;},
                advanced=>{calls.Add("connect");return Task.CompletedTask;});
            string? error=null;
            try{await ServicePreparation.Connect(new Version(0,8,0),scenario=="rootOnly"?null:"SYNTHETIC_PRIVATE",false,scenario!="retry",actions,_=>{});}catch(IOException e){error=e.Message;}
            if(scenario is "current" or "old" or "missing" or "rootOnly"){
                if(error!=null||calls.Last()!="connect")throw new Exception("Preparation did not continue "+scenario);
                if(calls.Count(c=>c=="setup")!=(scenario is "old" or "missing"?1:0))throw new Exception("Unnecessary/missing setup "+scenario);
                if(scenario!="rootOnly"&&calls.IndexOf("import")>calls.IndexOf("connect"))throw new Exception("Connect before import");
                if(scenario=="rootOnly"&&calls.Contains("import"))throw new Exception("Replaced SYSTEM-only profile");
            }else{
                if(error==null||calls.Contains("import")||calls.Contains("connect"))throw new Exception("Unsafe continuation "+scenario);
                if((scenario is "newer" or "untrusted" or "active" or "retry")&&calls.Contains("setup"))throw new Exception("Unsafe elevation "+scenario);
            }
        }
        Console.WriteLine("PASS: service preparation ordering, update once, UAC/failure refusal, authenticated recheck, active/newer/untrusted/retry guards, SYSTEM-only profile preserved (synthetic callbacks)");
    }
}
