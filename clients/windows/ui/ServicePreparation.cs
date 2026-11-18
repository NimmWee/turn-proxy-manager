using System.IO;

namespace FreeTurn.Windows;

// The desktop owns intent; the existing elevated setup owns system mutations.
// No downloads, arbitrary broker commands, or background elevation.
internal static class ServicePreparation
{
    internal sealed record Actions(Func<Task<ServiceReply>> Status,Func<Task> Setup,Func<string,Task> Import,Func<bool?,Task> Connect);

    internal static async Task Connect(Version expected,string? selectedProfile,bool advanced,bool allowSetup,Actions actions,Action<string> progress)
    {
        progress("Проверяем готовность…");
        ServiceReply? service=null;
        try{service=await actions.Status();}
        catch(IOException e) when(e.Message=="SERVICE_UNAVAILABLE"){}
        if(service is not null)CheckIdle(service);
        var needsSetup=service is null||NeedsSetup(service,expected);
        if(needsSetup){
            if(!allowSetup)throw new IOException("SERVICE_UPDATE_ON_CONNECT");
            progress(service is null?"Подготавливаем FreeTurn…":"Обновляем сетевое ядро…");
            await actions.Setup();
            // SCM Running may precede the authenticated pipe being ready.
            for(var attempt=0;;attempt++){
                try{service=await actions.Status();break;}
                catch(IOException e) when(e.Message=="SERVICE_UNAVAILABLE"&&attempt<24){await Task.Delay(200);}
            }
            CheckIdle(service);
            if(NeedsSetup(service,expected))throw new IOException("SERVICE_VERSION_MISMATCH");
        }
        if(service is null)throw new IOException("SERVICE_UNAVAILABLE");
        if(selectedProfile is not null){progress("Применяем выбранный сервер…");await actions.Import(selectedProfile);}
        else if(!service.HasProfile)throw new IOException("PROFILE_NOT_SELECTED");
        progress("Подключаемся…");
        await actions.Connect(advanced?true:null);
    }

    internal static bool NeedsSetup(ServiceReply service,Version expected)
    {
        if(string.IsNullOrEmpty(service.ServiceVersion))return true; // Legacy broker.
        if(!Version.TryParse(service.ServiceVersion,out var actual)||actual.Build<0)throw new IOException("SERVICE_VERSION_INVALID");
        actual=new Version(actual.Major,actual.Minor,actual.Build);
        expected=new Version(expected.Major,expected.Minor,Math.Max(0,expected.Build));
        if(actual>expected)throw new IOException("CLIENT_OLDER_THAN_SERVICE");
        if(actual<expected)return true;
        if(service.Capabilities?.Contains("connection-stages-v1")!=true||service.Capabilities?.Contains("socket-protection-v2")!=true)throw new IOException("SERVICE_VERSION_MISMATCH");
        return false;
    }

    private static void CheckIdle(ServiceReply service)
    {
        if(!service.Ok)throw new IOException(service.Error??"STATUS_FAILED");
        if(service.TunnelActive||service.State is not ("stopped" or "error"))throw new IOException("SETUP_STOP_FIRST");
    }
}
