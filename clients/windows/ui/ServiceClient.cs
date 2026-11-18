using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace FreeTurn.Windows;

internal sealed record ServiceReply(bool Ok, string? Error, string State, bool HasProfile,
    string? Transport, bool Handshake, ulong Rx, ulong Tx, string? Captcha, bool Manual, string[]? Capabilities = null, ulong CaptchaId = 0,long Started=0,int Streams=0,int TotalStreams=0,string? Kind=null,string? Listen=null,int SocksPort=0,string? Stage=null,long StageSince=0,long LastProgress=0,string? DiagnosticError=null,bool TunnelActive=false,string? ServiceVersion=null,string? FailureStage=null,uint ServiceWin32Code=0,uint ServiceSpecificCode=0,CoreEvent[]? Events=null,ulong EventSession=0,SystemRoutingReport? SystemRouting=null,string? ConfiguredProfileIdentity=null,string? RuntimeProfileIdentity=null,ulong ConnectionId=0,ulong LastAttemptId=0,bool AutoPaths=false,string? RuntimePath=null,ulong PathEpoch=0,bool PathPending=false,EffectiveSettings? Effective=null);

internal static class ServiceClient
{
    private const string Pipe = @"\\.\pipe\FreeTurnManager.v1";
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    internal static Task<ServiceReply> Send(string operation,string? profile=null,bool? advancedCaptcha=null)=>SendCore(operation,profile,advancedCaptcha,null);
    internal static Task<ServiceReply> StartSocks(SocksSettings settings)=>SendCore("socks-start",null,null,settings);
    internal static Task<ServiceReply> Connect(bool? advancedCaptcha,SystemRoutingSettings? routing,bool autoPaths=false,bool forceManualCaptcha=false)=>SendCore("connect",null,advancedCaptcha,null,routing,autoPaths:autoPaths,forceManualCaptcha:forceManualCaptcha);
    internal static Task<ServiceReply> RecoverCurrent(RuntimeLease lease,string share)=>SendCore("recover-if-current",share,null,null,expected:lease);
    internal static Task<ServiceReply> ChangePath(RuntimeLease lease,string path)=>SendCore("switch-path-if-current",null,null,null,expected:lease,path:path);
    internal static Task<ServiceReply> RecoverPath(RuntimeLease lease,string share,string? path)=>SendCore("recover-if-current",share,null,null,expected:lease,recoveryPath:path);
    internal static Task<ServiceReply> DisconnectCurrent(RuntimeLease lease)=>SendCore("disconnect-if-current",null,null,null,expected:lease);
    internal static Task<ServiceReply> ReconnectNetwork(RuntimeLease expected)=>SendCore("network-reconnect-if-current",null,null,null,expected:expected);
    private static async Task<ServiceReply> SendCore(string operation, string? profile, bool? advancedCaptcha,SocksSettings? socks,SystemRoutingSettings? routing=null,RuntimeLease? expected=null,bool? autoPaths=null,string? path=null,string? recoveryPath=null,bool? forceManualCaptcha=null)
    {
        // A local pipe can be impersonated before the service starts. Authenticate
        // its server against SCM + the protected installation path BEFORE secrets.
        // Do not open the SYSTEM process: its process DACL may deny even query
        // access to the normal desktop user. SCM query rights suffice here.
        using var handle = CreateFile(Pipe, 0x80000002, 0, IntPtr.Zero, 3, 0x40000000 | 0x00100000, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException("SERVICE_UNAVAILABLE");
        VerifyServer(handle);
        using var stream = new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(48));
        var request = new Dictionary<string, object> { ["v"] = 1, ["op"] = operation };
        if(expected is not null){if(operation is not ("disconnect-if-current" or "recover-if-current" or "switch-path-if-current" or "network-reconnect-if-current")||!ProfileIdentity.Valid(expected.Identity)||expected.Attempt==0)throw new IOException("CONNECTION_CHANGED");request["expectedProfile"]=expected.Identity;request["expectedAttempt"]=expected.Attempt;request["expectedEpoch"]=expected.PathEpoch;}
        if(forceManualCaptcha==true)request["forceManualCaptcha"]=true;
        if(autoPaths==true)request["autoPaths"]=true;
        if(path is not null)request["path"]=path;
        if(recoveryPath is not null)request["recoveryPath"]=recoveryPath;
        if (profile is not null) request["profile"] = profile;
        if (advancedCaptcha.HasValue) request["advancedCaptcha"] = advancedCaptcha.Value;
        if(routing?.Enabled==true){if(operation!="connect"||!routing.Valid)throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");request["systemRouting"]=routing;}
        if(socks is not null){var proxy=new Dictionary<string,object>{["port"]=socks.Port,["user"]=socks.User,["password"]=socks.Password};if(socks.Routing?.Rules.Count>0)proxy["routing"]=socks.Routing;request["socks"]=proxy;}
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request) + "\n");
        if (bytes.Length > 512 * 1024) throw new IOException("PROFILE_TOO_LARGE");
        await stream.WriteAsync(bytes, timeout.Token);
        await stream.FlushAsync(timeout.Token);
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), false, 4096, true);
        var chars = new char[1024]; var line = new StringBuilder();
        while (line.Length < 64 * 1024)
        {
            var count=await reader.ReadAsync(chars.AsMemory(0,Math.Min(chars.Length,64*1024-line.Length)),timeout.Token);
            if(count==0)throw new IOException("SERVICE_CLOSED");
            var newline=Array.IndexOf(chars,'\n',0,count);
            if(newline>=0){line.Append(chars,0,newline);return JsonSerializer.Deserialize<ServiceReply>(line.ToString(),Json)??throw new IOException("INVALID_REPLY");}
            line.Append(chars,0,count);
        }
        throw new IOException("REPLY_TOO_LARGE");
    }

    private static void VerifyServer(SafePipeHandle pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe, out var pid)) throw new IOException("UNTRUSTED_PIPE");
        if (!GetNamedPipeServerSessionId(pipe, out var session) || session != 0) throw new IOException("UNTRUSTED_PIPE");
        var scm = OpenSCManager(null, null, 1);
        if (scm == IntPtr.Zero) throw new IOException("SCM_UNAVAILABLE");
        try
        {
            // SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG. No control rights.
            var service = OpenService(scm, "FreeTurnManager", 4 | 1);
            if (service == IntPtr.Zero) throw new IOException("SERVICE_UNAVAILABLE");
            try
            {
                if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _) || status.Pid != pid || status.State != 4)
                    throw new IOException("UNTRUSTED_PIPE");
                VerifyConfiguration(service);
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void VerifyConfiguration(IntPtr service)
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FreeTurnManager", "FreeTurn.Engine.exe");
        QueryServiceConfig(service, IntPtr.Zero, 0, out var size);
        if (size < Marshal.SizeOf<ServiceConfiguration>() || size > 65536) throw new IOException("UNTRUSTED_PIPE");
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!QueryServiceConfig(service, buffer, size, out _)) throw new IOException("UNTRUSTED_PIPE");
            var config = Marshal.PtrToStructure<ServiceConfiguration>(buffer);
            if (config.Type != 0x10 || !string.Equals(Marshal.PtrToStringUni(config.Account), "LocalSystem", StringComparison.OrdinalIgnoreCase))
                throw new IOException("UNTRUSTED_PIPE");
            var command = Marshal.PtrToStringUni(config.Binary) ?? throw new IOException("UNTRUSTED_PIPE");
            var argv = CommandLineToArgv(command, out var count);
            if (argv == IntPtr.Zero) throw new IOException("UNTRUSTED_PIPE");
            try
            {
                if (count != 2 || !string.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)), expected, StringComparison.OrdinalIgnoreCase) ||
                    Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, IntPtr.Size)) != "--broker")
                    throw new IOException("UNTRUSTED_PIPE");
            }
            finally { LocalFree(argv); }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    { public uint Type, State, Accepts, Exit, SpecificExit, Checkpoint, WaitHint, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfiguration
    { public uint Type, Start, Error; public IntPtr Binary, Group; public uint Tag; public IntPtr Dependencies, Account, DisplayName; }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafePipeHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out uint session);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, EntryPoint="CommandLineToArgvW", SetLastError=true)] private static extern IntPtr CommandLineToArgv(string command, out int count);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll")] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int required);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="QueryServiceConfigW", SetLastError=true)] private static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint size, out uint required);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
