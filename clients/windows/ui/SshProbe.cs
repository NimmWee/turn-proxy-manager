using System.IO;
using System.Text;
using FreeTurn.Windows.Models;
using Renci.SshNet;
namespace FreeTurn.Windows;
internal sealed record SshProbeResult(string State,string? Fingerprint=null);
internal static class SshProbe
{
    internal static async Task<SshProbeResult> Check(SshConfig config)
    {
        SshTrust.Validate(config);if(config.Ip.Length==0)return new("invalid");
        string? seen=null;
        try{
            using var keyBytes=new MemoryStream(Encoding.UTF8.GetBytes(config.SshKey));
            using var privateKey=config.AuthType=="SSH_KEY"?new PrivateKeyFile(keyBytes,config.Password):null;
            AuthenticationMethod authentication=config.AuthType=="SSH_KEY"?new PrivateKeyAuthenticationMethod(config.Username,privateKey!):new PasswordAuthenticationMethod(config.Username,config.Password);
            using var client=new SshClient(new ConnectionInfo(config.Ip,config.Port,config.Username,authentication){Timeout=TimeSpan.FromSeconds(12)});
            client.HostKeyReceived+=(_,e)=>{seen=SshTrust.Fingerprint(e.HostKey);e.CanTrust=SshTrust.Matches(config.HostFingerprint,e.HostKey);};
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(18));await client.ConnectAsync(timeout.Token);
            // Authentication check only: no shell, installer, sudo or VPN command.
            var authenticated=client.IsConnected;client.Disconnect();return new(authenticated?"authenticated":"failed");
        }catch{
            if(seen is not null&&!string.Equals(seen,config.HostFingerprint,StringComparison.Ordinal))return new(config.HostFingerprint.Length==0?"untrusted":"changed",seen);
            return new("failed");
        }
    }
}
