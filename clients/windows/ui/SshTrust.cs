using System.IO;
using System.Security.Cryptography;
using FreeTurn.Windows.Models;
namespace FreeTurn.Windows;
internal static class SshTrust
{
    internal static string Fingerprint(byte[] hostKey)=>"SHA256:"+Convert.ToBase64String(SHA256.HashData(hostKey)).TrimEnd('=');
    internal static bool Matches(string expected,byte[] hostKey)=>expected.Length>0&&string.Equals(expected,Fingerprint(hostKey),StringComparison.Ordinal);
    internal static void Validate(SshConfig config)
    {
        if(config.Ip.Length>255||config.Ip.Any(char.IsWhiteSpace)||config.Ip.Any(char.IsControl)||config.Ip.Length>0&&Uri.CheckHostName(config.Ip)==UriHostNameType.Unknown||config.Port is <1 or >65535||string.IsNullOrWhiteSpace(config.Username)||config.Username.Length>128||config.Username.Any(char.IsControl)||config.Password.Length>4096||config.SshKey.Length>128*1024||config.SudoPassword.Length>4096||config.AuthType is not ("PASSWORD" or "SSH_KEY"))throw new IOException("SSH_SETTINGS_INVALID");
        if(config.HostFingerprint.Length>0){if(!config.HostFingerprint.StartsWith("SHA256:",StringComparison.Ordinal))throw new IOException("SSH_FINGERPRINT_INVALID");try{var b64=config.HostFingerprint[7..];var bytes=Convert.FromBase64String(b64.PadRight((b64.Length+3)/4*4,'='));if(bytes.Length!=32||Convert.ToBase64String(bytes).TrimEnd('=')!=b64)throw new IOException();}catch{throw new IOException("SSH_FINGERPRINT_INVALID");}}
    }
}
