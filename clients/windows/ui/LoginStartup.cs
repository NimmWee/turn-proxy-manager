using System.IO;
using Microsoft.Win32;
namespace FreeTurn.Windows;
internal static class LoginStartup
{
    private const string Key=@"Software\Microsoft\Windows\CurrentVersion\Run",Name="FreeTurnManagerUI";
    internal static string Command(string path)
    {
        if(!Path.IsPathFullyQualified(path)||path.Contains('"')||path.Any(char.IsControl)||!path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new IOException("STARTUP_PATH_INVALID");
        return "\""+path+"\" --start-hidden";
    }
    internal static bool Enabled(string executable){using var key=Registry.CurrentUser.OpenSubKey(Key);return string.Equals(key?.GetValue(Name) as string,Command(executable),StringComparison.OrdinalIgnoreCase);}
    internal static void Set(bool enabled,string executable)
    {
        var command=Command(executable);using var key=Registry.CurrentUser.CreateSubKey(Key,true);var old=key.GetValue(Name) as string;
        // Never overwrite/remove an entry belonging to another install path.
        if(old is not null&&!string.Equals(old,command,StringComparison.OrdinalIgnoreCase))throw new IOException("STARTUP_OTHER_INSTALL");
        if(enabled)key.SetValue(Name,command,RegistryValueKind.String);else if(old is not null)key.DeleteValue(Name,false);
    }
}
