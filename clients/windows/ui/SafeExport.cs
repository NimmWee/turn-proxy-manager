using System.IO;
namespace FreeTurn.Windows;
internal static class SafeExport
{
    internal static void Write(string destination,byte[] data)
    {
        var path=Path.GetFullPath(destination);if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("EXPORT_INVALID");
        var temporary=Path.Combine(Path.GetDirectoryName(path)!,"."+Guid.NewGuid().ToString("N")+".tmp");
        try{using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(data);stream.Flush(true);}File.Move(temporary,path,true);}
        finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
}
