using System.Diagnostics;
using System.Windows;
using System.Windows.Interop;
namespace FreeTurn.Windows;
internal sealed class CloseRequestTracker:IDisposable
{
    private readonly HwndSource source;private long explicitAt;
    internal CloseRequestTracker(Window window){source=HwndSource.FromHwnd(new WindowInteropHelper(window).Handle);source.AddHook(Hook);}
    private IntPtr Hook(IntPtr h,int message,IntPtr w,IntPtr l,ref bool handled){if(message==0x112&&(w.ToInt64()&0xfff0)==0xf060)explicitAt=Stopwatch.GetTimestamp();return IntPtr.Zero;}
    internal bool Consume(){var at=explicitAt;explicitAt=0;return at!=0&&Stopwatch.GetElapsedTime(at)<TimeSpan.FromSeconds(2);}
    public void Dispose()=>source.RemoveHook(Hook);
}
