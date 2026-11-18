using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;

namespace FreeTurn.Windows;
internal sealed class TrayController : IDisposable
{
    private const uint Callback=0x8001;
    private readonly Window owner;
    private readonly HwndSource source;
    private readonly uint taskbarCreated=RegisterWindowMessage("TaskbarCreated");
    private bool added;
    private readonly IntPtr appIcon;
    private readonly bool ownIcon;
    internal bool ExitRequested{get;private set;}
    internal bool Available=>added;
    internal TrayController(Window owner,Func<bool,Task> connection)
    {
        this.owner=owner;source=HwndSource.FromHwnd(new WindowInteropHelper(owner).Handle);source.AddHook(Hook);
        if(ExtractIconEx(Environment.ProcessPath!,0,out var large,out var small,1)>0){appIcon=small!=IntPtr.Zero?small:large;ownIcon=appIcon!=IntPtr.Zero;if(large!=IntPtr.Zero&&large!=appIcon)DestroyIcon(large);}
        if(appIcon==IntPtr.Zero)appIcon=LoadIcon(IntPtr.Zero,(IntPtr)32512);
        this.connection=connection;Add();
    }
    private readonly Func<bool,Task> connection;
    private NotifyData Data()=>new(){Size=(uint)Marshal.SizeOf<NotifyData>(),Window=source.Handle,Id=1,Flags=1|2|4,Callback=Callback,Icon=appIcon,Tip="FreeTurn — открыть приложение",Info="",Title=""};
    private void Add(){var data=Data();added=Shell_NotifyIcon(0,ref data);if(!added&&!owner.IsVisible)Show();}
    internal void Show(){owner.Show();owner.WindowState=WindowState.Normal;owner.Activate();}
    private IntPtr Hook(IntPtr hwnd,int msg,IntPtr wParam,IntPtr lParam,ref bool handled)
    {
        if(msg==taskbarCreated){Add();return IntPtr.Zero;}
        if(msg!=Callback)return IntPtr.Zero;
        var action=(uint)lParam.ToInt64()&0xffff;
        if(action==0x202||action==0x203){Show();handled=true;}
        if(action==0x205){
            var menu=new ContextMenu{Placement=PlacementMode.MousePoint};
            void Item(string label,Action action){var item=new MenuItem{Header=label};item.Click+=(_,_)=>action();menu.Items.Add(item);}
            Item("Открыть FreeTurn",Show);Item("Подключить",async()=>{Show();await connection(true);});Item("Отключить",async()=>{Show();await connection(false);});
            menu.Items.Add(new Separator());Item("Выйти",()=>{ExitRequested=true;owner.Close();ExitRequested=false;});
            SetForegroundWindow(source.Handle);menu.IsOpen=true;handled=true;
        }
        return IntPtr.Zero;
    }
    public void Dispose(){if(added){var data=Data();Shell_NotifyIcon(2,ref data);added=false;}source.RemoveHook(Hook);if(ownIcon)DestroyIcon(appIcon);}
    [DllImport("shell32.dll",CharSet=CharSet.Unicode)]private static extern uint ExtractIconEx(string file,int index,out IntPtr large,out IntPtr small,uint count);
    [DllImport("user32.dll")]private static extern bool DestroyIcon(IntPtr icon);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct NotifyData
    {
        public uint Size;public IntPtr Window;public uint Id,Flags,Callback;public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)]public string Tip;
        public uint State,StateMask;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Info;
        public uint Version;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)]public string Title;
        public uint InfoFlags;public Guid Guid;public IntPtr BalloonIcon;
    }
    [DllImport("shell32.dll",CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)]private static extern bool Shell_NotifyIcon(uint operation,ref NotifyData data);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]private static extern IntPtr LoadIcon(IntPtr instance,IntPtr name);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]private static extern uint RegisterWindowMessage(string name);
    [DllImport("user32.dll")]private static extern bool SetForegroundWindow(IntPtr hwnd);
}
