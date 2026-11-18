using System.Windows;
using System.Windows.Controls;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace FreeTurn.Windows;

internal sealed class CaptchaWindow : Border
{
    // The composition host's GraphicsItemD3DImage finalizer crashed the UI.
    // Keep the browser in this window using the HWND host, without D3D capture.
    private readonly WebView2 view = new();
    private readonly Window owner;
    private readonly string browserFolder;
    private bool disposed;
    private string current = "";
    private bool manualPresentation;
    private Task? initialization;
    internal bool Completed;
    internal event Action? Cancelled;

    internal CaptchaWindow(Window owner, bool manual,string? browserFolder=null)
    {
        this.owner=owner;this.browserFolder=browserFolder??System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FreeTurnManager", "WebView2");Background=UiTheme.Background;
        var content=new DockPanel();var header=new StackPanel{Margin=new Thickness(16)};header.Children.Add(AndroidSkin.Text("Проверка VK",24));
        var cancel=new Button{Content="Отменить подключение",Padding=new Thickness(12,8,12,8),Margin=new Thickness(0,12,0,0)};cancel.Click+=(_,_)=>Close();header.Children.Add(cancel);DockPanel.SetDock(header,Dock.Top);content.Children.Add(header);content.Children.Add(view);Child=content;Present(manual);
    }

    internal void Close()
    {
        if(disposed)return;disposed=true;
        try{view.CoreWebView2?.CookieManager.DeleteAllCookies();}catch{}
        try{view.Dispose();}
        finally{if(Parent is Panel panel)panel.Children.Remove(this);Child=null;}
        if(!Completed)Cancelled?.Invoke();
    }

    internal static bool Local(string raw) => Uri.TryCreate(raw, UriKind.Absolute, out var u) &&
        u.Scheme == "http" && u.Port == 8765 && u.UserInfo.Length == 0 &&
        (u.Host == "127.0.0.1" || u.Host == "localhost" || u.Host == "[::1]") && raw.Length < 8192;

    internal async Task Navigate(string address, bool manual)
    {
        if (!Local(address)) throw new InvalidOperationException("INVALID_CAPTCHA_URL");
        if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
        Present(manual);
        if (current == address) return;
        await EnsureBrowser().WaitAsync(TimeSpan.FromSeconds(20));
        if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
        current = address;
        (view.CoreWebView2 ?? throw new InvalidOperationException("WEBVIEW_UNAVAILABLE")).Navigate(address);
    }

    private Task EnsureBrowser()=>initialization??=InitializeBrowser();

    private async Task InitializeBrowser()
    {
        if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
        if (view.CoreWebView2 is null)
        {
            var environment = await CoreWebView2Environment.CreateAsync(null, browserFolder);
            if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
            var options = environment.CreateCoreWebView2ControllerOptions();
            options.IsInPrivateModeEnabled = true;
            await view.EnsureCoreWebView2Async(environment, options);
            if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
            var web = view.CoreWebView2 ?? throw new InvalidOperationException("WEBVIEW_UNAVAILABLE");
            web.Settings.AreDevToolsEnabled = false;
            web.Settings.AreHostObjectsAllowed = false;
            web.Settings.AreDefaultContextMenusEnabled = false;
            web.Settings.IsWebMessageEnabled = false;
            web.Settings.IsPasswordAutosaveEnabled = false;
            web.Settings.IsGeneralAutofillEnabled = false;
            web.NewWindowRequested += (_, e) => e.Handled = true;
            web.DownloadStarting += (_, e) => e.Cancel = true;
            web.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
            web.NavigationStarting += (_, e) => { if (!Local(e.Uri) && e.Uri != "about:blank") e.Cancel = true; };
            await web.Profile.ClearBrowsingDataAsync(CoreWebView2BrowsingDataKinds.Cookies);
            if(disposed)throw new ObjectDisposedException(nameof(CaptchaWindow));
        }
    }

    // Developer-only local HTML scenario. No VK request or connection attempt.
    internal async Task CheckLocalBrowser()
    {
        await EnsureBrowser().WaitAsync(TimeSpan.FromSeconds(15));var web=view.CoreWebView2!;
        var loaded=new TaskCompletionSource<CoreWebView2NavigationCompletedEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Loaded(object? sender,CoreWebView2NavigationCompletedEventArgs e)=>loaded.TrySetResult(e);
        web.NavigationCompleted+=Loaded;
        try{
            web.Navigate("about:blank");
            var completed=await loaded.Task.WaitAsync(TimeSpan.FromSeconds(12));
            if(!completed.IsSuccess)throw new InvalidOperationException("LOCAL_WEBVIEW_FAILED_"+completed.WebErrorStatus);
            var result=await web.ExecuteScriptAsync("document.body.textContent='Локальная проверка'; document.body.textContent.includes('Локальная') && !!crypto.getRandomValues(new Uint8Array(16))");
            if(result!="true"||Opacity!=0||IsHitTestVisible||view.IsVisible)throw new InvalidOperationException("AUTO_WEBVIEW_FAILED");
            await web.ExecuteScriptAsync("window.ftmTimerProbe=0; setTimeout(()=>window.ftmTimerProbe=1,25)");
            var timer="0";
            for(var i=0;i<20&&timer!="1";i++){await Task.Delay(100);timer=await web.ExecuteScriptAsync("window.ftmTimerProbe");}
            if(timer!="1")throw new InvalidOperationException("HIDDEN_WEBVIEW_TIMER_FAILED");
            Present(true);if(Opacity!=1||!IsHitTestVisible||!view.IsVisible)throw new InvalidOperationException("MANUAL_WEBVIEW_FAILED");
        }finally{web.NavigationCompleted-=Loaded;}
    }

    // HWND content ignores WPF opacity. Hidden keeps automatic JS alive while
    // explicitly hiding the native child; manual CAPTCHA uses this same host.
    private void Present(bool manual)
    {
        var reveal=manual&&!manualPresentation;manualPresentation=manual;
        Opacity=manual?1:0;IsHitTestVisible=manual;
        view.Visibility=manual?Visibility.Visible:Visibility.Hidden;
        if(reveal){owner.Show();owner.Activate();}
    }
}
