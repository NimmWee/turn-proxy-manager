using System.Windows;

namespace FreeTurn.Windows;

internal sealed class App : Application
{
    [STAThread]
    public static void Main(string[] args)
    {
        var app = new App();
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("Theme.xaml",UriKind.Relative) });
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("NavigationIcons.xaml",UriKind.Relative) });
        var development=args.Any(a=>a.StartsWith("--snapshot",StringComparison.Ordinal)||a.StartsWith("--preview",StringComparison.Ordinal)||a is "--check-desktop-ui" or "--check-single-window" or "--check-captcha-lifetime");
        if(development)UiTheme.Light=args.Length>0&&args[0].EndsWith("-light",StringComparison.Ordinal);else try{UiTheme.Light=new ProfileCatalog().Read().LightTheme;}catch{UiTheme.Light=false;}
        UiTheme.Configure(app);
        if(args.Length is 2 or 3&&args[0] is "--snapshot-system-routing" or "--snapshot-system-routing-light" or "--snapshot-managed" or "--snapshot-managed-light" or "--snapshot-enrollment" or "--snapshot-enrollment-light"){
            // Pure component render: no native window, real catalog, SCM or
            // loaded handler. This cannot install/start a VPN or alter routes.
            var folder=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"ftm-render-"+Guid.NewGuid().ToString("N"));
            InAppPage page=args[0].StartsWith("--snapshot-enrollment",StringComparison.Ordinal)?new EnrollmentWindow(null,new ProfileCatalog(folder),new EnrollmentLink(1,"ftm-enrollment","https://8.8.8.8","ftmu1_"+new string('A',43)),true):args[0].StartsWith("--snapshot-managed",StringComparison.Ordinal)?new ManagedWindow(null,new ProfileCatalog(folder),ManagedPreview(SyntheticProfile()),true):new SystemRoutingWindow(null,new ProfileCatalog(folder),true);
            var content=(FrameworkElement)page.Content;page.Content=null;
            content.Width=420;content.Height=740;content.Measure(new Size(420,740));content.Arrange(new Rect(0,0,420,740));content.UpdateLayout();
            if(args.Length==3&&args[2]=="--bottom"){if(content is System.Windows.Controls.DockPanel dock)dock.Children.OfType<System.Windows.Controls.ScrollViewer>().Single().ScrollToBottom();else if(content is System.Windows.Controls.ScrollViewer scroll)scroll.ScrollToBottom();content.UpdateLayout();}
            var bitmap=new System.Windows.Media.Imaging.RenderTargetBitmap(420,740,96,96,System.Windows.Media.PixelFormats.Pbgra32);bitmap.Render(content);
            var encoder=new System.Windows.Media.Imaging.PngBitmapEncoder();encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using(var output=System.IO.File.Create(System.IO.Path.GetFullPath(args[1])))encoder.Save(output);page.Close();return;
        }
        app.DispatcherUnhandledException += (_, e) =>
        {
            e.Handled = true;
            MessageBox.Show("Действие завершилось ошибкой. Проверьте состояние службы перед повтором.", "FreeTurn", MessageBoxButton.OK, MessageBoxImage.Warning);
        };
        if(args.Length==1&&args[0]=="--check-captcha-lifetime"){
            var shell=new MainWindow(true);shell.ContentRendered+=async(_,_)=>{var passed=false;string? checkError=null;try{await CaptchaLifetimeCheck.Run(shell);passed=true;}catch(Exception e){checkError=e.GetType().Name+": "+e.Message;}finally{Environment.ExitCode=passed?0:1;System.IO.File.WriteAllText(System.IO.Path.Combine(AppContext.BaseDirectory,"captcha-lifetime-check.json"),System.Text.Json.JsonSerializer.Serialize(new{CaptchaLifetime=passed,CheckError=checkError,Cycles=12,ForcedGC=true,Synthetic=true,ServicesUsed=false,NetworkChanged=false,VKE2E="NOT RUN"}));app.Shutdown();}};app.Run(shell);return;
        }
        if(args.Length==1&&args[0]=="--check-single-window"){
            var folder=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"ftm-flow-check-"+Guid.NewGuid().ToString("N"));var catalog=new ProfileCatalog(folder);var profile=SyntheticProfile();catalog.Add(profile.Name,profile.Share,true);
            var shell=new MainWindow(true);shell.ContentRendered+=async(_,_)=>{var passed=false;string? checkError=null;try{await SingleWindowCheck.Run(shell,catalog,profile);passed=true;}catch(Exception e){checkError=e.GetType().Name+": "+e.Message;passed=false;}finally{Environment.ExitCode=passed?0:1;System.IO.File.WriteAllText(System.IO.Path.Combine(AppContext.BaseDirectory,"single-window-check.json"),System.Text.Json.JsonSerializer.Serialize(new{SingleWindowFlow=passed,CheckError=checkError,Synthetic=true,ServicesUsed=false,NetworkChanged=false,CaptchaE2E="NOT RUN"}));app.Shutdown();if(System.IO.Directory.Exists(folder))System.IO.Directory.Delete(folder,true);}};app.Run(shell);return;
        }
        if(args.Length==1&&args[0]=="--check-desktop-ui"){
            var typeface=new System.Windows.Media.Typeface(UiTheme.Font,FontStyles.Normal,FontWeights.Normal,FontStretches.Normal);var fontReady=typeface.TryGetGlyphTypeface(out var glyph)&&glyph.FontUri.OriginalString.Contains("Roboto",StringComparison.OrdinalIgnoreCase)&&glyph.CharacterToGlyphMap.ContainsKey(0x0416);
            var checkWindow=new Window{Title="FreeTurn — локальная проверка трея",Width=420,Height=600,Content=new System.Windows.Controls.TextBlock{Text="Проверка окна и трея. Службы и сеть не используются.",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(24)}};
            checkWindow.ContentRendered+=async(_,_)=>{TrayController? tray=null;var passed=false;try{tray=new TrayController(checkWindow,_=>Task.CompletedTask);if(!tray.Available)throw new System.IO.IOException();checkWindow.Hide();await Task.Delay(100);tray.Show();passed=checkWindow.IsVisible&&checkWindow.WindowState==WindowState.Normal;}catch{passed=false;}finally{tray?.Dispose();Environment.ExitCode=passed&&fontReady?0:1;System.IO.File.WriteAllText(System.IO.Path.Combine(AppContext.BaseDirectory,"desktop-check.json"),System.Text.Json.JsonSerializer.Serialize(new{TrayRegisteredAndDisposed=passed,HideShow=passed,BundledRobotoCyrillic=fontReady,ServicesUsed=false,NetworkChanged=false}));checkWindow.Close();}};app.Run(checkWindow);return;
        }
        var compact=args.Contains("--compact");
        var preview=args.Length is 1 or 2&&(!compact||args.Length==2)&&new[]{"--snapshot","--snapshot-compact","--snapshot-add","--snapshot-settings","--snapshot-logs","--snapshot-share","--snapshot-editor","--snapshot-backup","--snapshot-ssh","--snapshot-socks","--snapshot-light","--snapshot-settings-light","--snapshot-editor-light","--snapshot-app","--snapshot-advanced","--snapshot-about","--snapshot-connected","--snapshot-busy","--snapshot-servers","--snapshot-routing","--snapshot-routing-light","--snapshot-progress","--snapshot-failed"}.Contains(args[0]);
        var previewPage=preview?args[0] switch{"--snapshot-logs"=>1,"--snapshot-share"=>2,"--snapshot-settings" or "--snapshot-settings-light"=>3,"--snapshot-add"=>4,"--snapshot-app"=>5,"--snapshot-advanced"=>6,"--snapshot-about"=>7,"--snapshot-connected"=>8,"--snapshot-busy"=>9,"--snapshot-progress"=>10,"--snapshot-failed"=>11,_=>0}:0;
        var interactivePreview=args.Length==1&&args[0]=="--preview";
        var routingPreview=args.Length==1&&args[0]=="--preview-routing";
        var developerView=preview||interactivePreview||args.Contains("--preview-editor")||routingPreview;
        var createdNew=true;using var instance=developerView?null:new Mutex(true,@"Local\FreeTurn.Windows.UI."+System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,out createdNew);
        if(!developerView&&!createdNew){MessageBox.Show("FreeTurn уже запущен. Откройте его значком в трее или на панели задач.","FreeTurn");return;}
        var editorPreview=preview&&args[0] is "--snapshot-editor" or "--snapshot-editor-light"||args.Length==1&&args[0]=="--preview-editor";
        var syntheticPath=System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetTempPath(),"ftm-preview-"+Guid.NewGuid().ToString("N")));
        var syntheticCatalog=new ProfileCatalog(syntheticPath);
        if(preview&&args[0]=="--snapshot-servers"){var profile=SyntheticProfile();syntheticCatalog.Add(profile.Name,profile.Share,true);}
        Window window = preview?args[0] switch{"--snapshot-routing" or "--snapshot-routing-light"=>new RoutingWindow(null,SyntheticRouting(),_=>{},true),"--snapshot-servers"=>new ServersWindow(null,syntheticCatalog,_=>Task.CompletedTask,FreeTurn.Windows.MainWindow.Validate,true),"--snapshot-backup"=>new BackupWindow(null,syntheticCatalog,true),"--snapshot-ssh"=>new SshWindow(null,syntheticCatalog,SyntheticProfile(),true),"--snapshot-socks"=>new SocksWindow(null,syntheticCatalog,true),"--snapshot-editor" or "--snapshot-editor-light"=>new ProfileEditor(null,SyntheticProfile(),FreeTurn.Windows.MainWindow.Validate),_=>new MainWindow(true,previewPage,args[0]=="--snapshot-compact"||compact)}:routingPreview?new RoutingWindow(null,SyntheticRouting(),_=>{}):editorPreview?new ProfileEditor(null,SyntheticProfile(),FreeTurn.Windows.MainWindow.Validate):new MainWindow(interactivePreview,startHidden:args.Length==1&&args[0]=="--start-hidden");
        if(preview&&compact)window.Width=420;
        if(editorPreview&&compact)window.Width=420;
        if(editorPreview)window.Title="Предпросмотр редактора — синтетический профиль";
        if (preview)
            window.ContentRendered += async (_, _) =>
            {
                await Task.Delay(350);
                window.UpdateLayout();
                var content = (FrameworkElement)window.Content;
                var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
                bitmap.Render(content);
                var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
                encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
                var stem=args[0]=="--snapshot"?"preview":args[0].Replace("--snapshot-","preview-");var name=stem+(compact?"-compact":"")+".png";
                using var output = System.IO.File.Create(System.IO.Path.Combine(AppContext.BaseDirectory, name));
                encoder.Save(output);
                window.Close();
            };
        try{app.Run(window);}
        finally
        {
            // Only this invocation's synthetic directory; never the user catalog.
            var tempRoot=System.IO.Path.GetFullPath(System.IO.Path.GetTempPath()).TrimEnd(System.IO.Path.DirectorySeparatorChar)+System.IO.Path.DirectorySeparatorChar;
            if(syntheticPath.StartsWith(tempRoot,StringComparison.OrdinalIgnoreCase)&&System.IO.Path.GetFileName(syntheticPath).StartsWith("ftm-preview-",StringComparison.Ordinal)&&System.IO.Directory.Exists(syntheticPath))
                try{System.IO.Directory.Delete(syntheticPath,true);}catch(System.IO.IOException){}catch(UnauthorizedAccessException){}
        }
    }
    // Only reserved documentation addresses and deterministic test keys. No user
    // catalog/service reads, writes or tunnel activation in this developer view.
    private static RoutingPolicy SyntheticRouting()=>new(1,[new("example.com","direct",true),new("login.example.com","vpn",false),new("blocked.example.com","block",true)]);
    private static SavedProfile SyntheticProfile()
    {
        var key=Convert.ToBase64String(Enumerable.Repeat((byte)1,32).ToArray());
        var node=new System.Text.Json.Nodes.JsonObject{["v"]=1,["name"]="Тестовый сервер",["provider"]="vk",["peer"]="203.0.113.1:5000",["mode"]="udp",["transport"]="tcp",["obf"]="rtpopus3",["key"]=new string('a',64),["cid"]=new string('b',32),["n"]=6,["spc"]=3,["vk"]="https://vk.com/call/join/SYNTHETIC",["wg"]=$"[Interface]\nPrivateKey = {key}\nAddress = 10.77.43.9/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = {key}\nPresharedKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n"};
        var share="freeturn://"+Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(node.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
        return new(Guid.NewGuid(),"Тестовый сервер",share);
    }
    internal static SavedProfile ManagedPreview(SavedProfile profile)
    {
        var config=new ManagedConfig("{}",profile.Share,"\""+new string('a',64)+"\"",3);
        return profile with{Managed=new("11111111-2222-3333-4444-555555555555","m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=","https://8.8.8.8","10.77.43.1",null,"2020-01-01T00:00:00Z","ftmd1_"+new string('B',43),Registered:true,Pending:config,PreviousShare:profile.Share,SeenRevision:3)};
    }
}
