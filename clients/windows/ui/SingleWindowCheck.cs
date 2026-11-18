using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace FreeTurn.Windows;

// Explicit local developer scenario: synthetic catalog; no service/setup/VPN.
internal static class SingleWindowCheck
{
    internal static async Task Run(MainWindow shell,ProfileCatalog catalog,SavedProfile profile)
    {
        var initial=Application.Current.Windows.Count;
        await shell.CheckUnexpectedClose();
        await CheckSavedSettings(shell,catalog);
        await CheckApplicationRules(shell);
        var pages=new InAppPage[]{
            new ServersWindow(shell,catalog,_=>Task.CompletedTask,MainWindow.Validate,true),
            new ProfileEditor(shell,profile,MainWindow.Validate),new BackupWindow(shell,catalog,true),
            new SshWindow(shell,catalog,profile,true),new SocksWindow(shell,catalog,true),
            new SystemRoutingWindow(shell,catalog,true),
            new ApplicationRulesWindow(shell,[new(@"C:\Apps\Browser.exe","vpn"),new(@"C:\Apps\Chat.exe","direct")],_=>{},preview:true),
            new ManagedWindow(shell,catalog,profile with{Managed=new("11111111-2222-3333-4444-555555555555","m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=","https://8.8.8.8","10.77.43.1","ftmb1_"+new string('A',43),DateTimeOffset.UtcNow.AddMinutes(20).ToString("O"),"ftmd1_"+new string('B',43))},true),
            new ManagedWindow(shell,catalog,App.ManagedPreview(profile),true),
            new ManagedWindow(shell,catalog,profile with{Managed=new("11111111-2222-3333-4444-555555555555","m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=","https://8.8.8.8","10.77.43.1","ftmb1_"+new string('A',43),"2020-01-01T00:00:00Z","ftmd1_"+new string('B',43))},true),
            new EnrollmentWindow(shell,catalog,null,true),
            new EnrollmentWindow(shell,catalog,new EnrollmentLink(1,"ftm-enrollment","https://8.8.8.8","ftmu1_"+new string('A',43)),true),
            new RoutingWindow(shell,new(1,[new("example.com","direct",true)]),_=>{},true)};
        foreach(var page in pages){
            var done=page.OpenAsync();await Task.Delay(160);shell.UpdateLayout();
            if(done.IsCompleted||Application.Current.Windows.Cast<Window>().Count(w=>w.IsVisible)!=1||!ReferenceEquals(page.DialogOwner,shell))throw new IOException("EMBEDDED_PAGE_OPEN_FAILED");
            if(page is ServersWindow)Capture(shell,"preview-single-window-servers.png");
            if(page is RoutingWindow)Capture(shell,"preview-single-window-routing.png");
            if(page is ApplicationRulesWindow){Capture(shell,"preview-single-window-app-rules.png");Descendants<ScrollViewer>((FrameworkElement)shell.Content).First(s=>s.Content is StackPanel panel&&panel.Children.OfType<TextBox>().Any()).ScrollToBottom();shell.UpdateLayout();Capture(shell,"preview-single-window-app-rules-bottom.png");}
            if(page is ManagedWindow)Capture(shell,"preview-single-window-managed.png");
            if(page is ManagedWindow&&Descendants<Button>((FrameworkElement)shell.Content).Any(b=>b.Content as string=="Проверить восстановление"))Capture(shell,"preview-single-window-claim-recovery.png");
            if(page is EnrollmentWindow)Capture(shell,"preview-single-window-enrollment.png");
            page.Close();if(await done!=false)throw new IOException("EMBEDDED_PAGE_RETURN_FAILED");
        }
        var parent=new InAppPage{Owner=shell,Content=new TextBlock{Text="Родительская страница"}};
        var parentTask=parent.OpenAsync();
        var child=new InAppPage{Owner=parent,Content=new TextBlock{Text="Вложенная страница"}};
        var childTask=child.OpenAsync();var locked=true;child.CanLeave=()=>!locked;
        child.Close();if(childTask.IsCompleted)throw new IOException("BUSY_PAGE_CLOSED");
        locked=false;child.DialogResult=true;if(await childTask!=true||parentTask.IsCompleted)throw new IOException("NESTED_PAGE_RESULT_FAILED");
        parent.Close();await parentTask;
        var browserFolder=Path.Combine(Path.GetTempPath(),"ftm-browser-check-"+Guid.NewGuid().ToString("N"));
        var browser=new CaptchaWindow(shell,false,browserFolder);shell.AttachCaptcha(browser);
        try{await browser.CheckLocalBrowser();if(Application.Current.Windows.Cast<Window>().Count(w=>w.IsVisible)!=1)throw new IOException("CAPTCHA_OPENED_WINDOW");}
        finally{browser.Completed=true;browser.Close();}
        // All hidden Window adapters must be released as well as their content.
        if(Application.Current.Windows.Count!=initial||Application.Current.Windows.Cast<Window>().Count(w=>w.IsVisible)!=1)throw new IOException("EMBEDDED_PAGE_LEAK");
        Capture(shell,"preview-single-window-home.png");
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T:DependencyObject
    {
        for(var i=0;i<VisualTreeHelper.GetChildrenCount(root);i++){var child=VisualTreeHelper.GetChild(root,i);if(child is T match)yield return match;foreach(var nested in Descendants<T>(child))yield return nested;}
    }
    private static void Click(FrameworkElement root,string text)
    {
        var button=Descendants<Button>(root).Single(b=>b.Content is string label?label==text:b.Content is DependencyObject content&&Descendants<TextBlock>(content).Any(t=>t.Text==text));
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    }
    private static async Task CheckSavedSettings(MainWindow shell,ProfileCatalog catalog)
    {
        var before=catalog.Read().Profiles.Single();var original=new ShareDocument(before.Share);
        var page=new ServersWindow(shell,catalog,_=>Task.CompletedTask,_=>Task.CompletedTask);
        var done=page.OpenAsync();await Task.Delay(160);shell.UpdateLayout();var root=(FrameworkElement)shell.Content;
        Click(root,"Параметры");await Task.Delay(160);shell.UpdateLayout();
        var streams=Descendants<TextBox>(root).Single(t=>System.Windows.Automation.AutomationProperties.GetName(t)=="Количество потоков");streams.Text="64";
        Click(root,"Сохранить");await Task.Delay(40);
        if(catalog.Read().Profiles.Single().Share!=before.Share||!Descendants<TextBlock>(root).Any(t=>t.Text.StartsWith("Не сохранено.")))throw new IOException("INVALID_SETTINGS_SILENTLY_SAVED");
        streams.Text="10";
        Click(root,"Сохранить");
        for(var n=0;n<40&&new ShareDocument(catalog.Read().Profiles.Single().Share).Values.Streams!=10;n++)await Task.Delay(25);
        var after=catalog.Read();var edited=after.Profiles.Single();
        if(after.ActiveId!=before.Id||new ShareDocument(edited.Share).Values.Streams!=10||new ShareDocument(edited.Share).WireGuard!=original.WireGuard)throw new IOException("EDITOR_SAVE_SETTINGS_LOST");
        page.Close();await done;
    }
    private static async Task CheckApplicationRules(MainWindow shell)
    {
        List<SystemAppRule>? saved=null;var page=new ApplicationRulesWindow(shell,[],items=>saved=items,_=>Task.CompletedTask);var done=page.OpenAsync();
        await Task.Delay(120);shell.UpdateLayout();var root=(FrameworkElement)shell.Content;
        var path=Descendants<TextBox>(root).Single(t=>System.Windows.Automation.AutomationProperties.GetName(t)=="Путь приложения");path.Text="browser.exe";Click(root,"Добавить правило");
        if(Descendants<ListBox>(root).Single().Items.Count!=0||saved is not null)throw new IOException("INVALID_APP_SELECTOR_SAVED");
        path.Text=@"C:\Apps\Browser.exe";Descendants<ComboBox>(root).Single().SelectedIndex=1;Click(root,"Добавить правило");shell.UpdateLayout();
        if(!Descendants<TextBlock>(root).Any(t=>t.Text.Contains("Browser.exe")&&t.Text.Contains("Напрямую")))throw new IOException("APP_RULE_LABEL_MISSING");Click(root,"Готово");
        if(await done!=true||saved is not[{Path:@"C:\Apps\Browser.exe",Action:"direct"}])throw new IOException("APP_EDITOR_DRAFT_LOST");
    }
    private static void Capture(MainWindow shell,string name)
    {
        shell.UpdateLayout();var content=(FrameworkElement)shell.Content;
        DependencyObject? hit=VisualTreeHelper.HitTest(content,new Point(content.ActualWidth/2,content.ActualHeight-40))?.VisualHit;
        while(hit is not null&&hit is not BottomNavigation)hit=VisualTreeHelper.GetParent(hit);
        if(hit is not BottomNavigation)throw new IOException("BOTTOM_NAVIGATION_OBSCURED");
        var bitmap=new RenderTargetBitmap((int)content.ActualWidth,(int)content.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(content);
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using var output=File.Create(Path.Combine(AppContext.BaseDirectory,name));encoder.Save(output);
    }
}
