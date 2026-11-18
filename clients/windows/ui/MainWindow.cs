// SPDX-License-Identifier: GPL-3.0-only
// Layout/palette adapted from FreeTurn Android 5.3.4; see THIRD_PARTY.md.
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace FreeTurn.Windows;

internal sealed class MainWindow : Window
{
    private readonly TextBlock state = Text("Служба ещё не установлена", 24, "#F4F7FC");
    private readonly TextBlock detail = Text("Импортируйте профиль FreeTurn для подключения.", 14, "#A4B3C8");
    private readonly TextBlock counters = Text("WireGuard: —     FreeTurn: —     Получено: 0 Б", 13, "#A4B3C8");
    private readonly TextBlock effective=Text("",12,"#A4B3C8");
    private EffectiveSettings? lastEffectiveSettings;
    private readonly TextBlock notice = Text("", 13, "#9DC7FF");
    private readonly TextBox input = new() { Height=86, AcceptsReturn=true, TextWrapping=TextWrapping.Wrap, MaxLength=96*1024, IsUndoEnabled=false, VerticalScrollBarVisibility=ScrollBarVisibility.Auto, Padding=new Thickness(12), FontSize=13 };
    private readonly CheckBox auto = new() { Content="Использовать штатную автоматическую CAPTCHA с ручным резервом", IsChecked=true, Foreground=Brush("#BAC8DA"), Margin=new Thickness(0,12,0,8) };
    private readonly ExpressivePower connect = new();
    private readonly TextBlock primaryLabel=AndroidSkin.Text("Подключить",14);
    private readonly EmbeddedPageHost embedded;
    private readonly Grid shellBody;
    private Action goHome=()=>{},openAdd=()=>{},openServers=()=>{};
    internal Task<bool?> OpenPage(InAppPage page){if(busy||closing||managedRecovery.Busy||transport.Busy){page.Close();notice.Text="Дождитесь завершения текущей операции подключения.";return Task.FromResult<bool?>(false);}transport.Cancel();managedRecovery.Cancel();managedSync.Cancel();return embedded.Push(page);}
    internal void AttachCaptcha(CaptchaWindow browser){Panel.SetZIndex(browser,100);shellBody.Children.Add(browser);}
    internal async Task CheckUnexpectedClose(){if(!designPreview)throw new InvalidOperationException();lastState="starting";tunnelActive=true;Close();await Task.Delay(50);if(!IsVisible||!notice.Text.Contains("отклонён"))throw new InvalidOperationException("UNSOLICITED_CLOSE_INTERRUPTED");lastState="stopped";tunnelActive=false;}
    private readonly Button disconnect = Button("Отключить", "#303C50");
    private readonly Button import = Button("Добавить сервер", "#303C50");
    private readonly Button setup = Button("Установить службу…", "#303C50");
    private readonly CheckBox advanced = new(){Content="Продвинутое решение CAPTCHA",IsChecked=false,Foreground=Brush("#C4C6D0"),Margin=new Thickness(0,12,0,8)};
    private readonly ProfileCatalog catalog = new();
    private readonly ManagedSync managedSync;
    private readonly ManagedRecovery managedRecovery;
    private readonly TransportManager transport;
    private readonly CheckBox autoTransport=new(){Content="Автоматически выбирать Direct / Relay",Foreground=UiTheme.Foreground};
    private readonly CheckBox sync=new(){Content="Проверять обновления управляемого профиля",Foreground=UiTheme.Foreground};
    private bool advancedSupported;
    private bool extendedTransportsSupported;
    private readonly bool designPreview;
    private readonly int designPage;
    private readonly DispatcherTimer timer = new() { Interval=TimeSpan.FromSeconds(3) };
    private readonly DispatcherTimer displayClock = new(){Interval=TimeSpan.FromMilliseconds(250)};
    private ServiceReply? latestReply;
    private CaptchaWindow? captcha;
    private ulong captchaId;
    private readonly ConnectionPages pages;
    private readonly TextBlock serverName=AndroidSkin.Text("Выберите сервер",22),serverAddress=AndroidSkin.Text("Подключения",14,true),uptime=AndroidSkin.Text("",14,true);
    private Border trafficCard=null!;
    private bool rootHasProfile;
    private TrayController? tray;
    private CloseRequestTracker? closeRequests;
    private readonly CheckBox closeToTray=new(){Content="Закрывать окно в трей",Foreground=Brush("#C4C6D0"),Margin=new Thickness(0,12,0,8)};
    private readonly CheckBox reconnect=new(){Content="Восстанавливать после обрыва, смены сети и сна",Foreground=Brush("#C4C6D0"),Margin=new Thickness(0,8,0,8)};
    private readonly CheckBox lightTheme=new(){Content="Светлая тема (после перезапуска)",Foreground=Brush("#C4C6D0"),Margin=new Thickness(0,8,0,8)};
    private readonly ReconnectPolicy intent=new();
    private readonly NetworkRecovery networkRecovery;
    private ulong previousRx,previousTx;private long previousSample;
    private bool refreshing, busy, closing, closeConfirmed;
    private string lastState="stopped";
    private string lastDiagnostic="";
    private bool tunnelActive;
    private bool connectRequested;
    private bool returnHome;
    private bool Idle=>lastState=="stopped"||lastState=="error"&&!tunnelActive;
    private static string Engine => Path.Combine(AppContext.BaseDirectory, "FreeTurn.Engine.exe");

    internal MainWindow(bool designPreview=false,int previewPage=0,bool compactPreview=false,bool startHidden=false)
    {
        networkRecovery=new(()=>ServiceClient.Send("status"),ServiceClient.ReconnectNetwork,message=>{notice.Text=message;pages?.Record(message);},()=>{transport?.Cancel();managedRecovery?.Cancel();managedSync?.Cancel();state.Text="Восстанавливаем сеть…";connect.SetPhase("starting");},lease=>{try{var s=catalog.Read();return s.AutoReconnect&&(lease.ProfileId==Guid.Empty||s.Profiles.Any(p=>p.Id==lease.ProfileId&&ProfileIdentity.Of(p.Share)==lease.Identity&&p.Managed is not{AccessDenied:true}));}catch{return false;}});
        this.designPreview=designPreview;
        designPage=previewPage;
        if(designPreview)catalog=new ProfileCatalog(Path.Combine(Path.GetTempPath(),"ftm-design-"+Guid.NewGuid().ToString("N")));
        var availableHeight=Math.Max(420,SystemParameters.WorkArea.Height-40);
        Title="FreeTurn для Windows"; Width=compactPreview?420:480; Height=Math.Min(860,availableHeight); MinWidth=420; MinHeight=Math.Min(640,availableHeight);
        Background=Brush("#111318"); Foreground=Brush("#E2E2E9"); FontFamily=UiTheme.Font;
        WindowStartupLocation=WindowStartupLocation.CenterScreen;
        Icon=System.Windows.Media.Imaging.BitmapFrame.Create(new Uri("pack://application:,,,/Assets/FreeTurn.ico"));
        var home=new Grid();home.RowDefinitions.Add(new(){Height=GridLength.Auto});home.RowDefinitions.Add(new(){Height=new GridLength(1,GridUnitType.Star)});
        var brand=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Center,Margin=new Thickness(0,20,0,0)};
        brand.Children.Add(new Border{Width=32,Height=32,CornerRadius=new CornerRadius(11),Background=UiTheme.PrimaryContainer,Child=AndroidIcon.Create("Logo",24,UiTheme.OnPrimaryContainer)});var wordmark=AndroidSkin.Text("FreeTurn",22);wordmark.FontWeight=FontWeights.Medium;wordmark.Margin=new Thickness(10,0,0,0);wordmark.VerticalAlignment=VerticalAlignment.Center;brand.Children.Add(wordmark);home.Children.Add(brand);
        var hero=new StackPanel{HorizontalAlignment=HorizontalAlignment.Center,VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(24,32,24,32)};Grid.SetRow(hero,1);home.Children.Add(hero);
        connect.HorizontalAlignment=HorizontalAlignment.Center;hero.Children.Add(connect);
        primaryLabel.HorizontalAlignment=HorizontalAlignment.Center;primaryLabel.FontWeight=FontWeights.Medium;primaryLabel.Margin=new Thickness(0,12,0,0);hero.Children.Add(primaryLabel);
        state.TextAlignment=TextAlignment.Center;state.FontSize=22;state.FontWeight=FontWeights.SemiBold;state.TextWrapping=TextWrapping.Wrap;state.MaxWidth=340;state.Margin=new Thickness(0,24,0,0);hero.Children.Add(state);
        detail.TextWrapping=TextWrapping.Wrap;detail.TextAlignment=TextAlignment.Center;detail.MaxWidth=310;detail.Margin=new Thickness(0,8,0,12);hero.Children.Add(detail);effective.TextWrapping=TextWrapping.Wrap;effective.TextAlignment=TextAlignment.Center;effective.MaxWidth=310;hero.Children.Add(effective);
        var pill=new Border{CornerRadius=new CornerRadius(18),Background=UiTheme.Brush("#282A2F"),Padding=new Thickness(16,8,16,8),HorizontalAlignment=HorizontalAlignment.Center,Child=uptime,MinHeight=36};pill.SetBinding(VisibilityProperty,new System.Windows.Data.Binding("Text"){Source=uptime,Converter=new EmptyTextVisibility()});hero.Children.Add(pill);
        var add=AndroidSkin.Page("Добавить сервер");var settings=AndroidSkin.Page("Настройки");
        var host=new ContentControl{Content=home,HorizontalContentAlignment=HorizontalAlignment.Stretch,VerticalContentAlignment=VerticalAlignment.Stretch};
        var scroll=new ScrollViewer{Content=host,Background=Background,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled};
        scroll.SizeChanged+=(_,_)=>home.MinHeight=Math.Max(330,scroll.ActualHeight);
        void Open(FrameworkElement page){host.Content=page;scroll.ScrollToTop();}
        async void ShowServers(){if(await new ServersWindow(this,catalog,SelectServer,Validate).OpenAsync()==true)goHome();UpdateServerSummary(rootHasProfile);await Refresh();}
        openServers=ShowServers;
        async void ShowBackup(){if(designPreview)return;intent.Stop();await new BackupWindow(this,catalog).OpenAsync();try{var restored=catalog.Read();advanced.IsChecked=restored.AdvancedCaptcha;closeToTray.IsChecked=restored.CloseToTray;reconnect.IsChecked=restored.AutoReconnect;lightTheme.IsChecked=restored.LightTheme;sync.IsChecked=restored.ManagedAutoSync;autoTransport.IsChecked=restored.AutoTransport;auto.IsChecked=!restored.ForceManualCaptcha;}catch{notice.Text="Каталог не прочитан.";}UpdateServerSummary(rootHasProfile);await Refresh();}
        var root=new DockPanel{Background=Background};Content=root;var main=new DockPanel();pages=new ConnectionPages(this,catalog);
        managedSync=new(catalog,()=>ServiceClient.Send("status"),ServiceClient.DisconnectCurrent,message=>{notice.Text=message;pages.Record(message);if(message.StartsWith("Подписка: доступ отозван",StringComparison.Ordinal)||message.StartsWith("Подписка: сервер отозвал",StringComparison.Ordinal))ManagedAccessRevoked();});
        managedRecovery=new(catalog,()=>ServiceClient.Send("status"),RecoverKnownPath,message=>{notice.Text=message;pages.Record(message);},RecoveryStarting);
        transport=new(catalog,()=>ServiceClient.Send("status"),ServiceClient.ChangePath,message=>{notice.Text=message;pages.Record(message);},()=>managedSync.Cancel(),()=>intent.Stop());
        var footerContent=new StackPanel();
        var handle=new Border{Width=32,Height=4,CornerRadius=new CornerRadius(2),Background=UiTheme.Brush("#44474E"),HorizontalAlignment=HorizontalAlignment.Center,Margin=new Thickness(0,0,0,14)};footerContent.Children.Add(handle);
        serverName.FontWeight=FontWeights.SemiBold;serverName.TextAlignment=TextAlignment.Center;serverName.TextTrimming=TextTrimming.CharacterEllipsis;serverName.TextWrapping=TextWrapping.NoWrap;
        serverAddress.TextAlignment=TextAlignment.Center;serverAddress.Foreground=Brush("#AAC7FF");serverAddress.Margin=new Thickness(0,4,0,0);
        var serverLabels=new StackPanel();serverLabels.Children.Add(serverName);serverLabels.Children.Add(serverAddress);
        var serverGrid=new Grid();serverGrid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});serverGrid.ColumnDefinitions.Add(new(){Width=new GridLength(28)});serverGrid.Children.Add(serverLabels);var expand=AndroidIcon.Create("Chevron",24,UiTheme.Muted);expand.RenderTransform=new RotateTransform(-90);Grid.SetColumn(expand,1);serverGrid.Children.Add(expand);
        var choose=Button("", "#191C20");choose.Content=serverGrid;choose.Padding=new Thickness(8,0,8,4);choose.HorizontalContentAlignment=HorizontalAlignment.Stretch;choose.Margin=new Thickness(0);choose.Click+=(_,_)=>ShowServers();System.Windows.Automation.AutomationProperties.SetName(choose,"Выбрать сервер");footerContent.Children.Add(choose);
        var homeFooter=AndroidSkin.Card(footerContent,16);homeFooter.Margin=new Thickness(16,0,16,0);homeFooter.CornerRadius=new CornerRadius(28,28,12,12);
        counters.TextWrapping=TextWrapping.Wrap;counters.TextAlignment=TextAlignment.Center;trafficCard=AndroidSkin.Card(counters);trafficCard.Margin=new Thickness(24,8,24,12);trafficCard.Visibility=Visibility.Collapsed;
        var homeBottom=new StackPanel();homeBottom.Children.Add(trafficCard);homeBottom.Children.Add(homeFooter);
        var body=new Grid();shellBody=body;body.Children.Add(main);embedded=new EmbeddedPageHost(this,main);body.Children.Add(embedded.View);
        var navigation=new BottomNavigation(this,index=>{Open(index switch{1=>pages.Logs,2=>pages.Share,3=>settings,4=>add,_=>home});homeBottom.Visibility=index==0?Visibility.Visible:Visibility.Collapsed;if(index==2&&!designPreview)pages.OpenShare();},()=>!busy&&embedded.CloseAll());
        goHome=()=>navigation.Select(0);openAdd=()=>navigation.Select(4);
        DockPanel.SetDock(navigation,Dock.Bottom);root.Children.Add(navigation);root.Children.Add(body);
        notice.Margin=new Thickness(24,12,24,12);notice.TextWrapping=TextWrapping.Wrap;DockPanel.SetDock(notice,Dock.Bottom);main.Children.Add(notice);
        var noticeStyle=new Style(typeof(TextBlock));var emptyNotice=new Trigger{Property=TextBlock.TextProperty,Value=""};emptyNotice.Setters.Add(new Setter(VisibilityProperty,Visibility.Collapsed));noticeStyle.Triggers.Add(emptyNotice);notice.Style=noticeStyle;
        DockPanel.SetDock(homeBottom,Dock.Bottom);main.Children.Add(homeBottom);main.Children.Add(scroll);
        var appPage=AndroidSkin.Page("Приложение",null,()=>Open(settings));
        var advancedPage=AndroidSkin.Page("Продвинутые",null,()=>Open(settings));
        var aboutPage=AndroidSkin.Page("О проекте",null,()=>Open(settings));
        settings.Children.Add(AndroidSkin.Group(
            AndroidSkin.Entry("Servers","Серверы","Подключения, параметры и SSH",ShowServers),
            AndroidSkin.Entry("App","Приложение","Оформление, запуск и резервные копии",()=>Open(appPage)),
            AndroidSkin.Entry("Advanced","Продвинутые","CAPTCHA, прокси и системная служба",()=>Open(advancedPage)),
            AndroidSkin.Entry("Info","О проекте","Версия, исходники и лицензии",()=>Open(aboutPage))));
        appPage.Children.Add(AndroidSkin.Section("Оформление"));lightTheme.IsChecked=UiTheme.Light;lightTheme.IsEnabled=!designPreview;appPage.Children.Add(AndroidSkin.SwitchGroup(lightTheme));
        void SaveTheme(){try{catalog.SetLightTheme(lightTheme.IsChecked==true);notice.Text="Тема применится при следующем запуске приложения.";}catch{notice.Text="Тема не сохранена.";}}lightTheme.Checked+=(_,_)=>SaveTheme();lightTheme.Unchecked+=(_,_)=>SaveTheme();
        appPage.Children.Add(AndroidSkin.Section("Работа в Windows"));
        var login=new CheckBox{Content="Запускать приложение при входе в Windows",Foreground=UiTheme.Foreground,IsEnabled=!designPreview};
        closeToTray.IsEnabled=reconnect.IsEnabled=!designPreview;appPage.Children.Add(AndroidSkin.SwitchGroup(closeToTray,reconnect,login));
        var desktopHint=AndroidSkin.Text("Автозапуск открывает только приложение. VPN включается вручную; переподключение ограничено пятью попытками.",13,true);desktopHint.Margin=new Thickness(16,-12,16,20);appPage.Children.Add(desktopHint);
        try{var preferences=catalog.Read();closeToTray.IsChecked=preferences.CloseToTray;reconnect.IsChecked=preferences.AutoReconnect;if(!designPreview)login.IsChecked=LoginStartup.Enabled(Environment.ProcessPath!);}catch{notice.Text="Настройки Windows не прочитаны.";}
        closeToTray.Checked+=(_,_)=>SaveDesktopPreference();closeToTray.Unchecked+=(_,_)=>SaveDesktopPreference();
        void SaveReconnect(){if(reconnect.IsChecked!=true){intent.Stop();networkRecovery.Stop();}try{catalog.SetAutoReconnect(reconnect.IsChecked==true);}catch{notice.Text="Настройка переподключения не сохранена.";}}reconnect.Checked+=(_,_)=>SaveReconnect();reconnect.Unchecked+=(_,_)=>SaveReconnect();
        var updatingStartup=false;void UpdateStartup(){if(updatingStartup||designPreview)return;try{LoginStartup.Set(login.IsChecked==true,Environment.ProcessPath!);notice.Text="Автозапуск приложения обновлён. VPN сам не включается.";}catch{updatingStartup=true;try{login.IsChecked=LoginStartup.Enabled(Environment.ProcessPath!);}catch{login.IsChecked=false;}finally{updatingStartup=false;}notice.Text="Автозапуск не изменён. Проверьте путь установленного приложения.";}}login.Checked+=(_,_)=>UpdateStartup();login.Unchecked+=(_,_)=>UpdateStartup();
        appPage.Children.Add(AndroidSkin.Section("Транспорт"));autoTransport.IsEnabled=!designPreview;
        if(!designPreview)try{autoTransport.IsChecked=catalog.Read().AutoTransport;}catch{}
        appPage.Children.Add(AndroidSkin.SwitchGroup(autoTransport));
        var pathHint=AndroidSkin.Text("Со следующего ручного подключения: сначала Direct, затем VK Relay при отсутствии интернета. Максимум два переключения; рабочий путь сохраняется. Нужен WireGuard-профиль с VK-ссылкой.",13,true);pathHint.Margin=new Thickness(16,-12,16,20);appPage.Children.Add(pathHint);
        void SaveTransport(){transport.Cancel();managedRecovery.Cancel();intent.Stop();try{catalog.SetAutoTransport(autoTransport.IsChecked==true);notice.Text="Выбор транспорта сохранён для следующего ручного подключения.";}catch{notice.Text="Выбор транспорта не сохранён.";}}autoTransport.Checked+=(_,_)=>SaveTransport();autoTransport.Unchecked+=(_,_)=>SaveTransport();
        appPage.Children.Add(AndroidSkin.Section("Данные"));var backups=AndroidSkin.Entry("Restore","Резервные копии","Создать или восстановить зашифрованную копию",ShowBackup);backups.IsEnabled=!designPreview;appPage.Children.Add(AndroidSkin.Group(backups));
        sync.IsEnabled=!designPreview;
        if(!designPreview)try{sync.IsChecked=catalog.Read().ManagedAutoSync;}catch{}
        appPage.Children.Add(AndroidSkin.SwitchGroup(sync));
        var syncHint=AndroidSkin.Text("Раз в 30 минут при работающем VPN. Новая версия сохраняется для вашего решения. При отзыве доступа соответствующее соединение отключается. Проверки идут, пока приложение открыто.",13,true);syncHint.Margin=new Thickness(16,-12,16,20);appPage.Children.Add(syncHint);
        void SaveSync(){managedSync.Cancel();try{catalog.SetManagedAutoSync(sync.IsChecked==true);notice.Text="Настройка проверки подписки сохранена.";}catch{notice.Text="Настройка проверки подписки не сохранена.";}}sync.Checked+=(_,_)=>SaveSync();sync.Unchecked+=(_,_)=>SaveSync();
        advancedPage.Children.Add(AndroidSkin.Section("Проверка VK"));advancedPage.Children.Add(AndroidSkin.SwitchGroup(auto,advanced));
        var captchaHint=AndroidSkin.Text("Экспериментальная браузерная проверка PoW из FreeTurn. При неудаче используется прежняя автоматика; ручная CAPTCHA имеет приоритет.",13,true);captchaHint.Margin=new Thickness(16,-12,16,24);advancedPage.Children.Add(captchaHint);
        auto.Content="Автоматическая CAPTCHA с ручным резервом";auto.ToolTip="Выключите для ручной проверки. Если в профиле выбрана ручная CAPTCHA, она имеет приоритет.";auto.Margin=new Thickness(0);auto.Unchecked+=(_,_)=>{advanced.IsChecked=false;advanced.IsEnabled=false;SaveManualCaptchaPreference();};auto.Checked+=(_,_)=>{advanced.IsEnabled=!busy;SaveManualCaptchaPreference();};
        try{var saved=catalog.Read();advanced.IsChecked=saved.AdvancedCaptcha;if(!designPreview)auto.IsChecked=!saved.ForceManualCaptcha;}catch{notice.Text="Каталог не прочитан. Данные не изменены.";}advanced.Checked+=(_,_)=>SaveCaptchaPreference();advanced.Unchecked+=(_,_)=>SaveCaptchaPreference();
        var socks=AndroidSkin.Entry("Link","SOCKS5 через VPN","Локальный TCP-прокси с паролем",async()=>await new SocksWindow(this,catalog).OpenAsync());socks.IsEnabled=!designPreview;advancedPage.Children.Add(AndroidSkin.Group(socks));
        var routing=AndroidSkin.Entry("Link","Системная маршрутизация","Российские сайты, локальная сеть и доменные исключения",async()=>await new SystemRoutingWindow(this,catalog).OpenAsync());routing.IsEnabled=!designPreview;advancedPage.Children.Add(AndroidSkin.Group(routing));
        advancedPage.Children.Add(AndroidSkin.Section("Сетевое ядро"));var service=new StackPanel();var serviceText=AndroidSkin.Text("FreeTurn проверяет ядро при подключении и обновляет его при необходимости. Windows запросит права администратора только для установки или обновления. Профили и ключи сохраняются. Кнопка ниже — для ручного восстановления.",14,true);serviceText.Margin=new Thickness(0,0,0,16);service.Children.Add(serviceText);
        var serviceRow=new WrapPanel();serviceRow.Children.Add(setup);var remove=Button("Удалить службы…","#33353A");remove.IsEnabled=!designPreview;serviceRow.Children.Add(remove);service.Children.Add(serviceRow);advancedPage.Children.Add(AndroidSkin.Card(service));
        var logo=new Border{Width=80,Height=80,CornerRadius=new CornerRadius(28),Background=UiTheme.PrimaryContainer,Child=AndroidIcon.Create("Logo",64,UiTheme.OnPrimaryContainer),HorizontalAlignment=HorizontalAlignment.Left,Margin=new Thickness(0,0,0,24)};aboutPage.Children.Add(logo);
        var appName=AndroidSkin.Text("FreeTurn для Windows",24);appName.FontWeight=FontWeights.SemiBold;aboutPage.Children.Add(appName);aboutPage.Children.Add(AndroidSkin.Text("Версия "+typeof(App).Assembly.GetName().Version,14,true));
        var aboutText=AndroidSkin.Text("На основе FreeTurn Android 5.3.4. Исходники Windows-клиента и лицензии включены в сборку. Реальное сетевое подключение этой версии проверяется отдельно.",14,true);aboutText.Margin=new Thickness(0,20,0,24);aboutPage.Children.Add(aboutText);
        aboutPage.Children.Add(AndroidSkin.Group(AndroidSkin.Entry("Logs","Исходники и лицензии","Файлы рядом с приложением",()=>MessageBox.Show(this,"Windows-Client-Sources.zip\nAndroid-LICENSE.txt\nRoboto-LICENSE.txt\nTHIRD_PARTY_NOTICES.txt","Исходники и лицензии"))));
        add.Children.Add(AndroidSkin.Section("Ссылка на подключение"));var importPanel=new StackPanel();input.Height=104;input.FontFamily=UiTheme.Font;input.FontSize=14;importPanel.Children.Add(input);
        var paste=Button("Вставить ссылку","#33353A");paste.Content=new StackPanel{Orientation=Orientation.Horizontal,Children={AndroidIcon.Create("Paste",20,UiTheme.Foreground),new TextBlock{Text="Вставить ссылку",Margin=new Thickness(8,0,0,0)}}};paste.Margin=new Thickness(0,12,0,8);paste.Click+=async(_,_)=>await Act(()=>{if(!Clipboard.ContainsText())throw new IOException("PROFILE_UNSUPPORTED_OR_INVALID");var value=Clipboard.GetText().Trim();if(value.Length>96*1024)throw new IOException("PROFILE_TOO_LARGE");if(EnrollmentLink.LooksLike(value))_=EnrollmentLink.Parse(value);else if(value.StartsWith('{'))_=ManagedBootstrap.Parse(value);else _ = new ShareDocument(value);input.Text=value;notice.Text="Профиль или подписка вставлены. Нажмите «Добавить сервер».";return Task.CompletedTask;});importPanel.Children.Add(paste);
        var check=Button("Проверить","#33353A");var importActions=new WrapPanel{Margin=new Thickness(0,12,0,0)};importActions.Children.Add(check);importActions.Children.Add(import);importPanel.Children.Add(importActions);add.Children.Add(AndroidSkin.Card(importPanel));
        add.Children.Add(AndroidSkin.Section("Другие способы"));var file=AndroidSkin.Entry("File","Из файла","Профиль, стартовый JSON или подписка из панели",OpenFile);var restore=AndroidSkin.Entry("Restore","Восстановить копию","Профили и настройки под паролем",ShowBackup);restore.IsEnabled=!designPreview;var pending=AndroidSkin.Entry("Advanced","Незавершённые регистрации","Продолжить с сохранёнными ключами",async()=>{if(designPreview||busy)return;await new EnrollmentWindow(this,catalog).OpenAsync();UpdateServerSummary(rootHasProfile);});pending.IsEnabled=!designPreview;add.Children.Add(AndroidSkin.Group(file,pending,restore));
        var privacy=AndroidSkin.Text("Для компьютера используйте отдельный профиль устройства. Ваши ключи сохраняются зашифрованными.",13,true);privacy.Margin=new Thickness(16,0,16,0);add.Children.Add(privacy);
        async Task Primary(){if(designPreview||busy||!embedded.CanClose)return;if(Idle&&!HasSelectedProfile()){if(catalog.Read().Profiles.Count>0){openServers();return;}if(!rootHasProfile){openAdd();return;}}await Act(()=>Apply(Idle?"connect":"disconnect"));}
        connect.Click+=async(_,_)=>await Primary();disconnect.Click+=async(_,_)=>await Act(()=>Apply("disconnect"));
        var connectCommand=new System.Windows.Input.RoutedCommand();CommandBindings.Add(new System.Windows.Input.CommandBinding(connectCommand,async(_,_)=>await Primary()));InputBindings.Add(new System.Windows.Input.KeyBinding(connectCommand,System.Windows.Input.Key.Enter,System.Windows.Input.ModifierKeys.Control));connect.ToolTip="Подключить / отключить · Ctrl+Enter";
        check.Click+=async(_,_)=>await Act(async()=>{var value=input.Text.Trim();if(EnrollmentLink.LooksLike(value))_=EnrollmentLink.Parse(value);else if(value.StartsWith('{'))await ManagedBootstrap.Verify(value);else await Validate(value);notice.Text="Формат поддерживается. VPN не подключался.";});import.Click+=async(_,_)=>await Act(Import);input.TextChanged+=(_,_)=>{if(!busy)notice.Text="";};
        setup.Click+=async(_,_)=>await Act(()=>Setup(false));remove.Click+=async(_,_)=>await Act(()=>Setup(true));
        if(!designPreview)UpdateServerSummary(false);else{serverName.Text="Тестовый сервер";serverAddress.Text="VK Relay · WireGuard";}
        void NetworkChanged(object? sender,EventArgs e){if(!Dispatcher.HasShutdownStarted)Dispatcher.BeginInvoke(()=>networkRecovery.Signal());}
        void PowerChanged(object sender,PowerModeChangedEventArgs e){if(!Dispatcher.HasShutdownStarted)Dispatcher.BeginInvoke(()=>{if(e.Mode==PowerModes.Suspend){networkRecovery.Suspend();managedSync.Cancel();managedRecovery.Cancel();transport.Cancel();}else if(e.Mode==PowerModes.Resume)networkRecovery.Resume();});}
        if(!designPreview){SystemEvents.PowerModeChanged+=PowerChanged;System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged+=NetworkChanged;}
        timer.Tick+=async(_,_)=>await Refresh();displayClock.Tick+=(_,_)=>{if(latestReply is { } r&&!busy){if(r.Started>0&&r.State!="stopped")uptime.Text=$"{r.Streams}/{r.TotalStreams} потоков · {TimeSpan.FromSeconds(Math.Max(0,DateTimeOffset.UtcNow.ToUnixTimeSeconds()-r.Started)):hh\\:mm\\:ss}";}};Loaded+=async(_,_)=>{await Refresh();timer.Start();displayClock.Start();};
        SourceInitialized+=(_,_)=>{closeRequests=new CloseRequestTracker(this);if(!designPreview)try{tray=new TrayController(this,on=>on?(Idle?Primary():Task.CompletedTask):(Idle?Task.CompletedTask:Act(()=>Apply("disconnect"))));}catch{notice.Text="Значок в трее недоступен. Окно останется открытым.";}};
        var pendingStartHide=startHidden&&!designPreview;ContentRendered+=(_,_)=>{if(pendingStartHide){pendingStartHide=false;if(tray?.Available==true)Hide();}};
        Closed+=(_,_)=>{networkRecovery.Dispose();if(!designPreview){SystemEvents.PowerModeChanged-=PowerChanged;System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged-=NetworkChanged;}transport.Dispose();managedRecovery.Dispose();managedSync.Dispose();closeRequests?.Dispose();tray?.Dispose();timer.Stop();displayClock.Stop();if(captcha is not null){captcha.Completed=true;captcha.Close();}};
        Closing+=async(_,e)=>
        {
            if(closeConfirmed)return;
            var nativeClose=closeRequests?.Consume()==true;var explicitExit=tray?.ExitRequested==true;
            var decision=ClosePolicy.Decide(!Idle,busy||closing||managedRecovery.Busy||transport.Busy,embedded.CanClose,tray?.Available==true,closeToTray.IsChecked==true,explicitExit,nativeClose);
            pages.Record("Запрос закрытия: "+(explicitExit?"выход из трея":nativeClose?"крестик / Alt+F4":"программный / внешний")+" · "+decision);
            if(decision==CloseAction.Allow)return;
            e.Cancel=true;
            if(decision==CloseAction.Wait){notice.Text="Дождитесь завершения текущей операции.";return;}
            if(decision==CloseAction.Ignore){notice.Text="Посторонний запрос закрытия отклонён. Подключение продолжается.";return;}
            if(decision==CloseAction.Hide){Hide();return;}
            if(MessageBox.Show(this,"Отключить VPN и выйти из FreeTurn?","Выход из FreeTurn",MessageBoxButton.OKCancel,MessageBoxImage.Question)!=MessageBoxResult.OK)return;
            closing=true;
            try{await Apply("disconnect");closeConfirmed=true;Close();}catch{notice.Text="Не удалось подтвердить отключение. Окно оставлено открытым.";}finally{closing=false;}
        };
        pages.Record(designPreview?"Предпросмотр интерфейса.":"Приложение запущено.");
        if(designPreview){navigation.Select(previewPage<5?previewPage:previewPage<8?3:0);if(previewPage==5)Open(appPage);if(previewPage==6)Open(advancedPage);if(previewPage==7)Open(aboutPage);}
    }

    private static SolidColorBrush Brush(string color)=>UiTheme.Brush(color);
    private static TextBlock Text(string text,double size,string color)=>new(){Text=text,FontSize=size,Foreground=Brush(color)};
    private static Button Button(string text,string color)=>new(){Content=text,Background=Brush(color),Foreground=UiTheme.Light&&color=="#33353A"?UiTheme.Foreground:Brush("#FFFFFF"),BorderThickness=new Thickness(0),Padding=new Thickness(16,10,16,10),Margin=new Thickness(0,0,8,8),Cursor=System.Windows.Input.Cursors.Hand};
    private static Border Card(UIElement content)=>new(){Child=content,Background=Brush("#191C20"),CornerRadius=new CornerRadius(28),Padding=new Thickness(20),Margin=new Thickness(0,18,0,18)};
    private void ManagedAccessRevoked(){networkRecovery.Stop();intent.Stop();transport.Cancel();managedRecovery.Cancel();}
    private Task<ServiceReply> RecoverKnownPath(RuntimeLease lease,string share)
    {
        var p=catalog.Read().Profiles.Single(p=>p.Id==lease.ProfileId);
        if(p.Share!=share||p.Managed is not{AccessDenied:false})throw new IOException("MANAGED_STORAGE_CHANGED");
        return ServiceClient.RecoverPath(lease,share,p.Managed.KnownGood?.Path);
    }
    private void RecoveryStarting()
    {
        intent.Stop();transport.Cancel();managedSync.Cancel();connectRequested=true;
        state.Text="Возвращаем рабочий профиль…";primaryLabel.Text="Возврат профиля";
        detail.Text="Проверяем сохранённую конфигурацию и выполняем одну попытку подключения. Ключи и полученное обновление сохраняются.";
        connect.IsEnabled=disconnect.IsEnabled=import.IsEnabled=setup.IsEnabled=false;connect.SetPhase("starting");
    }

    private async Task Act(Func<Task> action)
    {
        if(busy||managedRecovery.Busy||transport.Busy)return;transport.Cancel();managedRecovery.Cancel();managedSync.Cancel();busy=true;connect.IsEnabled=disconnect.IsEnabled=import.IsEnabled=setup.IsEnabled=false;input.IsEnabled=auto.IsEnabled=false;
        try{notice.Text="";await action();if(notice.Text.Length>0)pages.Record(notice.Text);}catch(Exception e){notice.Text=FriendlyError(e.Message);pages.Record(notice.Text);}
        finally{busy=false;input.IsEnabled=auto.IsEnabled=true;if(returnHome){returnHome=false;goHome();}await Refresh();}
    }

    internal static async Task Validate(string text)
    {
        if(text.Length>96*1024)throw new IOException("PROFILE_TOO_LARGE");
        if(!File.Exists(Engine))throw new IOException("ENGINE_MISSING");
        using var process=new Process { StartInfo=new ProcessStartInfo(Engine,"--check-profile") { UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false) } };
        process.Start();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
        try{
            var output=process.StandardOutput.ReadToEndAsync(timeout.Token);var error=process.StandardError.ReadToEndAsync(timeout.Token);
            await process.StandardInput.WriteAsync(text.AsMemory(),timeout.Token);process.StandardInput.Close();await process.WaitForExitAsync(timeout.Token);
            await output;await error;if(process.ExitCode!=0)throw new IOException("PROFILE_UNSUPPORTED_OR_INVALID");
        }catch{if(!process.HasExited)process.Kill();throw;}
    }

    private async Task Import()
    {
        intent.Stop();
        var value=input.Text.Trim();
        if(EnrollmentLink.LooksLike(value)){
            var source=EnrollmentLink.Parse(value);input.Clear();var page=new EnrollmentWindow(this,catalog,source);await page.OpenAsync();
            notice.Text=page.ProfilesAdded?"Профиль добавлен. Выберите сервер и подключитесь вручную.":"Незавершённую регистрацию можно продолжить на вкладке «Добавить». VPN не запускался.";returnHome=Idle;UpdateServerSummary(rootHasProfile);return;
        }
        if(value.StartsWith('{')){
            await ManagedBootstrap.Verify(value);catalog.AddBootstrap(ManagedBootstrap.Parse(value),Idle);
            notice.Text="Стартовый профиль сохранён. Подключите VPN, затем откройте «Серверы → Управление» для активации. Ключи сохранены без изменений.";
            returnHome=Idle;input.Clear();UpdateServerSummary(rootHasProfile);return;
        }
        await Validate(value);
        // Explicit user option only. Preserve all keys, addresses and CID.
        if(auto.IsChecked==true)
        {
            var encoded=value["freeturn://".Length..].Replace('-','+').Replace('_','/');encoded=encoded.PadRight((encoded.Length+3)/4*4,'=');
            var node=JsonNode.Parse(Convert.FromBase64String(encoded))!.AsObject();node["mcap"]=false;
            value="freeturn://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(node.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
        }
        catalog.Add(ImportedName(value),value,selected:Idle);
        notice.Text=Idle?"Сервер добавлен. Нажмите «Подключить» — FreeTurn подготовит всё необходимое.":"Сервер добавлен. Выберите его после отключения текущего соединения.";
        if(new ShareDocument(value).IsAmneziaWG)notice.Text="Профиль AmneziaWG добавлен. Для подключения включите системную маршрутизацию в настройках. Поддержка экспериментальная; сервер должен использовать совместимые параметры AWG.";
        returnHome=Idle;input.Clear();UpdateServerSummary(rootHasProfile);
    }

    private void OpenFile()
    {
        var dialog=new OpenFileDialog { Title="Профиль FreeTurn",Filter="Профили FreeTurn (*.txt;*.json)|*.txt;*.json|Все файлы (*.*)|*.*",CheckFileExists=true };
        if(dialog.ShowDialog(this)!=true)return;
        try{var info=new FileInfo(dialog.FileName);if(info.Length>96*1024)throw new IOException();input.Text=File.ReadAllText(info.FullName,Encoding.UTF8);}
        catch{notice.Text="Файл не прочитан или превышает допустимый размер.";}
    }

    private async Task Apply(string operation,bool retry=false)
    {
        if(operation=="disconnect"){networkRecovery.Stop();transport.Cancel();managedRecovery.Cancel();intent.Stop();connectRequested=false;}
        if(operation=="connect"){
            var snapshot=catalog.Read();var selected=ProfileSelection.ForConnect(snapshot);
            if(selected?.Managed is{AccessDenied:true}){intent.Stop();throw new IOException("MANAGED_ACCESS_REJECTED");}
            var routing=snapshot.SystemRouting;
            if(selected is not null&&new ShareDocument(selected.Share).IsAmneziaWG&&routing?.Enabled!=true)throw new IOException("AWG_SYSTEM_BACKEND_REQUIRED");
            if(routing?.Enabled==true&&selected?.Routing is{} delivered)routing=delivered.Current.Settings(routing);
            if(routing?.Enabled==true)routing=(await SystemRoutingCheck.Run(routing)).Policy;
            if(selected is not null)await Validate(selected.Share);
            if(selected?.Managed is not null)await ManagedBootstrap.VerifySaved(selected);
            ServiceReply? started=null;
            var actions=new ServicePreparation.Actions(()=>ServiceClient.Send("status"),()=>RunSetup(false),async share=>{var r=await ServiceClient.Send("import",share);if(!r.Ok)throw new IOException(r.Error??"PROFILE_SELECT_FAILED");},async advanced=>{if(routing?.Enabled==true&&(await ServiceClient.Send("status")).Capabilities?.Contains("system-routing-ipv4-v1")!=true)throw new IOException("SYSTEM_ROUTING_BUILD_REQUIRED");var r=await ServiceClient.Connect(advanced,routing,!retry&&snapshot.AutoTransport,snapshot.ForceManualCaptcha);started=r;if(!r.Ok)throw new IOException(r.Error??"SERVICE_OPERATION_FAILED");});
            try{await ServicePreparation.Connect(typeof(App).Assembly.GetName().Version!,selected?.Share,advanced.IsChecked==true,!retry,actions,stage=>{state.Text=stage;primaryLabel.Text="Подготовка подключения";detail.Text="Если Windows запросит разрешение, подтвердите его. Затем подключение продолжится автоматически.";connect.SetPhase("starting");pages.Record(stage);});}
            catch{intent.Stop();throw;}
            connectRequested=true;if(!retry){if(started is not null&&ProfileIdentity.Valid(started.ConfiguredProfileIdentity)&&started.LastAttemptId!=0)await networkRecovery.Begin(new(selected?.Id??Guid.Empty,started.ConfiguredProfileIdentity!,started.LastAttemptId,started.PathEpoch));intent.Started(DateTimeOffset.UtcNow);if(started is not null){managedRecovery.Begin(selected,started);transport.Begin(selected,started);}}
        }else{var reply=await ServiceClient.Send(operation);if(!reply.Ok)throw new IOException(reply.Error??"SERVICE_OPERATION_FAILED");}
        await Refresh();
    }

    private async Task Setup(bool remove)
    {
        var prompt=remove?"Отключить VPN и удалить только службы FreeTurn? Зашифрованный профиль останется на компьютере.":"Установить или обновить службы FreeTurn? При обновлении VPN должен быть отключён. Существующий профиль и ключи сохранятся, прежние бинарники будут сохранены для отката. Потребуются права администратора. VPN автоматически не включится.";
        if(MessageBox.Show(this,prompt,"FreeTurn",MessageBoxButton.OKCancel,MessageBoxImage.Question)!=MessageBoxResult.OK)return;
        await RunSetup(remove);
        notice.Text=remove?"Службы удалены. Зашифрованный профиль сохранён.":"Ядро готово. Вернитесь на главную и нажмите «Подключить».";
    }

    private static async Task RunSetup(bool remove)
    {
        if(!File.Exists(Engine))throw new IOException("ENGINE_MISSING");
        var sid=WindowsIdentity.GetCurrent().User?.Value??throw new IOException("SID_UNAVAILABLE");
        Process process;
        try{process=Process.Start(new ProcessStartInfo(Engine,remove?"--uninstall":"--setup "+sid){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden})??throw new IOException("SETUP_FAILED");}
        catch(System.ComponentModel.Win32Exception e) when(e.NativeErrorCode==1223){throw new IOException("SETUP_CANCELLED");}
        using(process){
        await process.WaitForExitAsync();if(process.ExitCode!=0)throw new IOException(process.ExitCode switch{10=>"SETUP_STOP_FIRST",11=>"SETUP_OWNER_MISMATCH",12=>"SETUP_ROLLED_BACK",13=>"SETUP_ROLLBACK_FAILED",14=>"SETUP_INCOMPLETE",_=>"SETUP_FAILED"});
        }
    }

    private async Task Refresh()
    {
        if(busy||managedRecovery.Busy||transport.Busy)return;
        if(designPreview){state.Text=designPage==8?"VPN подключён":designPage==9?"Подключаемся…":"Нажмите для подключения";detail.Text="Предпросмотр интерфейса · без подключения к сети";connect.SetPhase(designPage==8?"connected":designPage==9?"starting":"stopped",false);if(designPage>=8){uptime.Text="6/10 потоков · 00:12:34";effective.Text=new EffectiveSettings(10,10,4,"vk","udp","doh",false,false,1280).Summary;trafficCard.Visibility=Visibility.Visible;counters.Text="↓ 1,2 МБ/с          ↑ 84 КБ/с\nПолучено 128 МБ · Отправлено 12 МБ";}if(designPage is 10 or 11){var failed=designPage==11;var demo=new ServiceReply(true,null,failed?"error":"tunnel_unverified",true,"connecting",false,0,0,null,false,Started:DateTimeOffset.UtcNow.AddSeconds(-80).ToUnixTimeSeconds(),Streams:0,TotalStreams:6,Stage:failed?"error":"vk_auth",StageSince:DateTimeOffset.UtcNow.AddSeconds(-65).ToUnixTimeSeconds(),LastProgress:DateTimeOffset.UtcNow.AddSeconds(-65).ToUnixTimeSeconds(),DiagnosticError:failed?"NETWORK_TIMEOUT":null,TunnelActive:!failed,FailureStage:failed?"turn_connect":null);state.Text=failed?"Не удалось подключиться":ConnectionDiagnostics.Stage(demo.Stage);detail.Text=ConnectionDiagnostics.Detail(demo);connect.SetPhase(failed?"error":"starting",false);trafficCard.Visibility=Visibility.Collapsed;uptime.Text="Предпросмотр · без сети";}connect.IsEnabled=true;import.IsEnabled=setup.IsEnabled=advanced.IsEnabled=false;return;}
        if(refreshing)return;refreshing=true;
        try{
            var r=await ServiceClient.Send("status");if(busy)return;if(!r.Ok)throw new IOException("STATUS_FAILED");tunnelActive=r.TunnelActive;latestReply=r;timer.Interval=TimeSpan.FromMilliseconds(r.State is "stopped" or "error"?3000:r.State=="connected"?500:250);pages.AppendCore(r.Events,r.EventSession);
            if(r.State=="stopped"&&lastState!="stopped"&&connectRequested){connectRequested=false;notice.Text=r.Capabilities?.Contains("connection-stages-v1")==true?"Системная служба остановилась до подтверждения подключения и не успела сохранить причину ошибки.":"Попытка завершилась без подтверждённого подключения. Прежняя версия ядра не передала причину. При следующем подключении ядро обновится автоматически.";pages.Record(notice.Text);}
            advancedSupported=r.Capabilities?.Contains("advanced-captcha-v1")==true;
            extendedTransportsSupported=r.Capabilities?.Contains("direct-relay-transport-v1")==true;
            advanced.IsEnabled=!busy&&auto.IsChecked==true;
            advanced.ToolTip="Экспериментальная проверка исходного FreeTurn. Совместимое ядро подготовится при подключении.";
            if(lastState!=r.State)pages.Record(r.State switch{"stopped"=>"VPN отключён.","starting"=>"Подключение запускается.","stopping"=>"Отключение VPN.","captcha"=>"Проверка VK.","connected"=>"Туннель и интернет подтверждены.","handshake"=>"WireGuard handshake получен.",_=>"Проверка соединения."});
            lastState=r.State;
            state.Text=r.State switch{"stopped"=>"Нажмите для подключения","starting"=>"Подключаемся…","stopping"=>"Отключаем…","captcha"=>r.Manual?"Требуется проверка VK":"Автоматическая проверка VK…","connected"=>"VPN подключён","handshake"=>"Туннель установлен","proxy_ready"=>"Проброс готов","proxy_unverified"=>"Проброс запускается…",_=>"Проверяем туннель…"};
            detail.Text=r.State=="connected"?"Интернет работает через выбранный сервер.":r.State=="handshake"?"Туннель готов. Проверяем доступ в интернет.":r.State=="stopped"?(r.HasProfile?"Профиль готов. Нажмите «Подключить».":"Импортируйте профиль FreeTurn."):"Подключение считается рабочим после handshake и проверки трафика.";
            if(r.Capabilities?.Contains("connection-stages-v1")==true){if(r.State!="stopped"&&r.State!="connected")detail.Text=ConnectionDiagnostics.Detail(r);if(r.State=="error")state.Text="Не удалось подключиться";else if(r.State!="connected"&&r.State!="stopped"&&r.State!="stopping")state.Text=ConnectionDiagnostics.Stage(r.Stage);var diagnostic=(r.Stage??r.State)+"/"+(r.DiagnosticError??"");if(lastDiagnostic!=diagnostic){lastDiagnostic=diagnostic;pages.Record(ConnectionDiagnostics.Stage(r.Stage)+(string.IsNullOrEmpty(r.DiagnosticError)?"":" · "+ConnectionDiagnostics.Error(r.DiagnosticError)));}}
            else if(r.State!="stopped"){detail.Text+="\nПодробные этапы появятся после автоматического обновления ядра при следующем подключении.";}
            if(r.State=="switching"){state.Text="Переключаем транспорт…";detail.Text="WireGuard и маршруты сохраняются. Запускаем другой путь и проверяем интернет.";}
            else if(r.RuntimePath is "direct" or "relay")detail.Text+="\nПуть: "+(r.RuntimePath=="direct"?"Direct":"VK Relay")+(r.AutoPaths?$" · переключений {r.PathEpoch}/2":"");
            if(r.State!="stopped"&&r.Kind is ("tcp-forwarder" or "udp-forwarder"))detail.Text=$"Локальный {(r.Kind=="tcp-forwarder"?"TCP":"UDP")} listener: {r.Listen}. Системный VPN и маршруты не включаются; настройте использующее проброс приложение отдельно.";
            effective.Text=r.Effective is{Valid:true} settings?settings.Summary:"";
            if(r.Effective is{Valid:true} actual){effective.ToolTip="DNS FreeTurn: "+actual.DnsMode+" · "+actual.ProtocolLabel+" MTU "+actual.WireGuardMTU+"\nCAPTCHA: "+(actual.Provider=="direct"?"не используется":actual.ManualCaptcha?"ручная":actual.AdvancedCaptcha?"авто, продвинутая":"автоматическая");if(lastEffectiveSettings!=actual){lastEffectiveSettings=actual;pages.Record("Параметры ядра: "+actual.Summary+" · "+effective.ToolTip.ToString()!.Replace("\n"," · "));}}
            else {lastEffectiveSettings=null;effective.ToolTip=null;}
            var sample=Stopwatch.GetTimestamp();var seconds=previousSample==0?0:(sample-previousSample)/(double)Stopwatch.Frequency;
            var rxRate=seconds>0&&r.Rx>=previousRx?(ulong)((r.Rx-previousRx)/seconds):0;var txRate=seconds>0&&r.Tx>=previousTx?(ulong)((r.Tx-previousTx)/seconds):0;previousSample=sample;previousRx=r.Rx;previousTx=r.Tx;
            var elapsed=r.Started>0&&r.Started<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()?TimeSpan.FromSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-r.Started).ToString(@"hh\:mm\:ss"):"—";
            counters.Text=$"↓ {Size(rxRate)}/с                 ↑ {Size(txRate)}/с\nПолучено {Size(r.Rx)} · Отправлено {Size(r.Tx)}";trafficCard.Visibility=r.State is "connected" or "handshake"?Visibility.Visible:Visibility.Collapsed;uptime.Text=r.State=="stopped"?"":$"{r.Streams}/{r.TotalStreams} потоков · {elapsed}";if(rootHasProfile!=r.HasProfile){rootHasProfile=r.HasProfile;UpdateServerSummary(rootHasProfile);}
            connect.IsEnabled=!busy&&r.State!="stopping";connect.SetPhase(r.State);System.Windows.Automation.AutomationProperties.SetName(connect,r.State=="stopped"?"Подключить":r.State=="error"&&!r.TunnelActive?"Повторить подключение":"Отключить");disconnect.IsEnabled=!busy&&(r.TunnelActive||r.State!="stopped"&&r.State!="error");import.IsEnabled=!busy;setup.IsEnabled=!busy&&!r.TunnelActive&&(r.State is "stopped" or "error");setup.Content="Восстановить ядро…";UpdatePrimary(r);
            if(!string.IsNullOrEmpty(r.Captcha))await ShowCaptcha(r.Captcha,r.Manual,r.CaptchaId);
            else if(captcha is not null){captcha.Completed=true;captcha.Close();captcha=null;}
            if(r.State is "connected" or "proxy_ready")intent.Healthy(DateTimeOffset.UtcNow);
            networkRecovery.Observe(r,reconnect.IsChecked==true&&intent.Wanted&&!busy&&!closing&&embedded.View.Visibility!=Visibility.Visible);
            if(networkRecovery.Busy||networkRecovery.Suspended)return;
            transport.Observe(r,!busy&&!closing&&embedded.View.Visibility!=Visibility.Visible);
            if(transport.Busy)return;
            managedRecovery.Observe(r,!busy&&!closing&&embedded.View.Visibility!=Visibility.Visible,transport.HasIntent,transport.Exhausted);
            if(managedRecovery.Busy)return;
            if(r.Capabilities?.Contains("managed-recovery-v1")==true&&r.LastAttemptId==0&&r.State=="stopped")intent.Stop();
            managedSync.Observe(r,sync.IsChecked==true&&!busy&&!closing&&embedded.View.Visibility!=Visibility.Visible);
            if(r.State=="stopped"&&!networkRecovery.HasIntent&&!networkRecovery.Busy&&!busy&&!managedRecovery.HasTrial&&!transport.HasIntent&&!transport.Exhausted&&reconnect.IsChecked==true&&intent.TryBegin(DateTimeOffset.UtcNow)){
                notice.Text=$"Повторная попытка подключения {intent.Attempts}/5…";pages.Record(notice.Text);await Act(()=>Apply("connect",true));
            }
        }
        catch{
            transport.Cancel();managedRecovery.Cancel();managedSync.Cancel();intent.Stop();
            lastState="stopped";tunnelActive=false;latestReply=null;effective.Text="";timer.Interval=TimeSpan.FromSeconds(3);
            var selected=HasSelectedProfile();state.Text=selected||rootHasProfile?"Готово к подключению":"Добавьте сервер";
            detail.Text=selected||rootHasProfile?"Нажмите «Подключить». При необходимости FreeTurn установит или обновит ядро и продолжит подключение.":"Добавьте ссылку или файл профиля. FreeTurn сохранит сервер и вернёт вас на главный экран.";
            primaryLabel.Text=selected||rootHasProfile?"Подключить":"Добавить сервер";
            connect.IsEnabled=!busy;disconnect.IsEnabled=false;connect.SetPhase("stopped");trafficCard.Visibility=Visibility.Collapsed;uptime.Text="";import.IsEnabled=setup.IsEnabled=!busy;
            advanced.IsEnabled=!busy&&auto.IsChecked==true;
        }
        finally{refreshing=false;}
    }

    private async Task ShowCaptcha(string url,bool manual,ulong challengeId)
    {
        if(!CaptchaWindow.Local(url))throw new IOException("CAPTCHA_URL_INVALID");
        if(captcha is not null && challengeId!=0 && captchaId!=challengeId){captcha.Completed=true;captcha.Close();captcha=null;}
        captchaId=challengeId;
        if(captcha is null)
        {
            captcha=new CaptchaWindow(this,manual);captcha.Cancelled+=async()=>{captcha=null;await Act(async()=>await Apply("disconnect"));};System.Windows.Controls.Panel.SetZIndex(captcha,100);shellBody.Children.Add(captcha);
        }
        var challenge=captcha;
        try{await challenge.Navigate(url,manual);}
        catch{
            // A user may cancel while WebView initialization is still pending.
            if(!ReferenceEquals(captcha,challenge))return;
            notice.Text="Не удалось открыть CAPTCHA. Установите Microsoft Edge WebView2 Runtime и повторите подключение.";challenge.Completed=true;challenge.Close();captcha=null;await ServiceClient.Send("disconnect");
        }
    }

    private static string TransportName(string? value)=>value switch{"connected"=>"готов","captcha"=>"проверка VK","connecting"=>"подключение","error"=>"ошибка",_=>"—"};
    private static string Size(ulong value)=>value>=1024*1024?$"{value/(1024.0*1024):F1} МБ":value>=1024?$"{value/1024.0:F1} КБ":$"{value} Б";
    private static string FriendlyError(string code)=>code switch
    {
        "AUTO_PATH_PROFILE_INVALID"=>"Для автоматического режима нужен WireGuard-профиль с действующей VK-ссылкой. Отключите автоматический выбор транспорта или импортируйте подходящий профиль.",
        "PATH_STATE_INVALID"=>"Состояние переключения транспорта повреждено. Отключите VPN и подключитесь вручную; автоматический лимит не сбрасывался.",
        var managed when managed.StartsWith("MANAGED_",StringComparison.Ordinal)=>ManagedMessages.Friendly(managed),
        "PROFILE_UNSUPPORTED_OR_INVALID"=>"Профиль повреждён или содержит неподдерживаемые параметры. Поддерживаются WireGuard и проверенный набор параметров AmneziaWG 1–3; проверьте профиль сервера.",
        "AWG_SYSTEM_BACKEND_REQUIRED"=>"AmneziaWG требует включённой системной маршрутизации в настройках. Параметры AWG сохраняются; обычный WireGuard-драйвер их не поддерживает.",
        "PROFILE_TOO_LARGE"=>"Профиль превышает допустимый размер.",
        "ENGINE_MISSING"=>"Не найден FreeTurn.Engine.exe. Распакуйте всю сборку в одну папку.",
        "PHYSICAL_UPLINK_REQUIRED"=>"Не найден подходящий прямой интернет-канал. Перед проверкой отключите другой VPN; FreeTurn не останавливает его автоматически.",
        "STOP_BEFORE_IMPORT"=>"Сначала отключите текущее подключение FreeTurn, затем импортируйте профиль.",
        "SERVICE_UNAVAILABLE"=>"Ядро недоступно. Нажмите «Подключить» для автоматической подготовки; если ошибка повторится, используйте восстановление в настройках.",
        "UNTRUSTED_PIPE"=>"Не удалось подтвердить подлинность службы. Профиль ей не отправлен.",
        "SERVICE_UPGRADE_REQUIRED" or "SERVICE_UPDATE_ON_CONNECT"=>"Для продолжения нужно обновить ядро. Нажмите «Подключить» самостоятельно, чтобы подтвердить запрос Windows.",
        "SETUP_CANCELLED"=>"Разрешение Windows отменено. Подключение не началось; профиль сохранён. Когда будете готовы, нажмите «Подключить» ещё раз.",
        "CLIENT_OLDER_THAN_SERVICE"=>"На компьютере уже установлено более новое ядро. Откройте свежую сборку приложения; понижение версии не выполняется.",
        "SERVICE_VERSION_INVALID" or "SERVICE_VERSION_MISMATCH"=>"Не удалось подтвердить совместимость ядра. Подключение остановлено. Распакуйте полный актуальный пакет FreeTurn.",
        "PROFILE_NOT_SELECTED"=>"Выберите или добавьте сервер перед подключением.",
        "SETUP_STOP_FIRST"=>"Сначала отключите FreeTurn. Обновление не выполняется при активном туннеле.",
        "SETUP_OWNER_MISMATCH"=>"Службы закреплены за другим пользователем Windows. Владелец и профиль не изменены.",
        "SETUP_ROLLED_BACK"=>"Новая служба не запустилась. Предыдущая версия восстановлена; профиль сохранён.",
        "SETUP_ROLLBACK_FAILED"=>"Обновление и откат службы не завершены. Зашифрованный профиль сохранён; потребуется восстановление службы.",
        "SETUP_INCOMPLETE"=>"Найдена неполная или несовместимая установка служб. Автоматическое обновление остановлено.",
        "SETUP_FAILED"=>"Установка/обновление не завершены. Проверьте подтверждение UAC и состав распакованной сборки.",
        _=>"Действие не выполнено. Проверьте состояние службы и права установки. Секреты в журнал не записываются."
    };

    private static string ImportedName(string share)
    {
        try{var text=share["freeturn://".Length..].Replace('-','+').Replace('_','/');text=text.PadRight((text.Length+3)/4*4,'=');var node=JsonNode.Parse(Convert.FromBase64String(text));var value=node?["name"]?.GetValue<string>();if(!string.IsNullOrWhiteSpace(value)&&value.Length<=128&&!value.Any(char.IsControl))return value;}
        catch{}return "Импортированный сервер";
    }

    private async Task SelectServer(SavedProfile profile)
    {
        intent.Stop();
        if(!Idle)throw new IOException("STOP_BEFORE_IMPORT");
        await Validate(profile.Share);
        notice.Text="Сервер выбран. Подключение — кнопкой на главном экране.";
    }
    private bool HasSelectedProfile(){try{var data=catalog.Read();return data.Profiles.Any(p=>p.Id==data.ActiveId);}catch{return false;}}
    private void UpdatePrimary(ServiceReply reply)
    {
        ProfileSnapshot? data=null;try{data=catalog.Read();}catch{}var entries=data?.Profiles.Count??0;var ready=data is not null&&(data.Profiles.Any(p=>p.Id==data.ActiveId)||entries==0&&reply.HasProfile);
        primaryLabel.Text=Idle?(ready?(reply.State=="error"?"Повторить подключение":"Подключить"):"Добавить / выбрать сервер"):reply.State=="connected"?"Отключить":"Отменить подключение";
        if(reply.State=="stopped"){
            state.Text=ready?"Готово к подключению":entries>0?"Выберите сервер":"Добавьте сервер";
            detail.Text=ready?"Нажмите «Подключить». FreeTurn проверит ядро и подготовит соединение.":entries>0?"Выберите профиль из каталога. Старая копия службы автоматически не подставляется.":"Добавьте ссылку или файл профиля. Сервер останется на этом компьютере.";
        }
        var selected=data?.Profiles.FirstOrDefault(p=>p.Id==data.ActiveId);
        if(!Idle&&selected is not null&&ProfileIdentity.Valid(reply.RuntimeProfileIdentity)&&ProfileIdentity.Of(selected.Share)!=reply.RuntimeProfileIdentity)effective.ToolTip=(effective.ToolTip?.ToString()??"")+"\nСохранённые изменения применятся при следующем подключении. Сейчас ядро использует прежние параметры.";
        System.Windows.Automation.AutomationProperties.SetName(connect,primaryLabel.Text);
    }

    private void SaveManualCaptchaPreference()
    {
        if(designPreview)return;
        try{catalog.SetForceManualCaptcha(auto.IsChecked!=true);notice.Text="Режим CAPTCHA сохранён для следующего подключения.";}catch{notice.Text="Режим CAPTCHA не сохранён.";}
    }
    private void SaveCaptchaPreference()
    {
        try{catalog.SetAdvancedCaptcha(advanced.IsChecked==true);}catch{notice.Text="Настройка не сохранена. Повреждённый каталог не перезаписан.";}
    }
    private void UpdateServerSummary(bool hasProfile)
    {
        try{
            var snapshot=catalog.Read();var active=snapshot.Profiles.FirstOrDefault(p=>p.Id==snapshot.ActiveId);
            hasProfile=hasProfile&&snapshot.Profiles.Count==0;
            serverName.Text=active?.Name??(hasProfile?"Профиль Windows":"Выберите сервер");
            if(active is null)serverAddress.Text=hasProfile?"Сохранён в службе":"Добавьте ссылку на вкладке «Добавить»";
            else{var document=new ShareDocument(active.Share);serverAddress.Text=(document.Values.Provider=="direct"?"Direct · ":"VK Relay · ")+(document.IsAmneziaWG?"AmneziaWG · ":"")+document.Values.Peer;}
        }
        catch{serverName.Text="Каталог недоступен";serverAddress.Text="Сохранённые данные не изменены";}
    }
    private void SaveDesktopPreference(){try{catalog.SetCloseToTray(closeToTray.IsChecked==true);}catch{notice.Text="Настройки окна не сохранены. Каталог не изменён.";}}
}
