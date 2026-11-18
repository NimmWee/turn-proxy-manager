using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FreeTurn.Windows;

internal sealed class ProfileEditor : InAppPage
{
    internal string? EditedShare { get; private set; }
    internal string EditedName { get; private set; }="";
    private readonly ShareDocument document;
    private readonly string initialWireGuardText;
    private bool saving;
    private readonly TextBox name=new(),peer=new(),streams=new(),credentials=new(),dnsServers=new();
    private readonly PasswordBox callLink=new(){Padding=new Thickness(10)};
    private readonly ComboBox dns=new(){ItemsSource=new[]{"auto","plain","doh"},Padding=new Thickness(8)};
    private readonly ComboBox provider=new(){ItemsSource=new[]{"vk","direct"},Padding=new Thickness(8)},transport=new(){ItemsSource=new[]{"tcp","udp"},Padding=new Thickness(8)},obf=new(){ItemsSource=new[]{"none","rtpopus","rtpopus2","rtpopus3"},Padding=new Thickness(8)};
    private readonly PasswordBox obfKey=new(){Padding=new Thickness(10),MaxLength=64};private readonly TextBox timing=new(){MaxLength=4};
    private readonly ComboBox proxyMode=new(){ItemsSource=new[]{"udp","tcp"},Padding=new Thickness(8)};
    private readonly TextBox listen=new(){MaxLength=128},kcp=new(){AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,Height=140,MaxLength=4096,IsUndoEnabled=false};
    private readonly CheckBox bond=new(){Content="Bond для TCP-проброса",Foreground=UiTheme.Foreground,Margin=new Thickness(0,14,0,14)};
    private readonly CheckBox manual=new(){Content="Ручная CAPTCHA",Foreground=UiTheme.Foreground,Margin=new Thickness(0,14,0,14)};
    private readonly TextBox wg=new(){AcceptsReturn=true,TextWrapping=TextWrapping.NoWrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Auto,Height=220,IsUndoEnabled=false,FontFamily=new FontFamily("Consolas"),Visibility=Visibility.Collapsed};
    private readonly TextBlock error=new(){TextWrapping=TextWrapping.Wrap,Foreground=UiTheme.Error,Margin=new Thickness(0,12,0,12)};
    internal ProfileEditor(Window? owner,SavedProfile profile,Func<string,Task> validate)
    {
        document=new ShareDocument(profile.Share);if(owner is not null)Owner=owner;Title="Параметры подключения — FreeTurn";Width=480;MinWidth=420;var availableHeight=Math.Max(420,SystemParameters.WorkArea.Height-40);Height=Math.Min(800,availableHeight);MinHeight=Math.Min(500,availableHeight);
        WindowStartupLocation=owner is null?WindowStartupLocation.CenterScreen:WindowStartupLocation.CenterOwner;Background=UiTheme.Background;Foreground=UiTheme.Foreground;FontFamily=UiTheme.Font;
        var root=new DockPanel();Content=new Border{Padding=new Thickness(24),Background=Background,Child=root};
        var actions=new WrapPanel();var footer=new StackPanel();footer.Children.Add(actions);footer.Children.Add(error);DockPanel.SetDock(footer,Dock.Bottom);root.Children.Add(footer);
        var save=MakeButton("Сохранить");var cancel=MakeButton("Отмена");actions.Children.Add(save);actions.Children.Add(cancel);cancel.Click+=(_,_)=>{if(owner is null)Close();else DialogResult=false;};
        var content=new StackPanel();root.Children.Add(new ScrollViewer{Content=content,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});
        var title=AndroidSkin.Text("Подключение",36);title.FontWeight=FontWeights.Bold;title.Margin=new Thickness(0,0,0,20);content.Children.Add(title);
        StackPanel Group(string label,bool expanded=true){content.Children.Add(AndroidSkin.Section(label));var panel=new StackPanel();var card=AndroidSkin.Card(panel);card.Margin=new Thickness(0,0,0,12);if(expanded)content.Children.Add(card);else{content.Children.Add(new Expander{Header="Показать параметры",Content=card,Foreground=UiTheme.Foreground,Padding=new Thickness(0),Margin=new Thickness(0,0,0,12)});}return panel;}
        var basic=Group("Сервер");Add(basic,"Название",name);Add(basic,"Адрес сервера",peer);Add(basic,"Способ подключения",provider);Add(basic,"Ссылка на звонок",callLink);
        var connection=Group("Соединение");Add(connection,"Транспорт до TURN",transport);Add(connection,"Количество потоков",streams);streams.ToolTip="От 1 до 32. В автоматическом Direct используется 1; Relay использует сохранённое значение.";Add(connection,"Потоков на учётные данные",credentials);credentials.ToolTip="От 1 до 16, только для VK Relay.";connection.Children.Add(manual);
        var resolver=Group("DNS подключения FreeTurn");Add(resolver,"Режим DNS",dns);Add(resolver,"Свои DNS-серверы через запятую",dnsServers);resolver.Children.Add(AndroidSkin.Text("Этот DNS используется для служебных запросов FreeTurn. DNS трафика VPN задаётся строкой DNS в разделе Interface параметров WireGuard.",13,true));
        var obfuscation=Group("Обфускация",false);Add(obfuscation,"Профиль",obf);Add(obfuscation,"Ключ обфускации (hex)",obfKey);Add(obfuscation,"Пауза, мс",timing);obfuscation.Children.Add(AndroidSkin.Text("Параметры должны совпадать с сервером.",13,true));
        var forwarding=Group("Проброс и KCP",false);Add(forwarding,"Прикладной режим",proxyMode);Add(forwarding,"Локальный адрес",listen);forwarding.Children.Add(bond);Add(forwarding,"KCP JSON (пусто — настройки ядра)",kcp);forwarding.Children.Add(AndroidSkin.Text("Для системного WireGuard нужны UDP и адрес 127.0.0.1:9000. Отдельный TCP/UDP-проброс использует пустой WG и не включает VPN всего ПК. Перед сменой режима сохраните копию.",13,true));
        var reveal=MakeButton("Показать параметры WireGuard");content.Children.Add(reveal);
        reveal.Click+=(_,_)=>{wg.Visibility=wg.Visibility==Visibility.Visible?Visibility.Collapsed:Visibility.Visible;reveal.Content=wg.Visibility==Visibility.Visible?"Скрыть параметры WireGuard":"Показать параметры WireGuard";};
        content.Children.Add(wg);content.Children.Add(new TextBlock{Text="Сохранение сохраняет выбор сервера. Изменения применятся при следующем подключении; текущее соединение продолжит работать с прежними параметрами. В автоматическом режиме Direct использует один поток, Relay — указанное здесь количество.",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,16,0,0)});
        var value=document.Values;name.Text=profile.Name;peer.Text=value.Peer;callLink.Password=value.CallLink;streams.Text=value.Streams.ToString(CultureInfo.InvariantCulture);credentials.Text=value.StreamsPerCredential.ToString(CultureInfo.InvariantCulture);dns.SelectedItem=value.DnsMode;dnsServers.Text=value.DnsServers;manual.IsChecked=value.ManualCaptcha;wg.Text=document.WireGuard;
        initialWireGuardText=wg.Text;CanLeave=()=>!saving;Closing+=(_,e)=>{if(saving)e.Cancel=true;};
        provider.SelectedItem=value.Provider;transport.SelectedItem=value.Transport;obf.SelectedItem=value.ObfProfile;obfKey.Password=value.ObfKey;timing.Text=value.Timing.ToString(CultureInfo.InvariantCulture);
        proxyMode.SelectedItem=value.ProxyMode;listen.Text=value.Listen;bond.IsChecked=value.Bond;kcp.Text=value.KcpJson;
        void UpdateProvider(){var relay=(provider.SelectedItem as string)!="direct";callLink.IsEnabled=manual.IsEnabled=credentials.IsEnabled=transport.IsEnabled=relay;}
        provider.SelectionChanged+=(_,_)=>UpdateProvider();UpdateProvider();
        name.MaxLength=128;peer.MaxLength=300;callLink.MaxLength=4096;streams.MaxLength=3;credentials.MaxLength=3;dnsServers.MaxLength=4096;wg.MaxLength=65536;
        save.Click+=async(_,_)=>{
            saving=true;content.IsEnabled=save.IsEnabled=cancel.IsEnabled=false;error.Text="";
            try{
                var values=new ProfileEdits(name.Text,peer.Text,callLink.Password,int.Parse(streams.Text,CultureInfo.InvariantCulture),int.Parse(credentials.Text,CultureInfo.InvariantCulture),dns.SelectedItem as string??"auto",dnsServers.Text,manual.IsChecked==true,provider.SelectedItem as string??"vk",transport.SelectedItem as string??"tcp",obf.SelectedItem as string??"none",obfKey.Password,int.Parse(timing.Text,CultureInfo.InvariantCulture),proxyMode.SelectedItem as string??"udp",listen.Text,bond.IsChecked==true,kcp.Text);
                var share=document.Build(values,wg.Text==initialWireGuardText?null:wg.Text);
                await validate(share);EditedShare=share;EditedName=values.Name.Trim();saving=false;if(owner is null)Close();else DialogResult=true;
            }catch{error.Text="Не сохранено. Потоки: 1–32; на учётные данные: 1–16. Проверьте также адреса, режим, KCP, DNS и WireGuard. Сохранённый профиль не изменён.";}
            finally{saving=false;content.IsEnabled=save.IsEnabled=cancel.IsEnabled=true;}
        };
    }
    private static void Add(Panel panel,string label,Control control)
    {
        panel.Children.Add(new TextBlock{Text=label,Margin=new Thickness(0,12,0,5),TextWrapping=TextWrapping.Wrap});
        System.Windows.Automation.AutomationProperties.SetName(control,label);
        if(control is TextBox text){text.Padding=new Thickness(10);text.IsUndoEnabled=false;}
        panel.Children.Add(control);
    }
    private static Button MakeButton(string label)=>new(){Content=label,Padding=new Thickness(14,10,14,10),Margin=new Thickness(0,8,8,8),Background=UiTheme.Button,Foreground=Brushes.White};
}
