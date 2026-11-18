using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Diagnostics;

namespace FreeTurn.Windows;

internal sealed class SystemRoutingWindow : InAppPage
{
    internal SystemRoutingWindow(Window? owner,ProfileCatalog catalog,bool preview=false)
    {
        Owner=owner;Title="Системная маршрутизация — FreeTurn";AndroidSkin.Font(this);
        Width=520;MinWidth=420;Height=Math.Min(860,SystemParameters.WorkArea.Height-40);
        var saved=catalog.Read().SystemRouting??new SystemRoutingSettings();
        var rules=new List<DomainRule>(saved.Rules);var presets=saved.Presets;
        var appRules=new List<SystemAppRule>(saved.AppRules??[]);
        var root=new DockPanel{Background=Background};Content=root;
        var footer=new StackPanel{Margin=new Thickness(24,8,24,16)};DockPanel.SetDock(footer,Dock.Bottom);root.Children.Add(footer);
        var panel=AndroidSkin.Page("Системная маршрутизация","Экспериментальный режим для всех программ. Обычный VPN остаётся по умолчанию; изменения вступают в силу после нового подключения.");
        root.Children.Add(new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});
        var enabled=new CheckBox{Content="Использовать раздельную маршрутизацию",IsChecked=saved.Enabled};panel.Children.Add(AndroidSkin.SwitchGroup(enabled));
        CheckBox Option(string label,string hint,bool value)=>new(){Content=label,ToolTip=hint,IsChecked=value};
        var ru=Option("Российские сайты напрямую","Доменные списки, .ru/.su/.рф и геолокация IPv4 по DB-IP Lite. Возможны ошибки определения страны.",presets.RussianDirect);
        var lan=Option("Локальная сеть напрямую","Домашние устройства по IPv4. Частные имена — через локальный DNS; имена .local — через отдельный поиск в выбранной домашней подсети. Служебные адреса защищены отдельно.",presets.LANDirect);
        var youtube=Option("YouTube через VPN","Имеет приоритет над широким российским списком.",presets.YouTubeVPN);
        var push=Option("Push Apple и Google через VPN","Известные домены мобильных push-сервисов.",presets.PushVPN);
        var connectivity=Option("Проверка интернета напрямую","Системные connectivity checks. Проверка самого VPN всё равно идёт через туннель.",presets.ConnectivityDirect);
        var torrent=Option("Блокировать BitTorrent","Известные BitTorrent/DHT-сигнатуры. Зашифрованный или замаскированный torrent может не распознаться.",presets.BlockBitTorrent);
        var split=Option("Раздельный DNS","DNS следует выбранному маршруту. При ошибке VPN-запрос не переключается на прямое подключение.",presets.SplitDNS);
        panel.Children.Add(AndroidSkin.Section("Готовые правила"));panel.Children.Add(AndroidSkin.SwitchGroup(ru,lan,youtube,push,connectivity,torrent,split));
        var catalogInfo=AndroidSkin.Text("База IP этого пакета — DB-IP Lite. Геолокация приблизительная. Новая база используется после обновления ядра при следующем подключении.",13,true);panel.Children.Add(catalogInfo);
        var attribution=AndroidSkin.Text("",12,true);var sourceLink=new Hyperlink(new Run("IP Geolocation by DB-IP")){NavigateUri=new Uri("https://db-ip.com/"),Foreground=UiTheme.Foreground};
        sourceLink.RequestNavigate+=(_,e)=>{try{Process.Start(new ProcessStartInfo("https://db-ip.com/"){UseShellExecute=true});}catch{}e.Handled=true;};attribution.Inlines.Add(sourceLink);attribution.Inlines.Add(" · CC BY 4.0");panel.Children.Add(attribution);
        panel.Children.Add(AndroidSkin.Section("Исключения для доменов"));
        var ruleSummary=AndroidSkin.Text($"Правил: {rules.Count}. Явные исключения выше пресетов; блокировки и защита служебных адресов сохраняются.",13,true);panel.Children.Add(ruleSummary);
        var edit=new Button{Content="Настроить домены…",Margin=new Thickness(0,8,0,20),Padding=new Thickness(16,10,16,10)};panel.Children.Add(edit);
        panel.Children.Add(AndroidSkin.Section("Приложения"));var appSummary=AndroidSkin.Text($"Правил приложений: {appRules.Count}. Используется полный путь EXE. DNS остаётся общим.",13,true);panel.Children.Add(appSummary);
        var editApps=new Button{Content="Настроить приложения…",Margin=edit.Margin,Padding=edit.Padding};panel.Children.Add(editApps);
        panel.Children.Add(AndroidSkin.Section("DNS для прямого маршрута"));
        panel.Children.Add(AndroidSkin.Text("IPv4-адреса, по одному в строке (до четырёх). По умолчанию — Яндекс. DNS VPN берётся из выбранного профиля.",13,true));
        var dns=new TextBox{Text=string.Join(Environment.NewLine,saved.DirectDNS),AcceptsReturn=true,MaxLength=128,Height=120,Padding=new Thickness(16),Margin=new Thickness(0,8,0,20)};panel.Children.Add(dns);
        var actual=AndroidSkin.Text("Состояние службы ещё не прочитано.",13,true);panel.Children.Add(AndroidSkin.Card(actual));
        var refresh=new Button{Content="Обновить состояние",Margin=new Thickness(0,0,0,16),Padding=new Thickness(16,10,16,10)};panel.Children.Add(refresh);
        panel.Children.Add(AndroidSkin.Text("Поддерживается IPv4. Частные имена используют локальный DNS, .local — отдельный поиск в выбранной домашней подсети. Автоматический список устройств Bonjour пока не поддерживается. Приложения с собственным защищённым DNS или поиском устройств могут обходить этот DNS-маршрутизатор.",13,true));
        var status=AndroidSkin.Text("Настройки не применяются к уже открытому соединению.",13,true);footer.Children.Add(status);
        var actions=new WrapPanel();var save=new Button{Content="Сохранить",Padding=new Thickness(16,10,16,10),Margin=new Thickness(0,8,8,0)};var close=new Button{Content="Закрыть",Padding=save.Padding,Margin=save.Margin};actions.Children.Add(save);actions.Children.Add(close);footer.Children.Add(actions);
        var busy=false;var closed=false;var refreshing=false;PageClosed+=()=>closed=true;CanLeave=()=>!busy;Closing+=(_,e)=>e.Cancel=busy;
        SystemRoutingSettings Draft()=>new(){Enabled=enabled.IsChecked==true,Rules=new(rules),Presets=new(ru.IsChecked==true,lan.IsChecked==true,youtube.IsChecked==true,push.IsChecked==true,connectivity.IsChecked==true,torrent.IsChecked==true,split.IsChecked==true),DirectDNS=dns.Text.Split(['\r','\n'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).ToList(),AppRules=appRules.Count==0?null:new(appRules)};
        async Task Refresh()
        {
            if(refreshing||closed)return;refreshing=true;
            try{
                var local=await SystemRoutingCheck.Run(new SystemRoutingSettings());if(closed)return;
                catalogInfo.Text=local.GeoIP!.Description+" Новая база используется после обновления ядра при следующем подключении.";
                var reply=await ServiceClient.Send("status");if(closed)return;
                if(!reply.Ok)throw new System.IO.IOException("STATUS_FAILED");
                actual.Text=reply.SystemRouting is{Active:true} active?$"Маршрутизатор работает. VPN: {(reply.State=="connected"?"проверен":"подключается")}\nПотоки: напрямую {active.DirectFlows}, VPN {active.VPNFlows}, заблокировано {active.BlockedFlows}.":reply.SystemRouting is{Requested:true}&&reply.TunnelActive?ConnectionDiagnostics.Stage(reply.SystemRouting.SetupStage):reply.TunnelActive?"Сейчас работает обычный режим VPN.":"Маршрутизатор сейчас выключен.";
                if(reply.Capabilities?.Contains("system-routing-ipv4-v1")!=true)actual.Text+="\nПри подключении потребуется обновить службу из этого пакета.";
                if(reply.Capabilities?.Contains("system-mdns-oneshot-ipv4-v1")!=true)actual.Text+="\nДля поддержки .local нужно ядро из этого пакета; оно проверится при следующем подключении.";
                if(appRules.Count>0&&reply.Capabilities?.Contains("system-app-path-ipv4-v1")!=true)actual.Text+="\nПравила приложений требуют ядро из этого пакета.";
                if(reply.SystemRouting is{Active:true} report){actual.Text+=$"\nDNS-запросы: {report.DNSQueries}, ошибки: {report.DNSErrors}.";actual.Text+=report.LocalDNSReady?"\nDNS локальной сети найден.":"\nЛокальный DNS-сервер не найден.";actual.Text+=report.MDNSConfigured?"\nРежим разрешения имён .local включён.":"\nПоиск .local не настроен для этого канала. Можно использовать IPv4-адрес устройства.";if(!string.IsNullOrEmpty(report.LastError))actual.Text+="\n"+ConnectionDiagnostics.Error(report.LastError);}
                if(reply.SystemRouting is{Active:true,PublicationRevision:>0} published)actual.Text+=$"\nПрименена публикация администратора №{published.PublicationRevision}.";
                if(reply.SystemRouting is{Active:true,AppRules:>0} apps)actual.Text+=$"\nАктивных правил приложений: {apps.AppRules}. Без подтверждённого владельца заблокировано: {apps.UnknownAppFlows}.";
            }catch{if(!closed)actual.Text="Служба недоступна. Можно сохранить настройки; ядро проверится при подключении.";}
            finally{refreshing=false;}
        }
        edit.Click+=async(_,_)=>{
            if(busy)return;
            try{
                if(!Draft().Valid){status.Text="Сначала укажите до четырёх DNS-серверов в виде IPv4-адресов.";return;}
                var editor=new RoutingWindow(this,new(1,new(rules)),policy=>{rules=new(policy.Rules);ruleSummary.Text=$"Правил: {rules.Count}. Не забудьте сохранить настройки маршрутизации.";},systemMode:true,validate:async(policy,host)=>{
                    var result=await SystemRoutingCheck.Run(Draft() with{Enabled=true,Rules=policy.Rules},host);return new RoutingResult(result.Ok,new(1,result.Policy.Rules),result.Decision);
                });await editor.OpenAsync();
            }catch{status.Text="Редактор не открыт. Проверьте DNS-адреса и наличие ядра в пакете.";}
        };
        editApps.Click+=async(_,_)=>{if(busy)return;var editor=new ApplicationRulesWindow(this,appRules,items=>{appRules=items;appSummary.Text=$"Правил приложений: {appRules.Count}. Включите раздельный режим и сохраните маршрутизацию для их применения.";},async items=>{await SystemRoutingCheck.Run(Draft() with{AppRules=items.Count==0?null:items});});await editor.OpenAsync();};
        save.Click+=async(_,_)=>{
            if(busy)return;busy=true;panel.IsEnabled=footer.IsEnabled=false;
            try{var result=await SystemRoutingCheck.Run(Draft());catalog.SetSystemRouting(result.Policy);catalogInfo.Text=result.GeoIP!.Description;status.Text=result.Policy.AppRules is{Count:>0}&&!result.Policy.Enabled?"Правила сохранены, но раздельный режим выключен. Включите его и подключитесь заново для применения.":"Проверено и сохранено. Будет применено при следующем подключении; текущая сеть не менялась.";}
            catch{status.Text="Настройки не сохранены. Проверьте домены/DNS и используйте полный пакет с ядром маршрутизации.";}
            finally{busy=false;panel.IsEnabled=footer.IsEnabled=true;}
        };
        refresh.Click+=async(_,_)=>await Refresh();close.Click+=(_,_)=>Close();if(!preview)panel.Loaded+=async(_,_)=>await Refresh();
        if(preview){actual.Text="Предпросмотр: службы и сеть не используются.";editApps.IsEnabled=edit.IsEnabled=save.IsEnabled=refresh.IsEnabled=false;}
    }
}
