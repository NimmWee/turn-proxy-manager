using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace FreeTurn.Windows;
internal sealed class SocksWindow : InAppPage
{
    internal SocksWindow(Window? owner, ProfileCatalog catalog, bool preview = false)
    {
        Owner = owner; Title = "SOCKS5 — FreeTurn"; Width = 480; MinWidth = 420;
        Height = Math.Min(800, SystemParameters.WorkArea.Height - 40);
        WindowStartupLocation = WindowStartupLocation.CenterOwner; AndroidSkin.Font(this);
        var panel = AndroidSkin.Page("SOCKS5", "TCP-прокси на 127.0.0.1 для программ с поддержкой SOCKS5. Нужен подтверждённый WireGuard VPN; при его потере прокси останавливается.");
        Content = new ScrollViewer { Content = panel, Background = Background, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var saved = catalog.Read().LocalProxy ?? new SocksSettings(Password: Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18)));
        var fields = new StackPanel();
        TextBox Field(string label, string value)
        {
            fields.Children.Add(new TextBlock { Text = label, Margin = new Thickness(0, 10, 0, 6) });
            var box = new TextBox { Text = value, Padding = new Thickness(10), MaxLength = 255 }; fields.Children.Add(box); return box;
        }
        var port = Field("Порт", saved.Port.ToString(CultureInfo.InvariantCulture)); var username = Field("Пользователь", saved.User);
        fields.Children.Add(new TextBlock { Text = "Пароль (от 12 байт)", Margin = new Thickness(0, 10, 0, 6) });
        var password = new PasswordBox { Password = saved.Password, Padding = new Thickness(10), MaxLength = 255 }; fields.Children.Add(password);
        var copy = Button("Копировать пароль"); fields.Children.Add(copy); copy.Click += (_, _) => Clipboard.SetText(password.Password);
        panel.Children.Add(AndroidSkin.Card(fields)); panel.Children.Add(AndroidSkin.Section("Правила для этого прокси"));
        SocksSettings ReadForm()
        {
            var value = new SocksSettings(int.Parse(port.Text, CultureInfo.InvariantCulture), username.Text, password.Password, saved.Routing);
            if (!value.Valid) throw new System.IO.IOException(); return value;
        }
        var route = AndroidSkin.Entry("Advanced", "Маршрутизация SOCKS5", "Домены: напрямую, через VPN или блокировать", async () =>
        {
            try
            {
                var form = ReadForm();
                await new RoutingWindow(this, saved.Routing, policy => { var next = form with { Routing = policy }; catalog.SetProxy(next); saved = next; }, preview).OpenAsync();
            }
            catch { MessageBox.Show(DialogOwner, "Проверьте порт, пользователя и пароль. Настройки не изменены.", "SOCKS5"); }
        });
        panel.Children.Add(AndroidSkin.Group(route));
        var limits = AndroidSkin.Text("Правила действуют только для SOCKS5 TCP/IPv4. В программе включите передачу доменов и DNS через SOCKS5 (socks5h). UDP/IPv6/LAN и системная раздельная маршрутизация пока недоступны. Новые правила применяются после остановки и нового запуска прокси.", 13, true); panel.Children.Add(limits);
        var actions = new WrapPanel(); var save = Button("Сохранить настройки"); var start = Button("Запустить"); var stop = Button("Остановить"); actions.Children.Add(save); actions.Children.Add(start); actions.Children.Add(stop); panel.Children.Add(actions);
        var status = AndroidSkin.Text("", 13, true); status.Margin = new Thickness(0, 16, 0, 0); panel.Children.Add(status);
        var busy = false; var refreshing = false; var closed = false; var supported = false; var routingSupported = false;
        async Task Refresh()
        {
            if (refreshing || closed) return; refreshing = true;
            try
            {
                var reply = await ServiceClient.Send("status");
                supported = reply.Capabilities?.Contains("socks-tcp-v1") == true;
                routingSupported = reply.Capabilities?.Contains("socks-domain-routing-v1") == true;
                start.IsEnabled = !busy && supported && reply.State == "connected" && reply.SocksPort == 0 && reply.SystemRouting?.Requested!=true;
                stop.IsEnabled = !busy && supported && reply.SocksPort > 0;
                status.Text = reply.SocksPort > 0 ? $"SOCKS5 работает: 127.0.0.1:{reply.SocksPort}" : supported ? "Прокси остановлен. Запуск доступен после проверки VPN." : "Для запуска SOCKS5 нужна служба0.4 или новее.";
                if(reply.SystemRouting?.Requested==true)status.Text="Сейчас используется системная маршрутизация для всех программ. Отдельный SOCKS5 в этом режиме пока не поддерживается.";
                if (!routingSupported && saved.Routing?.Rules.Count > 0) status.Text += " Для доменных правил обновите службу до0.6 или новее; они не будут проигнорированы.";
            }
            catch { start.IsEnabled = stop.IsEnabled = false; status.Text = "Служба недоступна. Локальное редактирование и сохранение доступны."; }
            finally { refreshing = false; }
        }
        async Task Act(Func<Task> action)
        {
            if (busy) return; busy = true; panel.IsEnabled = false; string? error = null;
            try { await action(); }
            catch { error = "Операция не выполнена. Проверьте VPN, службу, правила, порт и учётные данные."; }
            finally { busy = false; panel.IsEnabled = true; await Refresh(); if (error is not null) status.Text = error; }
        }
        async Task Save()
        {
            var next = ReadForm();
            if (next.Routing is not null) next = next with { Routing = (await RoutingCheck.Run(next.Routing)).Policy };
            catalog.SetProxy(next); saved = next;
        }
        save.Click += async (_, _) => await Act(Save);
        start.Click += async (_, _) => await Act(async () =>
        {
            if (!supported || saved.Routing?.Rules.Count > 0 && !routingSupported) throw new System.IO.IOException();
            await Save(); var result = await ServiceClient.StartSocks(saved); if (!result.Ok) throw new System.IO.IOException();
        });
        stop.Click += async (_, _) => await Act(async () => { if (supported) { var result = await ServiceClient.Send("socks-stop"); if (!result.Ok) throw new System.IO.IOException(); } });
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) }; timer.Tick += async (_, _) => await Refresh();
        panel.Loaded += async (_, _) => { if (preview) { start.IsEnabled = stop.IsEnabled = copy.IsEnabled = save.IsEnabled = false; status.Text = "Предпросмотр. Служба и сеть не используются."; } else { await Refresh(); timer.Start(); } };
        CanLeave=()=>!busy; Closing += (_, e) => { if (busy) e.Cancel = true; }; void Cleanup(){closed=true;timer.Stop();} Closed+=(_,_)=>Cleanup();PageClosed+=Cleanup;
    }
    private static Button Button(string text) => new() { Content = text, Padding = new Thickness(12, 10, 12, 10), Margin = new Thickness(0, 12, 8, 0), Background = UiTheme.Button, Foreground = Brushes.White };
}
