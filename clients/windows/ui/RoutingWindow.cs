using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FreeTurn.Windows;

internal sealed class RoutingWindow : InAppPage
{
    private sealed record ActionOption(string Key, string Label) { public override string ToString() => Label; }

    internal RoutingWindow(Window? owner, RoutingPolicy? current, Action<RoutingPolicy> savePolicy, bool preview = false,bool systemMode=false,Func<RoutingPolicy,string?,Task<RoutingResult>>? validate=null)
    {
        Owner = owner; Title = systemMode?"Правила системной маршрутизации — FreeTurn":"Маршрутизация SOCKS5 — FreeTurn";
        Width = 520; MinWidth = 420; Height = Math.Min(860, SystemParameters.WorkArea.Height - 40);
        WindowStartupLocation = WindowStartupLocation.CenterOwner; AndroidSkin.Font(this);
        var panel = AndroidSkin.Page("Маршрутизация", systemMode?"Доменные исключения для всех программ в новом режиме. Проверка показывает решение при включённой системной маршрутизации; сохранение черновика не меняет сеть.":"Правила только для программ, использующих SOCKS5 FreeTurn. Системный VPN и остальные программы эти правила пока не используют.");
        var root = new DockPanel { Background = Background }; Content = root;
        var footer = new StackPanel { Margin = new Thickness(24, 8, 24, 16) }; DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        root.Children.Add(new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Background = Background });
        var hint = AndroidSkin.Text(systemMode?"BLOCK и защита служебных адресов выше исключений. Явные доменные правила выше пресетов. По умолчанию — VPN. При ошибке VPN прямой обход не включается.":"Без совпадения — через VPN. BLOCK выше разрешений; затем выбирается наиболее точное правило. DIRECT использует обычный IP и DNS физической сети. При потере VPN останавливается весь SOCKS5.", 14, true);
        hint.Margin = new Thickness(0, 0, 0, 20); panel.Children.Add(hint);
        var rules = new List<DomainRule>(current?.Rules ?? []);
        var editIndex = -1;
        var form = new StackPanel();
        form.Children.Add(AndroidSkin.Text("Домен без https:// и пути"));
        var domain = new TextBox { MaxLength = 1024, Margin = new Thickness(0, 8, 0, 12) }; form.Children.Add(domain);
        var options = new[] { new ActionOption("direct", "Напрямую"), new ActionOption("vpn", "Через VPN"), new ActionOption("block", "Блокировать") };
        var action = new ComboBox { ItemsSource = options, SelectedIndex = 0 }; form.Children.Add(action);
        var subdomains = new CheckBox { Content = "Включая поддомены", IsChecked = true }; form.Children.Add(subdomains);
        var add = Button("Добавить правило"); form.Children.Add(add); panel.Children.Add(AndroidSkin.Card(form));
        panel.Children.Add(AndroidSkin.Section("Сохранённые правила"));
        panel.Children.Add(AndroidSkin.Text("Поиск по домену", 13, true));
        var search = new TextBox { MaxLength = 253, Margin = new Thickness(0, 0, 0, 8), ToolTip = "Поиск по домену" };
        System.Windows.Automation.AutomationProperties.SetName(search, "Поиск правил"); panel.Children.Add(search);
        var list = new ListBox { Height = 200, Background = Brushes.Transparent, Foreground = Foreground, BorderThickness = new Thickness(0) };
        ScrollViewer.SetHorizontalScrollBarVisibility(list, ScrollBarVisibility.Disabled);
        var template = new DataTemplate(typeof(DomainRule)); var item = new FrameworkElementFactory(typeof(TextBlock));
        item.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding()); item.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap); item.SetValue(TextBlock.MarginProperty, new Thickness(12)); template.VisualTree = item; list.ItemTemplate = template;
        panel.Children.Add(list);
        void RefreshList() => list.ItemsSource = rules.Where(r => r.Domain.Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToList();
        search.TextChanged += (_, _) => RefreshList(); RefreshList();
        var row = new WrapPanel(); var edit = Button("Изменить"); var delete = Button("Удалить"); var clear = Button("Отменить правку"); row.Children.Add(edit); row.Children.Add(delete); row.Children.Add(clear); panel.Children.Add(row);
        void ResetForm() { editIndex = -1; domain.Text = ""; add.Content = "Добавить правило"; }
        edit.Click += (_, _) => { if (list.SelectedItem is not DomainRule selected) return; editIndex = rules.IndexOf(selected); domain.Text = selected.Domain; action.SelectedItem = options.First(o => o.Key == selected.Action); subdomains.IsChecked = selected.Subdomains; add.Content = "Применить правку"; };
        delete.Click += (_, _) => { if (list.SelectedItem is DomainRule selected) { rules.Remove(selected); ResetForm(); RefreshList(); } };
        clear.Click += (_, _) => ResetForm();
        var status = AndroidSkin.Text(systemMode?"До 300 правил. Вернитесь к настройкам и сохраните их; применяются при следующем подключении.":"До 300 правил. Изменения применяются после нового запуска SOCKS5.", 13, true); status.Margin = new Thickness(0, 4, 0, 8);
        panel.Children.Add(AndroidSkin.Section("Проверить домен"));
        var probe = new TextBox { MaxLength = 1024 }; panel.Children.Add(probe); var check = Button("Показать маршрут"); panel.Children.Add(check); footer.Children.Add(status);
        var actions = new WrapPanel(); var save = Button("Сохранить"); var cancel = Button("Закрыть"); actions.Children.Add(save); actions.Children.Add(cancel); footer.Children.Add(actions);
        var busy = false; var unsavedForm = false; var allowClose = false;
        Task<RoutingResult> Validate(RoutingPolicy p,string? host=null)=>validate is null?RoutingCheck.Run(p,host):validate(p,host);
        domain.TextChanged += (_, _) => unsavedForm = domain.Text.Length > 0;
        async Task Act(Func<Task> work)
        {
            if (busy) return; busy = true; panel.IsEnabled = footer.IsEnabled = false;
            try { await work(); }
            catch { status.Text = "Правило не принято. Нужен домен без URL/порта; IP, публичные суффиксы и конфликты запрещены. Сохранённые настройки не изменены."; }
            finally { busy = false; panel.IsEnabled = footer.IsEnabled = true; }
        }
        add.Click += async (_, _) => await Act(async () =>
        {
            var candidate = new List<DomainRule>(rules); var rule = new DomainRule(domain.Text, ((ActionOption)action.SelectedItem).Key, subdomains.IsChecked == true);
            if (editIndex >= 0) candidate[editIndex] = rule; else candidate.Add(rule);
            var result = await Validate(new(1, candidate)); rules = result.Policy.Rules; ResetForm(); RefreshList(); status.Text = "Правило добавлено в черновик. Нажмите «Сохранить».";
        });
        check.Click += async (_, _) => await Act(async () =>
        {
            if (string.IsNullOrWhiteSpace(probe.Text)) { status.Text = "Введите домен для локальной проверки."; return; }
            var result = await Validate(new(1, rules), probe.Text);
            status.Text = "Маршрут: " + DomainRule.ActionLabel(result.Decision!.Action) + (result.Decision.Rule is null ? " · правило по умолчанию" : " · найдено доменное правило") + ". Проверка без DNS и сетевого подключения.";
        });
        save.Click += async (_, _) => await Act(async () =>
        {
            if (unsavedForm) { status.Text = "Сначала добавьте введённое правило или отмените правку."; return; }
            var result = await Validate(new(1, rules)); savePolicy(result.Policy); allowClose = true; Close();
        });
        CanLeave=()=>!busy||allowClose; cancel.Click += (_, _) => Close(); Closing += (_, e) => { if (busy && !allowClose) e.Cancel = true; };
        if (preview) { domain.Text = "example.com"; add.IsEnabled = save.IsEnabled = check.IsEnabled = delete.IsEnabled = edit.IsEnabled = clear.IsEnabled = false; status.Text = "Предпросмотр: синтетические правила, сеть и служба не используются."; }
    }
    private static Button Button(string label) => new() { Content = label, Padding = new Thickness(16, 10, 16, 10), Margin = new Thickness(0, 8, 8, 0), Background = UiTheme.Button, Foreground = Brushes.White };
}
