using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Microsoft.Win32;

namespace FreeTurn.Windows;

internal sealed class ApplicationRulesWindow:InAppPage
{
 private sealed record Choice(string Action,string Label){public override string ToString()=>Label;}
 internal ApplicationRulesWindow(Window? owner,IEnumerable<SystemAppRule> current,Action<List<SystemAppRule>> save,Func<List<SystemAppRule>,Task>? validate=null,bool preview=false)
 {
  Owner=owner;Title="Правила приложений — FreeTurn";AndroidSkin.Font(this);Width=480;Height=780;
  var root=new DockPanel{Background=UiTheme.Background};Content=root;
  var footer=new StackPanel{Margin=new Thickness(24,8,24,16)};DockPanel.SetDock(footer,Dock.Bottom);root.Children.Add(footer);
  var panel=AndroidSkin.Page("Правила приложений","Работают только в раздельном режиме после нового подключения. Путь EXE определяет приложение; отдельные сетевые помощники требуют своих правил.");
  root.Children.Add(new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});
  panel.Children.Add(AndroidSkin.Text("Правило приложения выше обычных доменных правил и пресетов. Блокировки и защита служебных адресов сохраняются. DNS общий. При невозможности определить владельца соединение блокируется. Проверка владельца UDP может увеличить нагрузку.",13,true));
  var rules=current.ToList();var selected=-1;
  panel.Children.Add(AndroidSkin.Section("Исполняемый файл"));
  var path=new TextBox{MaxLength=1024,Margin=new Thickness(0,0,0,8)};System.Windows.Automation.AutomationProperties.SetName(path,"Путь приложения");panel.Children.Add(path);
  var browse=new Button{Content="Выбрать EXE…",Padding=new Thickness(16,10,16,10),HorizontalAlignment=HorizontalAlignment.Left};panel.Children.Add(browse);
  var choice=new ComboBox{ItemsSource=new[]{new Choice("vpn","Через VPN"),new Choice("direct","Напрямую"),new Choice("block","Блокировать")},SelectedIndex=0,Margin=new Thickness(0,16,0,8)};panel.Children.Add(choice);
  var add=new Button{Content="Добавить правило",Padding=browse.Padding,Margin=new Thickness(0,0,0,16)};panel.Children.Add(add);
  var list=new ListBox{Height=210,Background=UiTheme.Background,Foreground=UiTheme.Foreground,BorderThickness=new Thickness(0)};
  var template=new DataTemplate(typeof(SystemAppRule));var text=new FrameworkElementFactory(typeof(TextBlock));text.SetBinding(TextBlock.TextProperty,new Binding("Display"));text.SetValue(TextBlock.TextWrappingProperty,TextWrapping.Wrap);text.SetValue(TextBlock.MarginProperty,new Thickness(8));template.VisualTree=text;list.ItemTemplate=template;ScrollViewer.SetHorizontalScrollBarVisibility(list,ScrollBarVisibility.Disabled);panel.Children.Add(list);
  var remove=new Button{Content="Удалить выбранное",Padding=browse.Padding,Margin=new Thickness(0,8,0,16)};panel.Children.Add(remove);
  panel.Children.Add(AndroidSkin.Text("Локальный полный путь, до 64 правил. Ярлыки, UNC, маски и переменные окружения не поддерживаются. Другая версия EXE по другому пути не наследует правило. Это настройка маршрута по пути, а не проверка подписи программы.",13,true));
  var status=AndroidSkin.Text("После возврата сохраните настройки маршрутизации.",13,true);footer.Children.Add(status);
  var row=new WrapPanel();var done=new Button{Content="Готово",Padding=browse.Padding,Margin=new Thickness(0,8,8,0)};var back=new Button{Content="Назад",Padding=browse.Padding,Margin=done.Margin};row.Children.Add(done);row.Children.Add(back);footer.Children.Add(row);
  void Refresh(){list.ItemsSource=rules.ToList();selected=-1;list.SelectedIndex=-1;add.Content="Добавить правило";}
  Refresh();list.SelectionChanged+=(_,_)=>{selected=list.SelectedIndex;if(selected>=0){var rule=rules[selected];path.Text=rule.Path;choice.SelectedIndex=rule.Action=="vpn"?0:rule.Action=="direct"?1:2;add.Content="Обновить правило";}};
  browse.Click+=(_,_)=>{var dialog=new OpenFileDialog{Filter="Приложения Windows (*.exe)|*.exe",CheckFileExists=true,Multiselect=false};if(dialog.ShowDialog(DialogOwner)==true)path.Text=dialog.FileName;};
  add.Click+=(_,_)=>{
   var rule=new SystemAppRule(path.Text.Trim(),((Choice)choice.SelectedItem).Action);
   if(!rule.Valid){status.Text="Укажите полный локальный путь к EXE, например C:\\Apps\\Browser.exe.";return;}
   if(rules.Where((_,i)=>i!=selected).Any(r=>string.Equals(r.Path,rule.Path,StringComparison.OrdinalIgnoreCase))){status.Text="Для этого пути уже есть правило.";return;}
   if(selected<0&&rules.Count>=64){status.Text="Доступно до 64 правил.";return;}
   if(selected>=0)rules[selected]=rule;else rules.Add(rule);Refresh();path.Clear();status.Text="Правило добавлено в черновик. Нажмите «Готово», затем сохраните маршрутизацию.";
  };
  remove.Click+=(_,_)=>{if(selected>=0){rules.RemoveAt(selected);Refresh();path.Clear();}};
  var busy=false;CanLeave=()=>!busy;
  done.Click+=async(_,_)=>{if(busy)return;busy=true;panel.IsEnabled=footer.IsEnabled=false;try{var copy=rules.ToList();if(!(new SystemRoutingSettings{AppRules=copy}).Valid)throw new System.IO.IOException();if(validate is not null)await validate(copy);save(copy);busy=false;DialogResult=true;}catch{status.Text="Правила не подтверждены. Проверьте пути и наличие ядра из этого пакета.";}finally{busy=false;panel.IsEnabled=footer.IsEnabled=true;}};
  back.Click+=(_,_)=>Close();if(preview){browse.IsEnabled=add.IsEnabled=remove.IsEnabled=done.IsEnabled=false;}
 }
}
