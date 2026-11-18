using System.Windows;
using System.Windows.Controls;

namespace FreeTurn.Windows;

internal sealed class EnrollmentWindow:InAppPage
{
 internal bool ProfilesAdded {get;private set;}
 internal EnrollmentWindow(Window? owner,ProfileCatalog catalog,EnrollmentLink? source=null,bool preview=false)
 {
  Owner=owner;Title="Регистрация устройства — FreeTurn";AndroidSkin.Font(this);Width=480;MinWidth=420;Height=800;
  var panel=AndroidSkin.Page("Регистрация устройства","Постоянная подписка создаёт отдельный доступ для этого компьютера. Сначала сохраняются ключи, затем отправляется запрос. VPN сам не включается.");
  Content=new ScrollViewer{Content=panel,Background=UiTheme.Background,FontFamily=UiTheme.Font,FontSize=14,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
  var summary=AndroidSkin.Text("",14,true);panel.Children.Add(AndroidSkin.Card(summary));
  panel.Children.Add(AndroidSkin.Section("Имя устройства"));var name=new TextBox{Text=preview?"Windows PC":Environment.MachineName,MaxLength=128,Padding=new Thickness(12),Margin=new Thickness(0,8,0,16)};panel.Children.Add(name);
  var viaVpn=new CheckBox{Content="Через уже подключённый FreeTurn",IsChecked=false,Margin=new Thickness(0,8,0,8)};panel.Children.Add(viaVpn);
  panel.Children.Add(AndroidSkin.Text("Обычно используется HTTPS-адрес из подписки. Если он недоступен, можно явно выбрать существующий VPN. Если рабочего VPN нет, попросите у администратора персональный стартовый JSON.",13,true));
  panel.Children.Add(AndroidSkin.Section("Незавершённые регистрации"));
  var list=new ListBox{MinHeight=52,MaxHeight=160,BorderThickness=new Thickness(0),Background=System.Windows.Media.Brushes.Transparent,Foreground=UiTheme.Foreground,Margin=new Thickness(0,8,0,16)};
  var label=new FrameworkElementFactory(typeof(TextBlock));label.SetBinding(TextBlock.TextProperty,new System.Windows.Data.Binding("Name"));label.SetValue(FrameworkElement.MarginProperty,new Thickness(12));label.SetValue(TextBlock.ForegroundProperty,UiTheme.Foreground);label.SetValue(TextBlock.TextTrimmingProperty,TextTrimming.CharacterEllipsis);list.ItemTemplate=new DataTemplate{VisualTree=label};panel.Children.Add(list);
  var actions=new WrapPanel();panel.Children.Add(actions);
  Button Action(string text){var b=new Button{Content=text,Padding=new Thickness(14,11,14,11),Margin=new Thickness(0,0,8,8)};actions.Children.Add(b);return b;}
  var start=Action("Начать регистрацию");var resume=Action("Продолжить регистрацию");var copy=Action("Скопировать ссылку подписки");var close=Action("Назад");
  var status=AndroidSkin.Text("",14,true);status.Margin=new Thickness(0,12,0,0);panel.Children.Add(status);
  var busy=false;var loading=false;Guid? selection=null;CanLeave=()=>!busy;
  List<EnrollmentAttempt> Entries()=>preview?[PreviewAttempt()]:new(catalog.Read().Enrollments??[]);
  void Buttons(){if(loading)return;var selected=list.SelectedItem as EnrollmentAttempt;resume.IsEnabled=!preview&&selected is not null;start.IsEnabled=!preview&&selected is null;name.IsReadOnly=selected is not null;if(selected is not null){selection=selected.RequestId;name.Text=selected.Name;summary.Text=selected.DeviceId is null?"Ключи сохранены. Можно безопасно повторить запрос регистрации.":"Устройство зарегистрировано. Ожидается готовая конфигурация сервера.";}}
  void Reload(){
   loading=true;var entries=Entries();list.ItemsSource=entries;
   var matching=source is null?null:entries.FirstOrDefault(e=>e.Origin==source.Origin&&e.SourceHash==source.SourceHash);
   list.SelectedItem=entries.FirstOrDefault(e=>e.RequestId==selection)??matching??(source is null?entries.FirstOrDefault():null);
   var completed=!preview&&source is not null&&catalog.Read().Profiles.Any(p=>p.Managed is{} m&&m.Origin==source.Origin&&m.EnrollmentSourceHash==source.SourceHash);
   summary.Text=completed?"Этот компьютер уже зарегистрирован по данной подписке. Профиль доступен в «Серверах».":source is not null?$"Сервер: {new Uri(source.Origin).Host}. Повторная попытка сохраняет те же ключи и не создаёт второе устройство.":entries.Count>0?"Выберите сохранённую попытку. После перезапуска ключи и запрос регистрации остаются прежними.":"Незавершённых регистраций нет. Добавьте JSON подписки или ссылку ftm-enroll на вкладке «Добавить».";
   start.Visibility=source is not null&&!completed&&matching is null?Visibility.Visible:Visibility.Collapsed;start.IsEnabled=!preview;copy.Visibility=source is not null?Visibility.Visible:Visibility.Collapsed;copy.IsEnabled=!preview;viaVpn.IsEnabled=!preview;
   loading=false;Buttons();
  }
  async Task Continue(Guid id){
   var through=viaVpn.IsChecked==true;var connected=false;if(through){var reply=await ServiceClient.Send("status");connected=reply.Ok&&reply.State=="connected"&&reply.TunnelActive;}
   var profile=await EnrollmentClient.Continue(catalog,id,through,connected,progress:step=>status.Text=step switch{"recover"=>"Восстанавливаем результат прошлой попытки…","register"=>"Регистрируем устройство…","download"=>"Проверяем готовность конфигурации…","validate"=>"Проверяем конфигурацию и соответствие ключей…","ready"=>"Профиль готов.","server_error"=>"На сервере возникла ошибка подготовки устройства. Ключи сохранены; попросите администратора проверить состояние в панели.",_=>"Сервер ещё готовит устройство. Повторите проверку позже."});
   if(profile is not null){ProfilesAdded=true;selection=null;status.Text="Профиль добавлен без смены ключей. Выберите его в «Серверах», затем подключитесь вручную.";}
  }
  async Task Run(Func<Task> action){if(busy||preview)return;busy=true;actions.IsEnabled=name.IsEnabled=list.IsEnabled=viaVpn.IsEnabled=false;try{await action();}catch(Exception e){status.Text=ManagedMessages.Friendly(e.Message);}finally{busy=false;actions.IsEnabled=name.IsEnabled=list.IsEnabled=viaVpn.IsEnabled=true;try{Reload();}catch{status.Text="Каталог недоступен. Сохранённые ключи не перезаписывались.";}}}
  list.SelectionChanged+=(_,_)=>Buttons();close.Click+=(_,_)=>Close();
  start.Click+=async(_,_)=>await Run(async()=>{if(source is null)return;status.Text="Создаём и сохраняем ключи этого устройства…";var attempt=await EnrollmentClient.Begin(catalog,source,name.Text);selection=attempt.RequestId;await Continue(attempt.RequestId);});
  resume.Click+=async(_,_)=>await Run(async()=>{if(list.SelectedItem is EnrollmentAttempt attempt)await Continue(attempt.RequestId);});
  copy.Click+=(_,_)=>{try{if(source is not null){Clipboard.SetText(source.ToUri());status.Text="Ссылка подписки скопирована. Передавайте её только доверенным пользователям.";}}catch{status.Text="Не удалось записать ссылку в буфер обмена.";}};
  Reload();
 }
 internal static EnrollmentAttempt PreviewAttempt()
 {
  var source=new EnrollmentLink(1,"ftm-enrollment","https://8.8.8.8","ftmu1_"+new string('A',43));
  return new(Guid.Parse("11111111-2222-3333-4444-555555555555"),"Windows PC",source.Origin,source.SourceHash,source.UserToken,Convert.ToBase64String(Enumerable.Repeat((byte)'x',32).ToArray()),"m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=",new string('b',32),"ftmd1_"+new string('B',43),Attempted:true);
 }
}
