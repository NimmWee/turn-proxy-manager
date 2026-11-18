using System.Windows;
using System.Windows.Controls;
using System.IO;

namespace FreeTurn.Windows;

internal sealed class ManagedWindow:InAppPage
{
 internal ManagedWindow(Window? owner,ProfileCatalog catalog,SavedProfile profile,bool preview=false)
 {
  Owner=owner;Title="Управление доступом — FreeTurn";AndroidSkin.Font(this);Width=480;MinWidth=420;Height=740;
  var panel=AndroidSkin.Page("Управление доступом","Персональный профиль и обновления от администратора. Ключ вашего устройства сохраняется.");
  Content=new ScrollViewer{Content=panel,Background=UiTheme.Background,FontFamily=UiTheme.Font,FontSize=14,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
  panel.Children.Add(AndroidSkin.Section(profile.Name));
  var status=AndroidSkin.Text("",14,true);panel.Children.Add(AndroidSkin.Card(status));
  panel.Children.Add(AndroidSkin.Text("Для активации и проверки обновлений подключите VPN. Полученное обновление сначала сохраняется отдельно. Применение и возврат меняют только каталог: открытое соединение продолжит работать до вашего переподключения.",14,true));
  var actions=new WrapPanel{Margin=new Thickness(0,20,0,0)};
  Button Action(string text){var b=new Button{Content=text,Padding=new Thickness(16,12,16,12),Margin=new Thickness(0,0,8,8)};actions.Children.Add(b);return b;}
  var claim=Action("Активировать управление");var refresh=Action("Проверить обновление");var apply=Action("Использовать при следующем подключении");var rollback=Action("Вернуть предыдущий профиль");var rules=Action("Обновить правила сети");var close=Action("Назад");panel.Children.Add(actions);
  var feedback=AndroidSkin.Text("",14,true);panel.Children.Add(feedback);
  var busy=false;CanLeave=()=>!busy;
  void Update(){
   var m=preview?profile.Managed:catalog.Read().Profiles.FirstOrDefault(p=>p.Id==profile.Id)?.Managed;
   var expired=m is{Registered:false}&&DateTimeOffset.Parse(m.ExpiresAt)<=DateTimeOffset.UtcNow;
   status.Text=m is null?"Это обычный профиль. Для управления нужен персональный стартовый JSON из панели.":m.AccessDenied?"Сервер отклонил доступ устройства. Ключи сохранены, подключение и применение старых обновлений заблокированы. Уточните доступ у администратора.":!m.Registered?expired?"Срок новой активации истёк. Если сервер уже принял прежний запрос, можно восстановить управление через VPN. Сохранённый профиль и ключи останутся прежними.":"Управление ещё не активировано. Стартовый профиль сохранён зашифрованным.":m.Pending is{} pending?$"Получено обновление версии {pending.Revision}. Текущий профиль сохранён; обновление ожидает вашего решения.":m.Applied is{} applied?$"В каталоге используется версия {applied.Revision}. Доступ устройства активирован.":"Доступ устройства активирован. Можно проверить обновление профиля.";
   var delivered=preview?profile.Routing:catalog.Read().Profiles.FirstOrDefault(p=>p.Id==profile.Id)?.Routing;if(delivered is not null)status.Text+=$"\nПравила сети: публикация №{delivered.Current.Revision}, для следующего подключения в системном режиме.";
   claim.Content=expired?"Проверить восстановление":"Активировать управление";
   claim.Visibility=m is{Registered:false}?Visibility.Visible:Visibility.Collapsed;refresh.Visibility=m is{Registered:true}?Visibility.Visible:Visibility.Collapsed;
   if(m is{Registered:true,AccessDenied:false})status.Text+=m.KnownGood is{} good?"\nПоследняя подтверждённая рабочая конфигурация: "+DateTimeOffset.Parse(good.VerifiedAt).ToLocalTime().ToString("g")+". При неудачном запуске выбранного обновления возможен один автоматический возврат.":"\nПодтверждённая рабочая конфигурация ещё не сохранена. Она появится после устойчивого handshake и проверки интернета.";
   apply.Visibility=m?.Pending is not null?Visibility.Visible:Visibility.Collapsed;rollback.Visibility=m?.PreviousShare is not null?Visibility.Visible:Visibility.Collapsed;
   rules.Visibility=m is{Registered:true}?Visibility.Visible:Visibility.Collapsed;rules.IsEnabled=!preview&&m is{Registered:true,AccessDenied:false};
   claim.IsEnabled=!preview&&m is{Registered:false};refresh.IsEnabled=!preview&&m is{Registered:true};
   apply.IsEnabled=!preview&&m is{AccessDenied:false,Pending:not null};rollback.IsEnabled=!preview&&m is{AccessDenied:false,PreviousShare:not null};
  }
  async Task Run(string working,Func<Task> action){
   if(busy||preview)return;busy=true;actions.IsEnabled=false;feedback.Text=working;
   try{await action();}catch(Exception e){feedback.Text=ManagedMessages.Friendly(e.Message);}
   finally{busy=false;actions.IsEnabled=true;try{Update();}catch{feedback.Text="Не удалось прочитать каталог. Сохранённые данные не перезаписывались.";}}
  }
  rules.Click+=async(_,_)=>await Run("Проверяем правила маршрутизации…",async()=>{
   var current=catalog.Read().Profiles.Single(p=>p.Id==profile.Id);var reply=await ServiceClient.Send("status");var lease=new RuntimeLease(current.Id,ProfileIdentity.Of(current.Share),reply.ConnectionId,reply.PathEpoch);
   if(!lease.Matches(reply))throw new IOException("MANAGED_CONNECT_FIRST");
   var received=await ManagedRouting.Refresh(catalog,profile.Id,ensureCurrent:async()=>{if(!lease.Matches(await ServiceClient.Send("status")))throw new IOException("MANAGED_SESSION_CHANGED");});
   feedback.Text=received?"Правила проверены и сохранены. Применятся при следующем подключении с системной маршрутизацией.":"Этот сервер пока не публикует правила. Локальные настройки сохранены.";
  });
  Update();close.Click+=(_,_)=>Close();
  claim.Click+=async(_,_)=>await Run("Проверяем профиль и состояние управления…",async()=>{
   var current=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==profile.Id)??throw new IOException("PROFILE_NOT_FOUND");
   var reply=await ServiceClient.Send("status");var lease=new RuntimeLease(current.Id,ProfileIdentity.Of(current.Share),reply.ConnectionId,reply.PathEpoch);
   if(!lease.Matches(reply))throw new IOException("MANAGED_CONNECT_FIRST");
   await ManagedClient.Claim(catalog,current.Id,true,ensureCurrent:async()=>{
    if(!lease.Matches(await ServiceClient.Send("status")))throw new IOException("MANAGED_SESSION_CHANGED");
   });feedback.Text="Управление подтверждено. Профиль и ключи сохранены.";
  });
  refresh.Click+=async(_,_)=>await Run("Проверяем обновление через VPN…",async()=>{
   var reply=await ServiceClient.Send("status");var result=await ManagedSubscription.Refresh(catalog,profile.Id,reply.Ok&&reply.State=="connected"&&reply.TunnelActive);
   feedback.Text=result switch{ManagedRefresh.Staged=>"Обновление проверено и сохранено отдельно. Текущий VPN не изменялся.",ManagedRefresh.Pending=>"Сервер ещё готовит конфигурацию. Текущий профиль сохранён.",_=>"Обновлений нет. Сохранённая конфигурация подтверждена сервером."};
  });
  apply.Click+=async(_,_)=>await Run("Повторно проверяем сохранённое обновление…",async()=>{await ManagedSubscription.Apply(catalog,profile.Id);feedback.Text="Обновление выбрано для следующего подключения. Когда будете готовы, отключите и подключите VPN вручную.";});
  rollback.Click+=async(_,_)=>await Run("Проверяем предыдущий профиль…",async()=>{await ManagedSubscription.Rollback(catalog,profile.Id);feedback.Text="Предыдущий профиль возвращён в каталог. Текущий VPN не изменялся. Сервер должен продолжать принимать прежние параметры.";});
 }
}

internal static class ManagedMessages
{
 internal static string Friendly(string code)=>code switch{
  "MANAGED_ENROLLMENT_INVALID"=>"Подписка или сохранённые параметры регистрации не прошли проверку. Ключи не заменены. Используйте исходный JSON или ссылку ftm-enroll.",
  "MANAGED_ALREADY_ENROLLED"=>"Этот компьютер уже зарегистрирован по данной подписке. Выберите существующий профиль в «Серверах».",
  "MANAGED_ENROLLMENT_CONFLICT"=>"Регистрация конфликтует с сохранённым устройством. Ключи сохранены. Обратитесь к администратору; новая пара автоматически не создаётся.",
  "MANAGED_ENROLLMENT_NOT_FOUND"=>"Сохранённая попытка не найдена. Проверьте, появился ли профиль в «Серверах».",
  "MANAGED_CONNECT_FIRST"=>"Сначала подключите VPN, затем повторите проверку или активацию.",
  "MANAGED_ACTIVATE_FIRST"=>"Сначала активируйте управление этим устройством.",
  "MANAGED_BOOTSTRAP_EXPIRED"=>"Сервер не подтвердил прежнюю активацию, а срок новой уже истёк. VPN-профиль и ключи сохранены. Обратитесь к администратору.",
  "MANAGED_ACTIVATION_PENDING"=>"Сервер распознал устройство, но ещё не подтвердил готовность. Повторите проверку позже. Профиль и ключи сохранены.",
  "MANAGED_SESSION_CHANGED"=>"VPN-соединение изменилось во время проверки. Подключите этот профиль и повторите действие. Учётные данные сохранены.",
  "MANAGED_ACCESS_REJECTED"=>"Сервер отклонил доступ. Сохранённые ключи не удалены. Уточните состояние устройства у администратора.",
  "MANAGED_RATE_LIMITED"=>"Слишком много запросов. Подождите минуту и повторите.",
  "MANAGED_PROFILE_READ_ONLY"=>"Этот профиль управляется администратором. Ключи нельзя менять или клонировать. Переименование доступно отдельно.",
  "MANAGED_BOOTSTRAP_INVALID"=>"Стартовый профиль не прошёл проверку ключа, адреса или формата. Запись сохранена без изменений.",
  "MANAGED_CONFIG_INVALID" or "MANAGED_RESPONSE_INVALID"=>"Обновление не прошло проверку устройства, версии или совместимости. Текущий профиль сохранён.",
  "MANAGED_STORAGE_CHANGED"=>"Профиль изменился во время проверки. Повторите действие; новые данные не перезаписывались.",
  "MANAGED_NO_ROLLBACK"=>"Предыдущего профиля для возврата нет.",
  _=>"Действие не выполнено. Профиль и ключи сохранены. Проверьте соединение и повторите — учётные данные останутся прежними."
 };
}
