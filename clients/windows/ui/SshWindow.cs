using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FreeTurn.Windows.Models;
using Microsoft.Win32;
namespace FreeTurn.Windows;
internal sealed class SshWindow : InAppPage
{
    internal SshWindow(Window? owner,ProfileCatalog catalog,SavedProfile profile,bool preview=false)
    {
        Owner=owner;Title="SSH — FreeTurn";Width=480;MinWidth=420;Height=Math.Min(800,SystemParameters.WorkArea.Height-40);Background=UiTheme.Background;Foreground=UiTheme.Foreground;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        var panel=new StackPanel{Margin=new Thickness(24)};Content=new ScrollViewer{Content=panel,Background=Background,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        panel.Children.Add(new TextBlock{Text="SSH сервера",FontSize=28});panel.Children.Add(new TextBlock{Text="Настройки хранятся зашифрованными. Проверка выполняет только SSH-аутентификацию, без команд и установки. При первом контакте пароль не отправляется до подтверждения ключа хоста.",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,12,0,12)});
        TextBox Field(string label,string value,int max=255){panel.Children.Add(new TextBlock{Text=label,Margin=new Thickness(0,12,0,6)});var box=new TextBox{Text=value,MaxLength=max,Padding=new Thickness(10),IsUndoEnabled=false};System.Windows.Automation.AutomationProperties.SetName(box,label);panel.Children.Add(box);return box;}
        var original=profile.Ssh??new SshConfig();var host=Field("Адрес SSH",original.Ip);var port=Field("Порт",original.Port.ToString(CultureInfo.InvariantCulture),5);var username=Field("Пользователь",original.Username,128);
        panel.Children.Add(new TextBlock{Text="Способ входа",Margin=new Thickness(0,12,0,6)});var auth=new ComboBox{ItemsSource=new[]{"PASSWORD","SSH_KEY"},SelectedItem=original.AuthType,Padding=new Thickness(8)};panel.Children.Add(auth);
        panel.Children.Add(new TextBlock{Text="Пароль / пароль ключа",Margin=new Thickness(0,12,0,6)});var password=new PasswordBox{Password=original.Password,MaxLength=4096,Padding=new Thickness(10)};panel.Children.Add(password);
        var key=original.SshKey;var pin=original.HostFingerprint;string? pendingPin=null;string? pendingHost=null;int pendingPort=0;
        var keyState=new TextBlock{Text=key.Length>0?"Приватный ключ загружен":"Приватный ключ не выбран",Margin=new Thickness(0,12,0,6)};panel.Children.Add(keyState);
        var load=Button("Загрузить приватный ключ…");panel.Children.Add(load);load.Click+=(_,_)=>{var dialog=new OpenFileDialog{Filter="SSH ключ|*.*"};if(dialog.ShowDialog(DialogOwner)==true)try{if(new FileInfo(dialog.FileName).Length>128*1024)throw new IOException();key=File.ReadAllText(dialog.FileName);keyState.Text="Приватный ключ загружен";}catch{keyState.Text="Ключ не прочитан.";}};
        var fingerprint=Field("Закреплённый ключ хоста",pin,128);fingerprint.IsReadOnly=true;
        var status=new TextBlock{TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,16,0,16),Foreground=UiTheme.Muted};panel.Children.Add(status);
        var trust=Button("Подтвердить полученный ключ");trust.IsEnabled=false;panel.Children.Add(trust);var clear=Button("Сбросить доверие к ключу");panel.Children.Add(clear);
        var save=Button("Сохранить SSH");var probe=Button("Проверить SSH");panel.Children.Add(save);panel.Children.Add(probe);
        if(preview){save.IsEnabled=probe.IsEnabled=load.IsEnabled=clear.IsEnabled=false;}
        SshConfig Values(){var candidate=original with{Ip=host.Text.Trim(),Port=int.Parse(port.Text,CultureInfo.InvariantCulture),Username=username.Text.Trim(),AuthType=auth.SelectedItem as string??"PASSWORD",Password=password.Password,SshKey=key,HostFingerprint=pin};if(!candidate.SameHost(original)&&pin==original.HostFingerprint)candidate=candidate with{HostFingerprint=""};SshTrust.Validate(candidate);return candidate;}
        void ClearPending(){pendingPin=null;trust.IsEnabled=false;}
        host.TextChanged+=(_,_)=>{ClearPending();pin="";fingerprint.Text="";};port.TextChanged+=(_,_)=>{ClearPending();pin="";fingerprint.Text="";};
        clear.Click+=(_,_)=>{if(MessageBox.Show(DialogOwner,"Забыть закреплённый ключ? Следующее подключение потребует сравнить новый fingerprint независимым способом.","Доверие SSH",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;pin="";fingerprint.Text="";ClearPending();};
        trust.Click+=(_,_)=>{if(pendingPin is null||host.Text.Trim()!=pendingHost||!int.TryParse(port.Text,out var p)||p!=pendingPort)return;if(MessageBox.Show(DialogOwner,$"Сравните fingerprint с консолью сервера или другим доверенным каналом:\n\n{pendingPin}\n\nДоверять этому ключу?","Ключ SSH",MessageBoxButton.YesNo,MessageBoxImage.Question)==MessageBoxResult.Yes){pin=pendingPin;fingerprint.Text=pin;ClearPending();status.Text="Ключ подтверждён. Сохраните настройки или повторите проверку.";}};
        save.Click+=(_,_)=>{try{catalog.SetSsh(profile.Id,Values());status.Text="SSH-настройки сохранены зашифрованными.";}catch{status.Text="Настройки не сохранены. Проверьте адрес, порт, пользователя и ключ хоста.";}};
        var busy=false;CanLeave=()=>!busy;Closing+=(_,e)=>{if(busy)e.Cancel=true;};
        probe.Click+=async(_,_)=>{if(busy)return;busy=true;panel.IsEnabled=false;status.Text="Проверка SSH…";try{var settings=Values();var result=await SshProbe.Check(settings);status.Text=result.State switch{"authenticated"=>"SSH-аутентификация успешна. Команды на сервере не выполнялись.","untrusted"=>"Ключ хоста ещё не подтверждён. Полученный fingerprint: "+result.Fingerprint,"changed"=>"Ключ хоста изменился. Соединение остановлено до отправки пароля. Проверьте сервер независимым способом.",_=>"SSH-проверка не прошла. Проверьте доступность, способ входа и учётные данные. Автоматических повторов нет."};if(result.State=="untrusted"){pendingPin=result.Fingerprint;pendingHost=settings.Ip;pendingPort=settings.Port;trust.IsEnabled=true;}}catch{status.Text="Проверьте параметры SSH. Сохранённые настройки не изменены.";}finally{busy=false;panel.IsEnabled=true;}};
    }
    private static Button Button(string text)=>new(){Content=text,Padding=new Thickness(12,10,12,10),Margin=new Thickness(0,8,0,8),Background=UiTheme.Button,Foreground=Brushes.White};
}
