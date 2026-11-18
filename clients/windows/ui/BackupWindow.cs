using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace FreeTurn.Windows;
internal sealed class BackupWindow : InAppPage
{
    internal BackupWindow(Window? owner,ProfileCatalog catalog,bool preview=false)
    {
        Owner=owner;Title="Резервные копии — FreeTurn";Width=480;MinWidth=420;Height=Math.Min(660,SystemParameters.WorkArea.Height-40);WindowStartupLocation=owner is null?WindowStartupLocation.CenterScreen:WindowStartupLocation.CenterOwner;Background=UiTheme.Background;Foreground=UiTheme.Foreground;
        var panel=new StackPanel{Margin=new Thickness(24)};Content=new ScrollViewer{Content=panel,Background=Background,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        panel.Children.Add(new TextBlock{Text="Резервные копии",FontSize=27});
        panel.Children.Add(new TextBlock{Text="Пароль защищает все профили и их ключи. Его нельзя восстановить. Импорт добавляет записи к существующим и не включает VPN. Сохранившиеся копии не создают новый доступ для другого устройства.",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,18,0,18)});
        panel.Children.Add(new TextBlock{Text="Пароль (для создания — не менее 10 символов)"});var password=new PasswordBox{Padding=new Thickness(10),MaxLength=1024,Margin=new Thickness(0,8,0,16)};panel.Children.Add(password);
        panel.Children.Add(new TextBlock{Text="Повтор пароля при создании копии"});var repeat=new PasswordBox{Padding=new Thickness(10),MaxLength=1024,Margin=new Thickness(0,8,0,16)};panel.Children.Add(repeat);
        var preferences=new CheckBox{Content="Восстановить настройки приложения",IsChecked=true,Foreground=UiTheme.Foreground,Margin=new Thickness(0,0,0,16)};panel.Children.Add(preferences);
        var export=Button("Создать копию…");var restore=Button("Восстановить…");var android=Button("Сохранить исходный Android backup…");panel.Children.Add(export);panel.Children.Add(restore);panel.Children.Add(android);
        var status=new TextBlock{TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,16,0,0),Foreground=UiTheme.Muted};panel.Children.Add(status);
        if(preview){export.IsEnabled=restore.IsEnabled=android.IsEnabled=false;status.Text="Предпросмотр. Реальные профили не используются.";}
        var busy=false;CanLeave=()=>!busy;Closing+=(_,e)=>{if(busy)e.Cancel=true;};
        async Task Run(Func<string,Task> operation){if(busy)return;busy=true;export.IsEnabled=restore.IsEnabled=android.IsEnabled=password.IsEnabled=repeat.IsEnabled=false;status.Text="Обработка…";var secret=password.Password;try{await operation(secret);}catch{status.Text="Операция не выполнена: проверьте пароль, формат файла и свободное место. Существующие записи сохранены.";}finally{secret="";password.Clear();repeat.Clear();busy=false;export.IsEnabled=restore.IsEnabled=android.IsEnabled=password.IsEnabled=repeat.IsEnabled=true;}}
        export.Click+=async(_,_)=>{
            if(password.Password.Length<10||password.Password!=repeat.Password){status.Text="Введите пароль от 10 символов и одинаковый повтор.";return;}
            var dialog=new SaveFileDialog{Filter="Зашифрованная копия FreeTurn (*.ftbackup)|*.ftbackup",FileName=$"FreeTurn-Windows-{DateTime.Now:yyyy-MM-dd}.ftbackup"};if(dialog.ShowDialog(DialogOwner)!=true)return;
            await Run(async secret=>{var raw=CatalogBackup.Encode(catalog.Read());try{var encrypted=await Task.Run(()=>BackupCrypto.Encrypt(raw,secret));SafeExport.Write(dialog.FileName,encrypted);status.Text="Зашифрованная копия сохранена.";}finally{CryptographicOperations.ZeroMemory(raw);}});
        };
        restore.Click+=async(_,_)=>{
            if(password.Password.Length==0){status.Text="Введите пароль резервной копии.";return;}
            var dialog=new OpenFileDialog{Filter="Копии FreeTurn (*.ftbackup;*.json)|*.ftbackup;*.json|Все файлы|*.*"};if(dialog.ShowDialog(DialogOwner)!=true)return;
            await Run(async secret=>{
                if(new FileInfo(dialog.FileName).Length>BackupCrypto.MaxEnvelope)throw new IOException();var encrypted=File.ReadAllBytes(dialog.FileName);var raw=await Task.Run(()=>BackupCrypto.Decrypt(encrypted,secret));
                try{var incoming=CatalogBackup.Decode(raw);
                    if(MessageBox.Show(DialogOwner,$"Восстановить из копии: профилей — {incoming.Profiles.Count}, незавершённых регистраций — {incoming.Enrollments?.Count??0}? Существующие записи и текущий профиль службы сохранятся. Некоторые Android-режимы пока могут быть недоступны для подключения.","Восстановление",MessageBoxButton.OKCancel,MessageBoxImage.Question)!=MessageBoxResult.OK){status.Text="Восстановление отменено.";return;}
                    var count=catalog.Merge(incoming,preferences.IsChecked==true);var registrations=catalog.Read().Enrollments?.Count??0;status.Text=$"Добавлено профилей: {count}. Для применения выберите нужный сервер."+(registrations>0?$" Незавершённых регистраций: {registrations}; продолжите их на вкладке «Добавить».":"")+(incoming.AndroidArchive is null?"":" Исходные Android-настройки сохранены зашифрованными.");
                }finally{CryptographicOperations.ZeroMemory(raw);}
            });
        };
        android.Click+=async(_,_)=>{
            if(password.Password.Length<10||password.Password!=repeat.Password){status.Text="Введите пароль от 10 символов и одинаковый повтор.";return;}
            var sources=catalog.Read();var archives=(sources.AndroidArchive is null?new List<string>():new List<string>{sources.AndroidArchive}).Concat(sources.AndroidArchiveHistory??[]).ToList();if(archives.Count==0){status.Text="Импортированной исходной копии Android нет.";return;}
            var chosen=0;if(archives.Count>1){var choose=new InAppPage{Owner=this,Title="Исходная копия Android",Width=420,Height=230,ResizeMode=ResizeMode.NoResize,WindowStartupLocation=WindowStartupLocation.CenterOwner,Background=UiTheme.Background,Foreground=UiTheme.Foreground};var box=new StackPanel{Margin=new Thickness(24)};box.Children.Add(new TextBlock{Text="Какой исходный документ сохранить?",TextWrapping=TextWrapping.Wrap});var list=new ComboBox{ItemsSource=Enumerable.Range(0,archives.Count).Select(i=>i==0?"Последний импорт":"Предыдущий документ "+i).ToList(),SelectedIndex=0,Margin=new Thickness(0,16,0,16)};box.Children.Add(list);var confirm=Button("Выбрать");box.Children.Add(confirm);confirm.Click+=(_,_)=>{chosen=list.SelectedIndex;choose.DialogResult=true;};choose.Content=box;if(await choose.OpenAsync()!=true)return;}
            var archive=archives[chosen];
            var dialog=new SaveFileDialog{Filter="Android backup (*.json)|*.json",FileName="FreeTurn-Android-original.json"};if(dialog.ShowDialog(DialogOwner)!=true)return;
            await Run(async secret=>{var raw=System.Text.Encoding.UTF8.GetBytes(archive);try{SafeExport.Write(dialog.FileName,await Task.Run(()=>BackupCrypto.Encrypt(raw,secret)));status.Text="Сохранена исходная копия Android. Изменения профилей в Windows в неё не включены.";}finally{CryptographicOperations.ZeroMemory(raw);}});
        };
    }
    private static Button Button(string label)=>new(){Content=label,Padding=new Thickness(12,12,12,12),Margin=new Thickness(0,0,0,12),Background=UiTheme.Button,Foreground=Brushes.White};
}
