using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FreeTurn.Windows;

internal sealed class ServersWindow : InAppPage
{
    private readonly ProfileCatalog catalog;
    private readonly Func<SavedProfile,Task> activate;
    private readonly ListBox list=new(){Margin=new Thickness(0,16,0,16),MinHeight=80,MaxHeight=260,BorderThickness=new Thickness(0),Background=Brushes.Transparent,Foreground=UiTheme.Foreground};
    private readonly TextBox name=new(){MaxLength=128,Padding=new Thickness(12),Margin=new Thickness(0,8,0,16)};
    private readonly TextBlock message=new(){TextWrapping=TextWrapping.Wrap,Foreground=UiTheme.Muted};
    private bool busy;
    internal ServersWindow(Window? owner,ProfileCatalog catalog,Func<SavedProfile,Task> activate,Func<string,Task> validate,bool preview=false)
    {
        this.catalog=catalog;this.activate=activate;Owner=owner;Title="Серверы — FreeTurn";Width=480;Height=Math.Min(720,SystemParameters.WorkArea.Height-40);MinWidth=420;MinHeight=480;
        WindowStartupLocation=WindowStartupLocation.CenterOwner;Background=UiTheme.Background;Foreground=UiTheme.Foreground;FontFamily=UiTheme.Font;
        var panel=new StackPanel{Margin=new Thickness(24)};Content=new ScrollViewer{Background=Background,Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        var title=AndroidSkin.Text("Серверы",36);title.FontWeight=FontWeights.Bold;panel.Children.Add(title);list.ItemTemplate=ServerTemplate();panel.Children.Add(list);
        panel.Children.Add(new TextBlock{Text="Название"});panel.Children.Add(name);
        list.SelectionChanged+=(_,_)=>name.Text=(list.SelectedItem as SavedProfile)?.Name??"";
        var actions=new WrapPanel();panel.Children.Add(actions);
        Add(actions,"Выбрать",async p=>{await activate(p);catalog.Select(p.Id);message.Text="Профиль выбран. Нажмите «Подключить» на главном экране.";DialogResult=true;});
        Add(actions,"Переименовать",p=>{catalog.Rename(p.Id,name.Text);return Task.CompletedTask;});
        Add(actions,"Параметры",async p=>{
            if(p.Managed is not null)throw new System.IO.IOException("MANAGED_PROFILE_READ_ONLY");
            await validate(p.Share);
            var editor=new ProfileEditor(this,p,validate);
            if(await editor.OpenAsync()==true&&editor.EditedShare is not null){catalog.Replace(p.Id,editor.EditedName,editor.EditedShare,p.Share);message.Text="Параметры сохранены. Выбор сервера сохранён; изменения применятся при следующем подключении.";}
        });
        Add(actions,"SSH",async p=>{await new SshWindow(this,catalog,p).OpenAsync();});
        Add(actions,"Управление",async p=>{if(p.Managed is null)throw new System.IO.IOException("MANAGED_BOOTSTRAP_INVALID");await new ManagedWindow(this,catalog,p).OpenAsync();});
        Add(actions,"Клонировать",p=>{catalog.Clone(p.Id);message.Text="Создана копия настроек этого подключения. Новые ключи устройства не выпускались.";return Task.CompletedTask;});
        Add(actions,"Удалить",p=>{
            if(MessageBox.Show(DialogOwner,"Удалить запись из локального каталога? Серверный доступ и профиль службы сохранятся.","FreeTurn",MessageBoxButton.OKCancel,MessageBoxImage.Question)==MessageBoxResult.OK)catalog.Delete(p.Id);
            return Task.CompletedTask;
        });panel.Children.Add(message);Reload();if(preview)actions.IsEnabled=false;
    }
    private void Add(Panel panel,string text,Func<SavedProfile,Task> action)
    {
        var body=new StackPanel{Orientation=Orientation.Horizontal};body.Children.Add(AndroidIcon.Create(text switch{"Выбрать"=>"Check","Параметры" or "Управление"=>"Advanced","Переименовать"=>"Edit","SSH"=>"Logs","Клонировать"=>"Copy",_=>"Delete"},18,Brushes.White));body.Children.Add(new TextBlock{Text=text,Margin=new Thickness(6,0,0,0)});var button=new Button{Content=body,Padding=new Thickness(12,10,12,10),Margin=new Thickness(0,0,8,12),Background=UiTheme.Button,Foreground=Brushes.White};
        panel.Children.Add(button);button.Click+=async(_,_)=>{
            if(busy||list.SelectedItem is not SavedProfile profile)return;busy=true;IsEnabled=false;
            try{await action(profile);Reload();}catch(Exception e){message.Text=e.Message.StartsWith("MANAGED_",StringComparison.Ordinal)?ManagedMessages.Friendly(e.Message):e.Message=="PROFILE_CHANGED_DURING_EDIT"?"Профиль изменился во время редактирования. Откройте параметры заново; новые данные не перезаписаны.":e.Message=="SERVICE_UPGRADE_REQUIRED"?"Для этого режима обновите службу из текущей сборки. Локальный профиль сохранён.":"Действие не выполнено. Для смены профиля отключите VPN. Неподдерживаемый профиль или повреждённый каталог не перезаписываются.";}
            finally{busy=false;IsEnabled=true;}
        };
        if(text is "Управление" or "Клонировать" or "Параметры"){
            void Permission(){var managed=(list.SelectedItem as SavedProfile)?.Managed is not null;button.IsEnabled=list.SelectedItem is SavedProfile&&(text=="Управление"?managed:!managed);}
            list.SelectionChanged+=(_,_)=>Permission();Permission();
        }
    }
    private static DataTemplate ServerTemplate()
    {
        var template=new DataTemplate(typeof(SavedProfile));var stack=new FrameworkElementFactory(typeof(StackPanel));stack.SetValue(FrameworkElement.MarginProperty,new Thickness(12));
        var name=new FrameworkElementFactory(typeof(TextBlock));name.SetBinding(TextBlock.TextProperty,new System.Windows.Data.Binding("Name"));name.SetValue(TextBlock.FontSizeProperty,16.0);name.SetValue(TextBlock.FontWeightProperty,FontWeights.Medium);name.SetValue(TextBlock.TextTrimmingProperty,TextTrimming.CharacterEllipsis);stack.AppendChild(name);
        var hint=new FrameworkElementFactory(typeof(TextBlock));hint.SetValue(TextBlock.TextProperty,"Профиль FreeTurn");hint.SetValue(TextBlock.FontSizeProperty,13.0);hint.SetValue(TextBlock.ForegroundProperty,UiTheme.Muted);hint.SetValue(FrameworkElement.MarginProperty,new Thickness(0,4,0,0));stack.AppendChild(hint);template.VisualTree=stack;return template;
    }
    private void Reload()
    {
        try{var snapshot=catalog.Read();list.ItemsSource=snapshot.Profiles;list.SelectedItem=snapshot.Profiles.FirstOrDefault(p=>p.Id==snapshot.ActiveId);if(snapshot.Profiles.Count==0)message.Text="Каталог пуст. Импортируйте ссылку на вкладке «Добавить». Профиль, ранее сохранённый службой, остаётся доступен.";}
        catch{message.Text="Не удалось прочитать каталог. Он сохранён без изменений.";}
    }
}
