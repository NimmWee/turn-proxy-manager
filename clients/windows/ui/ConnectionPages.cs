// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
namespace FreeTurn.Windows;
internal sealed class ConnectionPages
{
    internal readonly ObservableCollection<string> Events=[];
    internal FrameworkElement Logs{get;}
    internal FrameworkElement Share{get;}
    private readonly ComboBox profiles=new(){HorizontalAlignment=HorizontalAlignment.Stretch,Margin=new Thickness(0,8,0,16)};
    private readonly TextBlock shareStatus=AndroidSkin.Text("Выберите подключение из каталога.",13,true);
    private readonly ProfileCatalog catalog;
    private ulong eventSession,eventSequence;
    internal ConnectionPages(Window owner,ProfileCatalog catalog)
    {
        this.catalog=catalog;
        var log=AndroidSkin.Page("Логи","События ядра, потоки и действия приложения. Ключи, токены и ссылки исключены.");
        log.Children.Add(AndroidSkin.Text("Поиск",13,true));var filter=new TextBox{MaxLength=128,Padding=new Thickness(12),Margin=new Thickness(0,6,0,10),ToolTip="Поиск по журналу"};System.Windows.Automation.AutomationProperties.SetName(filter,"Поиск по журналу");log.Children.Add(filter);
        var level=new ComboBox{ItemsSource=new[]{"Все уровни","INFO","WARN","ERROR","APP"},SelectedIndex=0,Margin=new Thickness(0,0,0,12)};log.Children.Add(level);
        var follow=new CheckBox{Content="Следить за новыми событиями",IsChecked=true,Foreground=UiTheme.Foreground,Margin=new Thickness(0,0,0,12)};log.Children.Add(follow);
        var journal=new ListBox{ItemsSource=Events,Height=360,Margin=new Thickness(0),Background=Brushes.Transparent,Foreground=UiTheme.Foreground,BorderThickness=new Thickness(0),FontFamily=new FontFamily("Consolas"),FontSize=13,Padding=new Thickness(4)};
        ScrollViewer.SetHorizontalScrollBarVisibility(journal,ScrollBarVisibility.Disabled);var eventTemplate=new DataTemplate();var eventText=new FrameworkElementFactory(typeof(TextBlock));eventText.SetBinding(TextBlock.TextProperty,new System.Windows.Data.Binding());eventText.SetValue(TextBlock.TextWrappingProperty,TextWrapping.Wrap);eventTemplate.VisualTree=eventText;journal.ItemTemplate=eventTemplate;log.Children.Add(AndroidSkin.Card(journal));
        var view=System.Windows.Data.CollectionViewSource.GetDefaultView(Events);view.Filter=value=>value is string text&&text.Contains(filter.Text,StringComparison.OrdinalIgnoreCase)&&(level.SelectedIndex==0||text.Contains("["+level.SelectedItem+"]",StringComparison.Ordinal));filter.TextChanged+=(_,_)=>view.Refresh();level.SelectionChanged+=(_,_)=>view.Refresh();
        var scrollScheduled=false;Events.CollectionChanged+=(_,_)=>{if(follow.IsChecked!=true||scrollScheduled)return;scrollScheduled=true;journal.Dispatcher.BeginInvoke(new Action(()=>{scrollScheduled=false;if(follow.IsChecked==true&&journal.Items.Count>0)journal.ScrollIntoView(journal.Items[journal.Items.Count-1]);}));};
        log.Children.Add(AndroidSkin.Section("Журнал"));
        log.Children.Add(AndroidSkin.Group(AndroidSkin.Entry("Delete","Очистить","Удалить события из текущего окна",()=>{Events.Clear();Record("Журнал очищен.");}),AndroidSkin.Entry("File","Сохранить журнал","Текстовый файл без ключей и токенов",()=>{
            var dialog=new SaveFileDialog{Filter="Журнал (*.txt)|*.txt",FileName="FreeTurn-events.txt"};if(dialog.ShowDialog(owner)==true)try{SafeExport.Write(dialog.FileName,new UTF8Encoding(false).GetBytes(string.Join(Environment.NewLine,Events)));}catch{MessageBox.Show(owner,"Журнал не сохранён.","FreeTurn");}
        })));Logs=log;
        var share=AndroidSkin.Page("Поделиться","Ссылка на подключение этого устройства.");
        share.Children.Add(AndroidSkin.Section("Подключение"));var selection=new StackPanel();selection.Children.Add(AndroidSkin.Text("Сервер",14,true));selection.Children.Add(profiles);var hint=AndroidSkin.Text("В ссылке находятся ключи доступа. Для одновременной работы другого устройства нужен отдельный профиль.",13,true);selection.Children.Add(hint);share.Children.Add(AndroidSkin.Card(selection));
        share.Children.Add(AndroidSkin.Section("Передать профиль"));
        var copy=AndroidSkin.Entry("Copy","Копировать ссылку","В буфер обмена",()=>WithProfile(p=>{Clipboard.SetText(p.Share);shareStatus.Text="Ссылка скопирована.";}));
        var export=AndroidSkin.Entry("File","Сохранить в файл","Текстовый профиль FreeTurn",()=>WithProfile(p=>{
            var dialog=new SaveFileDialog{Filter="Профиль FreeTurn (*.txt)|*.txt",FileName="FreeTurn-profile.txt"};if(dialog.ShowDialog(owner)==true){SafeExport.Write(dialog.FileName,new UTF8Encoding(false).GetBytes(p.Share+Environment.NewLine));shareStatus.Text="Профиль сохранён.";}
        }));
        copy.IsEnabled=export.IsEnabled=false;profiles.SelectionChanged+=(_,_)=>copy.IsEnabled=export.IsEnabled=profiles.SelectedItem is SavedProfile;
        share.Children.Add(AndroidSkin.Group(copy,export));shareStatus.Margin=new Thickness(16,0,16,0);share.Children.Add(shareStatus);Share=share;
    }
    internal void Record(string message){Events.Add($"{DateTime.Now:HH:mm:ss.fff} [APP] {message}");Trim();}
    private void Trim(){while(Events.Count>1000)Events.RemoveAt(0);}
    internal void AppendCore(CoreEvent[]? entries,ulong session){if(entries is null||session==0)return;if(eventSession!=session){eventSession=session;eventSequence=0;Record("Журнал последней сессии ядра.");}foreach(var entry in entries){if(entry.Seq<=eventSequence)continue;eventSequence=entry.Seq;var line=CoreJournal.Format(entry);if(line is not null)Events.Add(line);}Trim();}
    internal void OpenShare(){try{var data=catalog.Read();profiles.ItemsSource=data.Profiles;profiles.SelectedItem=data.Profiles.FirstOrDefault(p=>p.Id==data.ActiveId);shareStatus.Text=data.Profiles.Count==0?"Добавьте ссылку на вкладке «Добавить». Серверный доступ не изменяется.":"Это копия того же подключения; новые ключи не создаются.";}catch{shareStatus.Text="Каталог не прочитан. Данные сохранены без изменений.";}}
    private void WithProfile(Action<SavedProfile> action){try{if(profiles.SelectedItem is SavedProfile profile)action(profile);else shareStatus.Text="Выберите подключение.";}catch{shareStatus.Text="Действие не выполнено. Сохранённый профиль не изменён.";}}
}
