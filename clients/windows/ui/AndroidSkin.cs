// SPDX-License-Identifier: GPL-3.0-only
// Composition adapted from pinned FreeTurn Android SettingsRows/SettingsGroup.
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FreeTurn.Windows;
internal static class AndroidSkin
{
    internal static TextBlock Text(string value,double size=14,bool muted=false)=>new(){Text=value,FontSize=size,Foreground=muted?UiTheme.Muted:UiTheme.Foreground,TextWrapping=TextWrapping.Wrap};
    internal static StackPanel Page(string title,string? description=null,Action? back=null)
    {
        var page=new StackPanel{Margin=new Thickness(24,24,24,24)};
        if(back is not null){var button=new Button{Content=AndroidIcon.Create("Back",24,UiTheme.Foreground),Width=44,Height=44,HorizontalAlignment=HorizontalAlignment.Left,Margin=new Thickness(-8,-12,0,12),Background=Brushes.Transparent,ToolTip="Назад"};System.Windows.Automation.AutomationProperties.SetName(button,"Назад");button.Click+=(_,_)=>back();page.Children.Add(button);}
        var heading=Text(title,36);heading.FontWeight=FontWeights.Bold;heading.Margin=new Thickness(0,0,0,24);page.Children.Add(heading);
        if(description is not null){var help=Text(description,14,true);help.Margin=new Thickness(0,-8,0,24);page.Children.Add(help);}return page;
    }
    internal static Border Card(UIElement child,double padding=16)=>new(){Background=UiTheme.Brush("#191C20"),CornerRadius=new CornerRadius(28),Padding=new Thickness(padding),Child=child};
    internal static Button Entry(string icon,string title,string subtitle,Action action)
    {
        var grid=new Grid();grid.ColumnDefinitions.Add(new(){Width=new GridLength(40)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(16)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(24)});
        var badge=new Border{Width=40,Height=40,CornerRadius=new CornerRadius(14),Background=UiTheme.PrimaryContainer,Child=AndroidIcon.Create(icon,24,UiTheme.OnPrimaryContainer)};grid.Children.Add(badge);
        var labels=new StackPanel{VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(0,0,12,0)};var label=Text(title,16);label.FontWeight=FontWeights.Medium;labels.Children.Add(label);if(subtitle.Length>0){var hint=Text(subtitle,13,true);hint.Margin=new Thickness(0,4,0,0);labels.Children.Add(hint);}Grid.SetColumn(labels,2);grid.Children.Add(labels);
        var arrow=AndroidIcon.Create("Chevron",22,UiTheme.Muted);Grid.SetColumn(arrow,3);grid.Children.Add(arrow);
        var button=new Button{Content=grid,HorizontalContentAlignment=HorizontalAlignment.Stretch,MinHeight=88,Padding=new Thickness(16),Background=UiTheme.Brush("#191C20"),Foreground=UiTheme.Foreground};System.Windows.Automation.AutomationProperties.SetName(button,title);button.Click+=(_,_)=>action();return button;
    }
    internal static StackPanel Group(params Button[] entries)
    {
        var group=new StackPanel{Margin=new Thickness(0,0,0,24)};for(var i=0;i<entries.Length;i++){entries[i].Tag=entries.Length==1?"Single":i==0?"First":i==entries.Length-1?"Last":"Middle";entries[i].Margin=new Thickness(0,0,0,2);group.Children.Add(entries[i]);}return group;
    }
    internal static TextBlock Section(string title){var label=Text(title,14);label.Foreground=UiTheme.Brush("#AAC7FF");label.FontWeight=FontWeights.Medium;label.Margin=new Thickness(16,12,0,10);return label;}
    internal static Border SwitchGroup(params CheckBox[] switches)
    {
        var panel=new StackPanel();foreach(var item in switches){if(item.Content is string label)item.Content=label;item.Margin=new Thickness(0);panel.Children.Add(item);}var card=Card(panel,16);card.Margin=new Thickness(0,0,0,24);return card;
    }
    internal static void Font(Window window){window.FontFamily=UiTheme.Font;window.FontSize=14;window.Foreground=UiTheme.Foreground;window.Background=UiTheme.Background;}
}
