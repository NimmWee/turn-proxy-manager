// SPDX-License-Identifier: GPL-3.0-only
// Android 5.3.4 AppNavigation order and original vectors, adapted to desktop WPF.
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;

namespace FreeTurn.Windows;

internal sealed class BottomNavigation : Border
{
    private static readonly (string Label,string Filled,string Outlined)[] Items =
    [ ("Главная","HomeFilled","HomeOutlined"), ("Логи","Logs","Logs"), ("Поделиться","ShareFilled","ShareOutlined"), ("Настройки","SettingsFilled","SettingsOutlined"), ("Добавить","Add","Add") ];
    private readonly Button[] buttons=new Button[5];
    private readonly Border[] indicators=new Border[5];
    private readonly System.Windows.Shapes.Path[] icons=new System.Windows.Shapes.Path[5];
    private readonly TextBlock[] labels=new TextBlock[5];
    private readonly Action<int> navigate;
    private readonly Func<bool> canNavigate;
    private int selected;

    internal BottomNavigation(Window owner,Action<int> navigate,Func<bool>? canNavigate=null)
    {
        this.navigate=navigate;
        this.canNavigate=canNavigate??(()=>true);
        Background=ColorBrush("#191C20");BorderThickness=new Thickness(0);
        CornerRadius=new CornerRadius(0);Padding=new Thickness(8,4,8,8);Margin=new Thickness(0);
        MaxWidth=760;Height=86;HorizontalAlignment=HorizontalAlignment.Stretch;VerticalAlignment=VerticalAlignment.Bottom;
        var grid=new Grid();Child=grid;
        for(var index=0;index<Items.Length;index++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition());var slot=index;
            var canvas=new Canvas{Width=960,Height=960,IsHitTestVisible=false};
            icons[index]=new System.Windows.Shapes.Path{IsHitTestVisible=false};canvas.Children.Add(icons[index]);
            indicators[index]=new Border{Width=64,Height=34,CornerRadius=new CornerRadius(18),Child=new Viewbox{Width=24,Height=24,Child=canvas}};
            labels[index]=new TextBlock{Text=Items[index].Label,FontSize=12,Margin=new Thickness(0,5,0,0),TextAlignment=TextAlignment.Center};
            var content=new StackPanel{HorizontalAlignment=HorizontalAlignment.Center};content.Children.Add(indicators[index]);content.Children.Add(labels[index]);
            var button=new Button{Content=content,MinWidth=68,MinHeight=68,Margin=new Thickness(1,0,1,0),Cursor=Cursors.Hand,Style=(Style)Application.Current.FindResource("BottomNavigationButton")};
            buttons[index]=button;Grid.SetColumn(button,index);grid.Children.Add(button);
            button.ToolTip=$"{Items[index].Label} · Ctrl+{index+1}";ToolTipService.SetPlacement(button,System.Windows.Controls.Primitives.PlacementMode.Top);
            System.Windows.Automation.AutomationProperties.SetName(button,Items[index].Label);
            button.Click+=(_,_)=>Select(slot);
            var command=new RoutedCommand();owner.CommandBindings.Add(new CommandBinding(command,(_,e)=>{Select(slot);buttons[slot].Focus();e.Handled=true;}));
            owner.InputBindings.Add(new KeyBinding(command,(Key)((int)Key.D1+index),ModifierKeys.Control));
        }
        PreviewKeyDown+=(_,e)=>{if(e.Key is Key.Left or Key.Right){Select((selected+(e.Key==Key.Right?1:4))%5);buttons[selected].Focus();e.Handled=true;}};
        Paint();
    }
    internal void Select(int index){if(index<0||index>=Items.Length||!canNavigate())return;selected=index;Paint();navigate(index);}
    private void Paint()
    {
        for(var index=0;index<Items.Length;index++)
        {
            var active=index==selected;var color=ColorBrush(active?"#D6E3FF":"#BEC6DC");
            indicators[index].Background=active?ColorBrush("#3E4759"):Brushes.Transparent;
            icons[index].Data=(Geometry)Application.Current.FindResource("NavIcon."+(active?Items[index].Filled:Items[index].Outlined));icons[index].Fill=color;
            labels[index].Foreground=color;labels[index].FontWeight=active?FontWeights.SemiBold:FontWeights.Normal;
            buttons[index].IsTabStop=active;
            System.Windows.Automation.AutomationProperties.SetHelpText(buttons[index],active?"Текущая вкладка · Ctrl+"+(index+1):"Ctrl+"+(index+1));
        }
    }
    private static SolidColorBrush ColorBrush(string value)=>UiTheme.Brush(value);
}

internal static class AndroidIcon
{
    internal static Viewbox Create(string resource,double size,Brush color)
    {
        var canvas=new Canvas{Width=960,Height=960,IsHitTestVisible=false};
        canvas.Children.Add(new System.Windows.Shapes.Path{Data=(Geometry)Application.Current.FindResource("NavIcon."+resource),Fill=color,IsHitTestVisible=false});
        return new Viewbox{Width=size,Height=size,Child=canvas,IsHitTestVisible=false};
    }
}
