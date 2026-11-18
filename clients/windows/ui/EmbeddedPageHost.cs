using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace FreeTurn.Windows;

internal sealed class EmbeddedPageHost
{
    private sealed record Entry(InAppPage Page,FrameworkElement View,TaskCompletionSource<bool?> Done);
    private readonly Stack<Entry> stack=new();
    private readonly FrameworkElement main;
    internal ContentControl View {get;}=new(){Visibility=Visibility.Collapsed,HorizontalContentAlignment=HorizontalAlignment.Stretch,VerticalContentAlignment=VerticalAlignment.Stretch};
    internal bool CanClose=>stack.All(entry=>entry.Page.CanLeave());
    internal EmbeddedPageHost(Window owner,FrameworkElement main)
    {
        this.main=main;
        var command=new RoutedCommand();owner.CommandBindings.Add(new CommandBinding(command,(_,_)=>Back()));owner.InputBindings.Add(new KeyBinding(command,Key.Left,ModifierKeys.Alt));
    }
    internal Task<bool?> Push(InAppPage page)
    {
        var done=new TaskCompletionSource<bool?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var content=page.Attach(value=>{if(stack.TryPeek(out var top)&&ReferenceEquals(top.Page,page))Pop(value);});
        var layout=new DockPanel{LastChildFill=true,Background=UiTheme.Background};
        var backLabel=new StackPanel{Orientation=Orientation.Horizontal};backLabel.Children.Add(AndroidIcon.Create("Back",20,UiTheme.Foreground));backLabel.Children.Add(new TextBlock{Text="Назад",Margin=new Thickness(6,0,0,0),VerticalAlignment=VerticalAlignment.Center});
        var back=new Button{Content=backLabel,Background=System.Windows.Media.Brushes.Transparent,Foreground=UiTheme.Foreground,HorizontalAlignment=HorizontalAlignment.Left,Padding=new Thickness(12,9,12,9),Margin=new Thickness(12,8,12,0),ToolTip="Назад · Alt+←"};
        back.Click+=(_,_)=>Back();System.Windows.Automation.AutomationProperties.SetName(back,"Назад");DockPanel.SetDock(back,Dock.Top);layout.Children.Add(back);layout.Children.Add(content);
        stack.Push(new(page,layout,done));Render();back.Focus();return done.Task;
    }
    private bool Back(){if(!stack.TryPeek(out var top)||!top.Page.CanLeave())return false;Pop(false);return true;}
    internal bool CloseAll()
    {
        if(!CanClose)return false;
        while(stack.Count>0)Pop(false);return true;
    }
    private void Pop(bool? result)
    {
        var entry=stack.Pop();entry.Page.Detached(result);entry.Done.TrySetResult(result);Render();
    }
    private void Render()
    {
        var open=stack.TryPeek(out var current);View.Content=open?current!.View:null;View.Visibility=open?Visibility.Visible:Visibility.Collapsed;main.Visibility=open?Visibility.Collapsed:Visibility.Visible;
    }
}
