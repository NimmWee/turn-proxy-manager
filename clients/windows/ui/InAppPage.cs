using System.Windows;

namespace FreeTurn.Windows;

// Window remains a standalone surface only for synthetic preview tools.
// Production opens its content inside MainWindow without Show/ShowDialog.
internal class InAppPage : Window
{
    internal Func<bool> CanLeave { get; set; }=()=>true;
    internal event Action? PageClosed;
    private Action<bool?>? finish;
    private bool? result;
    private Window? logicalOwner;
    // A page isn't a shown native Window; nested pages keep a logical owner.
    public new Window? Owner {get=>logicalOwner??base.Owner;set{logicalOwner=value;if(value is not InAppPage)base.Owner=value;}}
    internal Window DialogOwner=>Owner is InAppPage parent?parent.DialogOwner:Owner??this;
    internal Task<bool?> OpenAsync()=>DialogOwner is MainWindow shell?shell.OpenPage(this):Task.FromResult(base.ShowDialog());
    internal UIElement Attach(Action<bool?> complete)
    {
        var content=Content as UIElement??throw new InvalidOperationException("PAGE_CONTENT_MISSING");
        Content=null;finish=complete;return content;
    }
    internal void Detached(bool? value){result=value;finish=null;PageClosed?.Invoke();base.Close();}
    public new bool? DialogResult { get=>finish is null?base.DialogResult:result;set{if(finish is null)base.DialogResult=value;else if(CanLeave())finish(value);} }
    public new void Close(){if(finish is null)base.Close();else if(CanLeave())finish(false);}
}
