namespace FreeTurn.Windows;
internal enum CloseAction {Allow,Hide,Ignore,Wait,ConfirmExit}
internal static class ClosePolicy
{
    internal static CloseAction Decide(bool active,bool busy,bool canLeave,bool tray,bool preferTray,bool exit,bool nativeClose)
    {
        if(busy||!canLeave)return CloseAction.Wait;
        if(!active)return !exit&&preferTray&&tray?CloseAction.Hide:CloseAction.Allow;
        if(exit)return CloseAction.ConfirmExit;
        if(!nativeClose)return CloseAction.Ignore;
        return tray?CloseAction.Hide:CloseAction.ConfirmExit;
    }
}
