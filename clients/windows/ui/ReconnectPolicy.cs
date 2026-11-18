namespace FreeTurn.Windows;
// In-memory explicit connection intent. Never restored from disk or backup.
internal sealed class ReconnectPolicy
{
    internal bool Wanted{get;private set;}
    internal int Attempts{get;private set;}
    private DateTimeOffset next;
    internal void Started(DateTimeOffset now){Wanted=true;Attempts=0;next=now.AddSeconds(2);}
    internal void Stop(){Wanted=false;Attempts=0;}
    internal void Healthy(DateTimeOffset now){if(Wanted){Attempts=0;next=now.AddSeconds(2);}}
    internal bool TryBegin(DateTimeOffset now){if(!Wanted||Attempts>=5||now<next)return false;Attempts++;next=now.AddSeconds(Math.Min(30,Math.Pow(2,Attempts+1)));return true;}
}
