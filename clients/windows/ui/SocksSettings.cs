namespace FreeTurn.Windows;
internal sealed record SocksSettings(int Port=1080,string User="freeturn",string Password="",RoutingPolicy? Routing=null)
{
    public override string ToString()=>"SocksSettings (private fields omitted)";
    internal bool Valid=>Port is >=1024 and <=65535&&Port!=8765&&User is not null&&Password is not null&&System.Text.Encoding.UTF8.GetByteCount(User) is >=1 and <=255&&System.Text.Encoding.UTF8.GetByteCount(Password) is >=12 and <=255&&(Routing is null||Routing.Valid);
}
