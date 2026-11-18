namespace FreeTurn.Windows;

internal sealed record EffectiveSettings(int RequestedStreams,int StreamLimit,int StreamsPerCredential,string Provider,string Transport,string DnsMode,bool ManualCaptcha,bool AdvancedCaptcha,int WireGuardMTU,string VPNProtocol="")
{
 internal bool Valid=>RequestedStreams is >=1 and <=32&&StreamLimit is >=1 and <=32&&StreamsPerCredential is >=1 and <=16&&Provider is "vk" or "direct"&&Transport is "tcp" or "udp" or "dtls"&&DnsMode is "auto" or "plain" or "doh"&&(WireGuardMTU==0||WireGuardMTU is >=1280 and <=1420)&&VPNProtocol is "" or "wireguard" or "amneziawg1" or "amneziawg2" or "amneziawg3";
 internal string ProtocolLabel=>VPNProtocol switch{"amneziawg1"=>"AmneziaWG 1","amneziawg2"=>"AmneziaWG 2","amneziawg3"=>"AmneziaWG 3",_=>"WireGuard"};
 internal string Summary=>!Valid?"":Provider=="direct"?$"Direct: лимит потоков {StreamLimit} · Relay: {RequestedStreams}, на учётные данные {StreamsPerCredential}":$"Relay: лимит {StreamLimit} потоков · на учётные данные {StreamsPerCredential} · {Transport.ToUpperInvariant()}";
}
