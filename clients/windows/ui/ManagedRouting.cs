using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace FreeTurn.Windows;
internal sealed record RoutingPublication(int V,long Revision,RoutingPolicyBody Policy,RoutingCatalog? Catalog){
 public override string ToString()=>"Routing publication (domains omitted)";
 internal SystemRoutingSettings Settings(SystemRoutingSettings local)=>local with{PublicationRevision=Revision,Presets=Policy.Presets,Rules=Policy.Rules,DirectDNS=Policy.DirectDNS,Catalog=Catalog};
 internal bool Valid=>V==1&&Revision>=0&&Revision<=9007199254740991&&Policy is not null&&Settings(new()).Valid;
}
internal sealed record RoutingPolicyBody(SystemRoutingPresets Presets,List<DomainRule> Rules,List<string> DirectDNS);
internal sealed record ManagedRoutingState(RoutingPublication Current,RoutingPublication? Previous=null){
 public override string ToString()=>"Managed routing state (domains omitted)";
 internal bool Valid=>Current is{Valid:true}&&(Previous is null||Previous.Valid&&Previous.Revision<Current.Revision);
}
internal static class ManagedRouting{
 internal static async Task<bool> Refresh(ProfileCatalog catalog,Guid id,CancellationToken cancellation=default,Func<Task>? ensureCurrent=null,HttpMessageHandler? syntheticHandler=null,Func<SavedProfile,Task>? verify=null){
  var expected=catalog.Read().Profiles.Single(p=>p.Id==id);var m=expected.Managed;
  if(m is not{Registered:true,AccessDenied:false})throw new IOException("MANAGED_ACTIVATE_FIRST");
  using var client=syntheticHandler is null?new HttpClient(ManagedClient.CreateTransport(m)):new HttpClient(syntheticHandler,false);
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(15));
  async Task Current(){timeout.Token.ThrowIfCancellationRequested();if(ensureCurrent is not null)await ensureCurrent();timeout.Token.ThrowIfCancellationRequested();}
  using var request=new HttpRequestMessage(HttpMethod.Get,m.Origin+"/api/client/v1/routing"){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
  request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",m.DeviceToken);request.Headers.Add("X-FreeTurn-Capability","routing-bundle-v1");
  await (verify??ManagedBootstrap.VerifySaved)(expected);await Current();using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);await Current();
  if(response.StatusCode==HttpStatusCode.NotFound)return false; // Older server.
  if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden){catalog.DenyManaged(expected);throw new IOException("MANAGED_ACCESS_REJECTED");}
  if(response.StatusCode!=HttpStatusCode.OK)throw new IOException("MANAGED_SERVER_REJECTED");
  if(response.Content.Headers.ContentLength>384*1024)throw new IOException("MANAGED_RESPONSE_INVALID");
  using var stream=await response.Content.ReadAsStreamAsync(timeout.Token);using var data=new MemoryStream();var chunk=new byte[4096];
  while(true){var n=await stream.ReadAsync(chunk,timeout.Token);if(n==0)break;if(data.Length+n>384*1024)throw new IOException("MANAGED_RESPONSE_INVALID");data.Write(chunk,0,n);}
  using(var doc=JsonDocument.Parse(data.ToArray(),new(){MaxDepth=10}))ShareDocument.Unique(doc.RootElement);
  var bundle=JsonSerializer.Deserialize<RoutingPublication>(data.ToArray(),new JsonSerializerOptions{PropertyNameCaseInsensitive=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow});
  if(bundle is not{Valid:true})throw new IOException("MANAGED_RESPONSE_INVALID");
  var checkedBundle=await SystemRoutingCheck.Run(bundle.Settings(new(){Enabled=true}));
  if(expected.Routing is{} previous){var checkedPrevious=await SystemRoutingCheck.Run(previous.Current.Settings(new(){Enabled=true}));if(string.CompareOrdinal(checkedBundle.GeoIP!.Release,checkedPrevious.GeoIP!.Release)<0)throw new IOException("MANAGED_RESPONSE_INVALID");}
  await Current();
  catalog.StageRouting(expected,bundle);return true;
 }
}
internal sealed partial class ProfileCatalog{
 internal void StageRouting(SavedProfile expected,RoutingPublication candidate){
  if(!candidate.Valid)throw new IOException("MANAGED_RESPONSE_INVALID");var data=Read();var index=data.Profiles.FindIndex(p=>p.Id==expected.Id);
  if(index<0||expected.Managed is not{Registered:true,AccessDenied:false})throw new IOException("MANAGED_STORAGE_CHANGED");
  var actual=data.Profiles[index];
  if((actual with{Routing=null})!=(expected with{Routing=null})||JsonSerializer.Serialize(actual.Routing)!=JsonSerializer.Serialize(expected.Routing))throw new IOException("MANAGED_STORAGE_CHANGED");
  var old=expected.Routing?.Current;
  // Compare canonical serialisation, not record List reference equality.
  if(old is not null&&(candidate.Revision<old.Revision||candidate.Revision==old.Revision&&JsonSerializer.Serialize(candidate)!=JsonSerializer.Serialize(old)))throw new IOException("MANAGED_RESPONSE_INVALID");
  if(candidate.Revision==0||old?.Revision==candidate.Revision)return;
  data.Profiles[index]=expected with{Routing=new(candidate,old)};Write(data);
 }
}
