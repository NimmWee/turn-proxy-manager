using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace FreeTurn.Windows;

internal enum ManagedRefresh {Pending,Unchanged,Staged}
internal sealed class ManagedRetryException(TimeSpan delay):IOException("MANAGED_RATE_LIMITED")
{
 internal TimeSpan Delay {get;}=delay;
}
internal static class ManagedSubscription
{
 internal static async Task<ManagedRefresh> Refresh(ProfileCatalog catalog,Guid id,bool connected,HttpMessageHandler? syntheticHandler=null,
  Func<SavedProfile,Task>? verify=null,Func<SavedProfile,string,string,long,Task<ManagedConfig>>? build=null,
  CancellationToken cancellation=default,Func<Task>? ensureCurrent=null)
 {
  if(!connected)throw new IOException("MANAGED_CONNECT_FIRST");
  var p=catalog.Read().Profiles.SingleOrDefault(p=>p.Id==id)??throw new IOException("PROFILE_NOT_FOUND");
  var m=p.Managed??throw new IOException("MANAGED_CONFIG_INVALID");
  if(!m.Valid||!m.Registered)throw new IOException("MANAGED_ACTIVATE_FIRST");
  await (verify??ManagedBootstrap.VerifySaved)(p);var builder=build??ManagedUpdateBuilder.Build;
  var cached=m.Pending??m.Applied;
  if(cached is not null){var checkedCache=await builder(p,cached.Manifest,cached.ETag,cached.Revision);if(checkedCache!=cached)throw new IOException("MANAGED_CONFIG_INVALID");if(cached.Revision<m.SeenRevision)cached=null;}
  using var client=syntheticHandler is null?new HttpClient(ManagedClient.CreateTransport(m)):new HttpClient(syntheticHandler,false);
  client.Timeout=TimeSpan.FromSeconds(15);using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(15));
  async Task Current(){timeout.Token.ThrowIfCancellationRequested();if(ensureCurrent is not null)await ensureCurrent();timeout.Token.ThrowIfCancellationRequested();}
  using var request=new HttpRequestMessage(HttpMethod.Get,m.Origin+"/api/client/v1/subscription"){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
  request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",m.DeviceToken);request.Headers.Accept.Add(new("application/json"));
  if(cached is not null)request.Headers.IfNoneMatch.Add(new EntityTagHeaderValue(cached.ETag));
  try{
   await Current();
   using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
   await Current();
   if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden){catalog.DenyManaged(p);throw new IOException("MANAGED_ACCESS_REJECTED");}
   if(response.StatusCode==HttpStatusCode.Accepted){await ManagedClient.ReadBody(response,timeout.Token);return ManagedRefresh.Pending;}
   var etag=response.Headers.ETag?.ToString();
   if(response.StatusCode==HttpStatusCode.NotModified){
    if(cached is null||etag!=cached.ETag||(await ManagedClient.ReadBody(response,timeout.Token)).Length!=0)throw new IOException("MANAGED_RESPONSE_INVALID");
    await Current();catalog.ConfirmManagedUnchanged(p);return ManagedRefresh.Unchanged;
   }
   if(response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable){
    var retry=response.Headers.RetryAfter;var delay=retry?.Delta??(retry?.Date is{} date?date-DateTimeOffset.UtcNow:TimeSpan.FromMinutes(1));
    throw new ManagedRetryException(TimeSpan.FromSeconds(Math.Clamp(delay.TotalSeconds,60,86400)));
   }
   if(response.StatusCode!=HttpStatusCode.OK)throw new IOException("MANAGED_SERVER_REJECTED");
   var raw=await ManagedClient.ReadBody(response,timeout.Token);var manifest=new UTF8Encoding(false,true).GetString(raw);
   if(etag is null)throw new IOException("MANAGED_RESPONSE_INVALID");
   var candidate=await builder(p,manifest,etag,m.SeenRevision);await Current();catalog.StageManaged(p,candidate);return ManagedRefresh.Staged;
  }catch(IOException e)when(e.Message.StartsWith("MANAGED_",StringComparison.Ordinal)){throw;}
  catch(OperationCanceledException)when(cancellation.IsCancellationRequested){throw;}
  catch{throw new IOException("MANAGED_NETWORK_FAILED");}
 }
 internal static async Task Apply(ProfileCatalog catalog,Guid id)
 {
  var p=catalog.Read().Profiles.Single(p=>p.Id==id);var m=p.Managed??throw new IOException("MANAGED_CONFIG_INVALID");
  if(m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");
  if(m.Pending is null)throw new IOException("MANAGED_CONFIG_INVALID");
  var verified=await ManagedUpdateBuilder.Verify(p,m.Pending,m.SeenRevision);catalog.ApplyManaged(p,verified);
 }
 internal static async Task Rollback(ProfileCatalog catalog,Guid id)
 {
  var p=catalog.Read().Profiles.Single(p=>p.Id==id);var m=p.Managed??throw new IOException("MANAGED_CONFIG_INVALID");
  if(m.AccessDenied)throw new IOException("MANAGED_ACCESS_REJECTED");if(m.PreviousShare is null)throw new IOException("MANAGED_NO_ROLLBACK");
  await ManagedBootstrap.VerifySaved(p with{Share=m.PreviousShare});
  if(m.Previous is not null)await ManagedUpdateBuilder.Verify(p,m.Previous,m.Previous.Revision);
  catalog.RollbackManaged(p);
 }
}
