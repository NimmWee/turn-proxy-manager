using System.IO;

namespace FreeTurn.Windows;

internal static class ProfileSelection
{
 internal static SavedProfile? ForConnect(ProfileSnapshot data)
 {
  var selected=data.Profiles.SingleOrDefault(p=>p.Id==data.ActiveId);
  if(selected is null&&data.Profiles.Count>0)throw new IOException("PROFILE_NOT_SELECTED");
  return selected; // Legacy service-only profile is allowed only with an empty catalog.
 }
}
