using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FreeTurn.Windows;

// A validated configuration candidate, not proof of successful VPN traffic.
internal sealed record ManagedConfig(string Manifest,string Share,string ETag,long Revision)
{
 public override string ToString()=>"ManagedConfig (private fields omitted)";
 internal bool Valid{
  get{try{
   if(Manifest is null||Encoding.UTF8.GetByteCount(Manifest)>65536||Share is null||Share.Length>65536||Revision<1||ETag is null||!Regex.IsMatch(ETag,"\\A\"[a-f0-9]{64}\"\\z"))return false;
   using var doc=JsonDocument.Parse(Manifest,new(){MaxDepth=8});ShareDocument.Unique(doc.RootElement);
   _=new ShareDocument(Share);return doc.RootElement.ValueKind==JsonValueKind.Object;
  }catch{return false;}}
 }
}
