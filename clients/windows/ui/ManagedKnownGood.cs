using System.Globalization;
using System.Text.Json.Serialization;

namespace FreeTurn.Windows;

internal sealed record ManagedKnownGood(string Share,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedConfig? Config,string VerifiedAt,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]string? Path=null)
{
 internal bool Valid=>(Path is null or "direct" or "relay")&&Share is{Length:>0 and <=98304}&&Share.StartsWith("freeturn://",StringComparison.Ordinal)&&
  (Config is null||Config.Valid&&Config.Share==Share)&&VerifiedAt is{Length:<=40}&&DateTimeOffset.TryParse(VerifiedAt,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out _);
 public override string ToString()=>"ManagedKnownGood (private fields omitted)";
}
