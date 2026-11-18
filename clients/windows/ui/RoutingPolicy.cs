using System.Text.Json.Serialization;

namespace FreeTurn.Windows;

internal sealed record DomainRule(
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("subdomains")] bool Subdomains)
{
    public override string ToString() => Domain + "   ·   " + ActionLabel(Action) + (Subdomains ? " · с поддоменами" : " · только этот домен");
    internal static string ActionLabel(string action) => action switch { "direct" => "Напрямую", "block" => "Блокировать", _ => "Через VPN" };
}

internal sealed record RoutingPolicy(
    [property: JsonPropertyName("v")] int V,
    [property: JsonPropertyName("rules")] List<DomainRule> Rules)
{
    public override string ToString() => "RoutingPolicy (domains omitted)";
    // Storage bounds only. The engine's pinned IDNA/PSL classifier is authoritative
    // before save/start; a damaged file must never create an unbounded request.
    internal bool Valid => V == 1 && Rules is not null && Rules.Count <= 300 && Rules.All(r => r is not null && r.Domain is not null && r.Domain.Length is >= 3 and <= 1024 && !r.Domain.Any(char.IsControl) && r.Action is "direct" or "vpn" or "block");
}
