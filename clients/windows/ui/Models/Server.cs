// SPDX-License-Identifier: GPL-3.0-only
// Adapted from Android 5.3.4 data/server/Server.kt; see THIRD_PARTY.md.
namespace FreeTurn.Windows.Models;

internal sealed record Server(Guid Id, string Name, ClientConfig Client)
{
    public SshConfig Ssh { get; init; } = new();
    public string ProxyListen { get; init; } = "0.0.0.0:56000";
    public string ProxyConnect { get; init; } = "127.0.0.1:40537";
    public ServerOptions Options { get; init; } = new();
    public override string ToString()=>Name;
}
internal sealed record ServersSnapshot(IReadOnlyList<Server> Servers, Guid? ActiveId, bool Loaded)
{
    public Server? Active => Servers.FirstOrDefault(s => s.Id == ActiveId);
}
