"""Bounded, typed Unix IPC. The unprivileged API never opens the root SQLite DB."""

import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct

from .agent import NetworkAgent, reconcile
from .compat import managed_status
from .installer import _unique_object, read_private_json
from .store import Store, ValidationError, Conflict
from .client_protocol import ClientFault, ERRORS

SOCKET = "/run/ftm/control.sock"
MAX_REQUEST = 16384
MAX_RESPONSE = 512 * 1024


def _fields(value, required=(), optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValidationError("Invalid control request fields")
    return value


def execute(request, *, uid, api_uid, store, agent, exports=None, history=None):
    if uid not in (0, api_uid):
        raise PermissionError("Control peer is not authorized")
    _fields(request, ("v", "op", "args"))
    if type(request["v"]) is not int or request["v"] != 1 or not isinstance(request["op"], str):
        raise ValidationError("Unsupported control protocol")
    operation, args = request["op"], request["args"]
    if operation in ("subscriptions.list", "admin.subscription_revoke"):
        from .credentials import Credentials
        credentials = Credentials(store)
        if operation == "subscriptions.list":
            _fields(args, ("page", "search"))
            return credentials.list_subscriptions(page=args["page"], search=args["search"])
        _fields(args, ("user_id", "expected_version", "password"))
        if type(args["expected_version"]) is not int or not 1 <= args["expected_version"] <= 2**63 - 2:
            raise ClientFault("invalid_request")
        if exports is None:
            raise ClientFault("service_unavailable")
        exports.authenticate(args["password"])
        try:
            credentials.revoke_subscription(args["user_id"], expected_version=args["expected_version"])
        except Conflict:
            raise ClientFault("subscription_conflict") from None
        return {"revoked": True}
    if operation in ('admin.bootstrap_export', 'admin.subscription_export'):
        required = ('user_id', 'request_id', 'password', 'name', 'platform') if operation == 'admin.bootstrap_export' else ('user_id', 'request_id', 'password')
        _fields(args, required)
        if not all(isinstance(v, str) for v in args.values()):
            raise ClientFault('invalid_request')
        if exports is None:
            raise ClientFault('service_unavailable')
        return exports.export('bootstrap' if operation == 'admin.bootstrap_export' else 'subscription', args)
    if operation == "client.bootstrap_claim":
        _fields(args, ("nonce", "device_id", "device_token_hash", "source_ip"))
        if not all(isinstance(v, str) for v in args.values()) or len(args['source_ip']) > 45:
            raise ClientFault('invalid_request')
        from .bootstrap import Bootstraps
        return Bootstraps(store, agent).claim(args['nonce'], args['device_id'], args['device_token_hash'], args['source_ip'])
    if operation in ("routing.get", "routing.publish", "client.routing"):
        from .routing_policy import RoutingPublication, CAPABILITY
        publication = RoutingPublication(store)
        if operation == "client.routing":
            _fields(args, ("token", "capability"))
            if args["capability"] != CAPABILITY: raise ClientFault("invalid_request")
            from .client_service import ClientService
            client = ClientService(store, agent); device = client._device(args["token"])
            if device["state"] != "active": raise ClientFault("service_unavailable")
            client._spec(device)
            return publication.read()
        if operation == "routing.get":
            _fields(args)
            result = publication.read()
            # Panel never needs the compressed catalogue itself.
            result["catalog"] = {"sha256": result["catalog"]["sha256"]} if result["catalog"] else None
            return result
        _fields(args, ("expected_revision", "policy"))
        try:
            return publication.publish(args["expected_revision"], args["policy"])
        except Conflict:
            raise ClientFault("routing_conflict") from None
    if operation in ("routing.get", "routing.publish", "client.routing"):
        from .routing_policy import RoutingPublication, CAPABILITY
        publication = RoutingPublication(store)
        if operation == "client.routing":
            _fields(args, ("token", "capability"))
            if args["capability"] != CAPABILITY: raise ClientFault("invalid_request")
            from .client_service import ClientService
            client = ClientService(store, agent); device = client._device(args["token"])
            if device["state"] != "active": raise ClientFault("service_unavailable")
            client._spec(device)
            return publication.read()
        if operation == "routing.get":
            _fields(args)
            result = publication.read()
            result["catalog"] = {"sha256": result["catalog"]["sha256"]} if result["catalog"] else None
            return result
        _fields(args, ("expected_revision", "policy"))
        try:
            return publication.publish(args["expected_revision"], args["policy"])
        except Conflict:
            raise ClientFault("routing_conflict") from None
    if operation in ("client.enroll", "client.status", "client.subscription"):
        from .client_service import ClientService
        client = ClientService(store, agent)
        if operation == "client.enroll":
            _fields(args, ("token", "registration"))
            return client.enroll(args["token"], args["registration"])
        _fields(args, ("token",), ("if_none_match",) if operation == "client.subscription" else ())
        if "if_none_match" in args and (not isinstance(args["if_none_match"], str) or len(args["if_none_match"]) > 512):
            raise ClientFault("invalid_request")
        return client.status(args["token"]) if operation == "client.status" else client.subscription(args["token"], args.get("if_none_match"))
    if operation == "status":
        _fields(args)
        return managed_status(agent.baseline, agent._registry())
    if operation == "metrics":
        _fields(args)
        from .metrics import collect
        return collect(agent.baseline)
    if operation == "metrics.history":
        _fields(args, ("hours",))
        if history is None:
            raise ClientFault("service_unavailable")
        return history.read(args["hours"])
    if operation == "users.list":
        _fields(args)
        return store.list_users()
    if operation == "events.list":
        _fields(args, optional=("limit",))
        return store.list_events(args.get("limit", 100))
    if operation == "users.create":
        _fields(args, ("name",), ("device_limit",))
        return store.create_user(args["name"], args.get("device_limit"))
    if operation == "users.set_enabled":
        _fields(args, ("id", "enabled"))
        if not isinstance(args["id"], str) or type(args["enabled"]) is not bool:
            raise ValidationError("Invalid user operation")
        store.set_user_enabled(args["id"], args["enabled"])
        return {"accepted": True, "apply": reconcile(store, agent)}
    if operation == "devices.list":
        _fields(args, optional=("user_id", "telemetry"))
        if "user_id" in args and not isinstance(args["user_id"], str):
            raise ValidationError("Invalid user identifier")
        if "telemetry" in args and type(args["telemetry"]) is not bool:
            raise ValidationError("Invalid telemetry flag")
        counters = None
        if args.get("telemetry"):
            from .metrics import wireguard_counters
            counters = wireguard_counters(agent.baseline) or {}
        return store.list_devices(args.get("user_id"), counters=counters)
    if operation == "devices.add":
        _fields(args, ("user_id", "name", "platform", "public_key", "request_id"))
        if not all(isinstance(value, str) for value in args.values()):
            raise ValidationError("Invalid device operation")
        device = store.create_device(args["user_id"], args["name"], args["platform"], args["public_key"], args["request_id"])
        report = reconcile(store, agent)
        return {"id": device["id"], "ip": device["ip"], "apply": report,
                "state": store.get_device(device["id"])["state"]}
    if operation == "devices.set_enabled":
        _fields(args, ("id", "enabled"))
        if not isinstance(args["id"], str) or type(args["enabled"]) is not bool:
            raise ValidationError("Invalid device operation")
        store.set_device_enabled(args["id"], args["enabled"])
        return {"accepted": True, "apply": reconcile(store, agent), "state": store.get_device(args["id"])["state"]}
    raise ValidationError("Unknown control operation")


def request(operation, args=None, *, path=SOCKET, timeout=30):
    """Client used by the API. Only structured data, no shell or sudo."""
    data = json.dumps({"v": 1, "op": operation, "args": {} if args is None else args}, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAX_REQUEST:
        raise ValidationError("Control request exceeds size limit")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(data)
        with connection.makefile("rb") as stream:
            raw = stream.readline(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE or not raw.endswith(b"\n"):
        raise RuntimeError("Control response rejected")
    reply = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        if isinstance(reply, dict) and reply.get("error") in ERRORS:
            raise ClientFault(reply["error"])
        raise RuntimeError("Control operation rejected or unavailable")
    return reply["result"]


class _Handler(socketserver.StreamRequestHandler):
    timeout = 3

    def handle(self):
        try:
            _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid not in (0, self.server.api_uid):
                raise PermissionError()
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                raise ValidationError("Invalid request frame")
            value = json.loads(raw, object_pairs_hook=_unique_object)
            import fcntl
            fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                # Maintenance may hold this lock while a root user enters a
                # recovery phrase. Return unavailable instead of blocking the
                # single control worker and accumulating queued requests.
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = execute(value, uid=uid, api_uid=self.server.api_uid, store=self.server.store,
                                 agent=self.server.agent, exports=self.server.exports, history=self.server.history)
            finally:
                os.close(fd)
            response = {"ok": True, "result": result}
        except ClientFault as error:
            response = {"ok": False, "error": error.code}
        except Exception:
            # The request and exception may contain credentials; never log them.
            response = {"ok": False, "error": "rejected_or_unavailable"}
        data = json.dumps(response, separators=(",", ":")).encode() + b"\n"
        if len(data) > MAX_RESPONSE:
            data = b'{"ok":false,"error":"response_too_large"}\n'
        try:
            self.wfile.write(data)
        except (OSError, TimeoutError):
            pass


def serve():
    if os.name != "posix" or os.geteuid() != 0 or not hasattr(socket, "SO_PEERCRED"):
        raise ValidationError("Control service requires root on Linux")
    import fcntl
    import pwd

    class Server(socketserver.UnixStreamServer):
        request_queue_size = 8

        def service_actions(self):
            self.reconciler.tick()
            self.exports.tick()
            self.history.tick()

        def handle_error(self, request, client_address):
            print("Control request failed; details withheld", file=__import__("sys").stderr)

    account = pwd.getpwnam("ftm-api")
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValidationError("API account must be unprivileged")
    directory = Path(SOCKET).parent
    if (directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != 0
            or directory.stat().st_gid != account.pw_gid or directory.stat().st_mode & 0o027):
        raise ValidationError("Control directory must be root-owned and protected")
    for path in (Path("/var/lib/ftm"), Path("/var/lib/ftm/manager.sqlite3"), Path("/var/lib/ftm-agent")):
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
            raise ValidationError("Root metadata ownership is required")
    lock_fd = os.open(directory / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        endpoint = Path(SOCKET)
        if endpoint.is_symlink():
            raise ValidationError("Control socket symlink rejected")
        if endpoint.exists():
            info = endpoint.stat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise ValidationError("Unexpected control socket path")
            endpoint.unlink()
        state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
        store = Store("/var/lib/ftm/manager.sqlite3")
        store.initialize()  # Root-only idempotent metadata schema upgrade; no VPN changes.
        with store.connect() as db:
            subnet = db.execute("SELECT value FROM settings WHERE key='subnet'").fetchone()[0]
        if subnet != state["subnet"]:
            raise ValidationError("Database subnet differs from the active VPN")
        agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
        from .reconcile_loop import ReconcileLoop
        with Server(SOCKET, _Handler) as server:
            os.chown(SOCKET, 0, account.pw_gid)
            os.chmod(SOCKET, 0o660)
            server.api_uid, server.store, server.agent = account.pw_uid, store, agent
            from .admin_exports import AdminExports
            from .metrics_history import MetricsHistory
            server.exports = AdminExports(store, agent)
            server.reconciler = ReconcileLoop(store, agent)
            server.history = MetricsHistory("/var/lib/ftm/monitoring.sqlite3", state)
            server.serve_forever(poll_interval=0.5)
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    if not args.serve:
        parser.error("Use --serve via the fixed systemd service")
    serve()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError):
        print("Control service failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
