"""Local synthetic SSH host-key/auth check. Never connects to an external host."""
import base64
import hashlib
import logging
import socket
import subprocess
import threading
from pathlib import Path

import paramiko

logging.getLogger("paramiko").addHandler(logging.NullHandler())
logging.getLogger("paramiko").propagate = False
root = Path(__file__).resolve().parent
key = paramiko.RSAKey.generate(2048)
fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(4)
listener.settimeout(1)
port = listener.getsockname()[1]
stop = threading.Event()
auth_attempts = []
shell_attempts = []

class Server(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        auth_attempts.append(True)
        return paramiko.AUTH_SUCCESSFUL if username == "ftm-synthetic" and password == "SYNTHETIC_PASSWORD" else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, channel_id):
        shell_attempts.append(True)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def serve():
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        transport = paramiko.Transport(connection)
        try:
            transport.add_server_key(key)
            transport.start_server(server=Server())
            while transport.is_active() and not stop.wait(0.05):
                pass
        except (EOFError, paramiko.SSHException, OSError):
            pass
        finally:
            transport.close()

thread = threading.Thread(target=serve, daemon=True)
thread.start()
try:
    subprocess.run(["dotnet", "build", str(root / "catalog-check/CatalogCheck.csproj"), "-c", "Release"], check=True, capture_output=True)
    dll = root / "catalog-check/bin/Release/net8.0-windows/CatalogCheck.dll"
    for pin, expected, count in [("none", "untrusted", 0), ("SHA256:" + "A" * 43, "changed", 0), (fingerprint, "authenticated", 1)]:
        result = subprocess.run(["dotnet", str(dll), "--ssh-loopback", str(port), pin, expected], capture_output=True, text=True, timeout=25)
        if result.returncode or len(auth_attempts) != count or shell_attempts:
            raise RuntimeError("Local SSH host-key/auth boundary failed")
    print("PASS: unknown/changed SSH key blocks credentials; pinned key authenticates once; no shell/commands")
finally:
    stop.set()
    thread.join(timeout=3)
    listener.close()
