"""Pure Windows child-process interop against the existing Python v1 contract.

All values synthetic. No file storage, network, services or route mutations.
Run from repository root after building the packaged engine.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ftm.managed_profile import to_share, validate_manifest


def decode(share):
    encoded = share.removeprefix("freeturn://")
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, default=ROOT / "clients/windows/artifacts/package/FreeTurn.Engine.exe")
    engine = parser.parse_args().engine.resolve()
    key = base64.b64encode(b"x" * 32).decode()
    public = "m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY="
    manifest = {
        "schema_version": 1, "format": "ftm-managed",
        "device_id": "11111111-2222-3333-4444-555555555555", "revision": 3,
        "name": "Проверка <>& 😀\u2028\\u2028", "platform": "windows",
        "wireguard": {"client_public_key": public, "addresses": ["10.77.43.9/32"],
                      "server_public_key": key, "preshared_key": key,
                      "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "8.8.8.8"],
                      "mtu": 1280, "local_endpoint": "127.0.0.1:9000",
                      "persistent_keepalive": 25, "ipv6_policy": "block"},
        "freeturn": {"v": 1, "provider": "vk", "peer": "8.8.8.8:5000", "transport": "tcp",
                     "mode": "udp", "obf": "rtpopus3", "key": "a" * 64, "n": 6, "spc": 3,
                     "cid": "b" * 32, "dns": "auto", "mcap": False,
                     "vk": "https://vk.com/call/join/SYNTHETIC"},
        "management": {"origin": "https://8.8.8.8", "api_path": "/api/client/v1/",
                       "internal_api_ip": "10.77.43.1", "tls_server_name": "8.8.8.8", "refresh_seconds": 1800},
    }
    validate_manifest(manifest, expected_public_key=public, expected_origin="https://8.8.8.8")
    native = to_share(manifest, key, expected_public_key=public, expected_origin="https://8.8.8.8")
    etag = '"' + hashlib.sha256(json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest() + '"'
    request = dict(manifest=manifest, current_share=native, device_id=manifest["device_id"],
                   public_key=public, origin="https://8.8.8.8", etag=etag, min_revision=3)

    def run(operation="--build-managed"):
        result = subprocess.run([str(engine), operation], input=json.dumps(request).encode(),
                                capture_output=True, timeout=15, check=False)
        return result.returncode, json.loads(result.stdout)

    code, result = run()
    assert code == 0 and result["ok"] and result["etag"] == etag
    assert decode(result["share"]) == decode(native), "Python/native share mismatch (values withheld)"
    request["etag"] = '"' + "0" * 64 + '"'
    code, result = run()
    assert code == 1 and result == {"ok": False, "error": "MANAGED_CONFIG_INVALID"}
    request["etag"] = etag
    request.pop("current_share")
    request.update(private_key=key, client_id=manifest["freeturn"]["cid"])
    code, result = run("--build-enrollment")
    assert code == 0 and decode(result["share"]) == decode(native)
    request["client_id"] = "c" * 32
    code, result = run("--build-enrollment")
    assert code == 1 and result == {"ok": False, "error": "MANAGED_ENROLLMENT_INVALID"}
    print("PASS: Python schema/Unicode ETag/share assembly matches Go refresh+first enrollment; key/CID/tamper refusal; no network/services")


if __name__ == "__main__":
    main()
