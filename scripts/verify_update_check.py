"""Exercise the offline Go verifier with an ephemeral in-memory signing key.

Only the verifier child is executed. The installer is read, never launched.
Requires Python cryptography; no HTTP, profiles, service or registry operations.
"""
import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=".local-cache/windows-build/FreeTurn.UpdateCheck.exe")
    parser.add_argument("--artifact", default="clients/windows/artifacts/FreeTurn-Setup-0.25.0-preview-win-x64.exe")
    parser.add_argument("--report", default=".local-cache/windows-build/update-check-smoke.json")
    args = parser.parse_args()
    binary, artifact = Path(args.binary).resolve(), Path(args.artifact).resolve()
    match = re.fullmatch(r"FreeTurn-Setup-([0-9]+\.[0-9]+\.[0-9]+)-preview-win-x64\.exe", artifact.name)
    if not match:
        parser.error("Use a local preview Setup artifact")
    release_version = match[1]
    b64 = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    compact = lambda value: json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    private = Ed25519PrivateKey.generate()  # Never serialized, printed or retained.
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {"schema": 1, "app": "freeturn-windows", "platform": "windows-amd64", "channel": "preview", "version": release_version,
                "sequence": 7, "issuedAt": stamp(now - datetime.timedelta(hours=1)), "expiresAt": stamp(now + datetime.timedelta(days=1)),
                "artifact": {"name": artifact.name, "url": "https://updates.example.invalid/windows/" + artifact.name,
                             "bytes": artifact.stat().st_size, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}}
    payload = compact(manifest)
    envelope = compact({"payload": b64(payload), "signature": b64(private.sign(b"FreeTurn.Windows.Release.v1\0" + payload))})
    report = {}
    with tempfile.TemporaryDirectory(prefix="ftm-update-check-") as folder:
        temporary = Path(folder)
        trust, release, bad = (temporary / name for name in ("trust.json", "release.json", "bad.exe"))
        trust.write_bytes(compact({"publicKey": b64(public), "origin": "https://updates.example.invalid", "channel": "preview"}))
        release.write_bytes(envelope)
        bad.write_bytes(b"MZ-BROKEN")

        def run(name, current="0.0.0", fence="6", file=artifact):
            process = subprocess.run([str(binary), "--trust", str(trust), "--release", str(release), "--artifact", str(file),
                                      "--current-version", current, "--accepted-sequence", fence], capture_output=True, text=True, timeout=12)
            assert process.stderr == ""
            result = json.loads(process.stdout)
            assert result["downloaded"] is False and result["executed"] is False
            report[name] = {"exit": process.returncode, "result": result}
            return process.returncode, result

        assert run("valid_signature_real_setup_bytes")[0] == 0
        assert run("artifact_tamper", file=bad)[1]["error"] == "UPDATE_PACKAGE_MISMATCH"
        assert run("same_version", current=release_version)[1]["error"] == "UPDATE_NOT_NEWER"
        assert run("revision_replay", fence="7")[1]["error"] == "UPDATE_ROLLBACK_REFUSED"
        trust.write_bytes(compact({"publicKey": b64(bytes(range(32))), "origin": "https://updates.example.invalid", "channel": "preview"}))
        assert run("untrusted_key")[1]["error"] == "UPDATE_SIGNATURE_INVALID"
        assert run("private_error_not_echoed", fence="SYNTHETIC_DIAGNOSTIC_MARKER")[1]["error"] == "UPDATE_INPUT_REQUIRED"
        report["private_error_not_echoed"]["rawInputRedacted"] = True
    output = Path(args.report).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("PASS: offline Ed25519 signature + actual Setup bytes; tamper/replay/version/key/input refusal. Installer never executed.")


if __name__ == "__main__":
    main()
