"""Fetch the pinned source dependency; never execute downloaded scripts."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
dependency = json.loads((Path(__file__).with_name("dependencies.json")).read_text())["core"]
target = ROOT / ".references" / dependency["directory"]
stamp = target / ".ftm-source-sha256"
data = urllib.request.urlopen(dependency["archive"], timeout=90).read(16 * 1024 * 1024)
if hashlib.sha256(data).hexdigest() != dependency["sha256"]:
    raise SystemExit("FreeTurn source checksum mismatch")
target.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
    expected = set()
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        relative = PurePosixPath(*path.parts[1:])
        if not member.isfile():
            if member.isdir():
                continue
            raise SystemExit("Non-regular source archive entry")
        if relative.is_absolute() or ".." in relative.parts or ":" in str(relative) or "\\" in str(relative):
            raise SystemExit("Unsafe source archive entry")
        destination = target.joinpath(*relative.parts)
        expected.add(destination.resolve())
        destination.parent.mkdir(parents=True, exist_ok=True)
        contents = archive.extractfile(member).read()
        if destination.exists() and destination.read_bytes() != contents:
            raise SystemExit("Pinned source was modified; refusing to overwrite it")
        destination.write_bytes(contents)
    actual = {p.resolve() for p in target.rglob("*") if p.is_file() and p != stamp}
    if actual != expected:
        raise SystemExit("Unexpected files in pinned source directory")
stamp.write_text(dependency["sha256"] + "\n")
print("Pinned FreeTurn source verified and extracted")

driver = json.loads(Path(__file__).with_name("dependencies.json").read_text())["wireguardNT"]
data = urllib.request.urlopen(driver["archive"], timeout=90).read(16 * 1024 * 1024)
if hashlib.sha256(data).hexdigest() != driver["sha256"]:
    raise SystemExit("WireGuardNT archive checksum mismatch")
output = Path(__file__).with_name("artifacts") / "dependencies"
output.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    dll = archive.read("wireguard-nt/bin/amd64/wireguard.dll")
    if hashlib.sha256(dll).hexdigest() != driver["amd64Sha256"]:
        raise SystemExit("WireGuardNT DLL checksum mismatch")
    (output / "wireguard.dll").write_bytes(dll)
    (output / "WireGuardNT-LICENSE.txt").write_bytes(archive.read("wireguard-nt/LICENSE.txt"))
print("Pinned WireGuardNT downloaded; build script must also verify Authenticode")

# sing-tun embeds this precise signed binary; preserve its official binary
# license separately from the MIT Go bindings and GPL library license.
wintun = json.loads(Path(__file__).with_name("dependencies.json").read_text())["wintun"]
data = urllib.request.urlopen(wintun["archive"], timeout=90).read(16 * 1024 * 1024)
if hashlib.sha256(data).hexdigest() != wintun["sha256"]:
    raise SystemExit("Wintun archive checksum mismatch")
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    dll = archive.read("wintun/bin/amd64/wintun.dll")
    license = archive.read("wintun/LICENSE.txt")
    if hashlib.sha256(dll).hexdigest() != wintun["amd64Sha256"] or hashlib.sha256(license).hexdigest() != wintun["licenseSha256"]:
        raise SystemExit("Wintun binary/license checksum mismatch")
    Path(__file__).with_name("Wintun-LICENSE.txt").write_bytes(license)
print("Pinned Wintun binary and license verified; DLL is embedded by sing-tun")
