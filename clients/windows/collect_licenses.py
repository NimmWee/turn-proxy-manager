"""Collect dependency notices for the local package without executing upstream code."""
import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument("--go", required=True)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
output = args.output or root / "artifacts" / "package" / "THIRD_PARTY_NOTICES.txt"
modules = subprocess.check_output([args.go, "list", "-m", "-json", "-mod=readonly", "all"], cwd=root / "engine", text=True)
decoder = json.JSONDecoder()
remaining = modules
notices = []
go_root=Path(subprocess.check_output([args.go,'env','GOROOT'],text=True).strip())

def collect(directory, label):
    if not directory.is_dir():
        return
    for path in sorted(directory.iterdir()):
        name = path.name.upper()
        if path.is_file() and name.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "THIRDPARTYNOTICES", "THIRD-PARTY")):
            notices.append(f"\n{'=' * 72}\n{label} — {path.name}\n{'=' * 72}\n" + path.read_text(encoding="utf-8", errors="replace"))

collect(go_root,'Go toolchain/runtime/standard library')

while remaining.strip():
    module, end = decoder.raw_decode(remaining.lstrip())
    remaining = remaining.lstrip()[end:]
    resolved = module.get("Replace", module)
    if resolved.get("Dir"):
        collect(Path(resolved["Dir"]), module["Path"] + " " + module.get("Version", "local"))
        if module['Path'] == 'github.com/sagernet/sing-tun':
            notices.append('\nWintun Go bindings — MIT\nCopyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.\nSee upstream internal/wintun source headers and official Wintun binary license below.\n')

assets = json.loads((root / "ui" / "obj" / "project.assets.json").read_text(encoding="utf-8"))
target = ET.parse(root / "ui" / "FreeTurn.Windows.csproj").findtext(".//TargetFramework")
runtime = json.loads((root / "ui" / "bin" / "Release" / target / "win-x64" / "FreeTurn.Windows.runtimeconfig.json").read_text())
for folder in assets["packageFolders"]:
    folder = Path(folder)
    for package in assets["libraries"]:
        collect(folder / package.lower(), package)
    for framework in runtime["runtimeOptions"].get("includedFrameworks", []):
        package = framework["name"].lower() + ".runtime.win-x64"
        collect(folder / package / framework["version"], package + " " + framework["version"])

sdk_version = ET.parse(root / "ui" / "FreeTurn.Windows.csproj").findtext(".//WindowsSdkPackageVersion")
if not any((Path(folder)/"microsoft.windows.sdk.net.ref"/sdk_version).is_dir() for folder in assets["packageFolders"]):
    raise RuntimeError("Windows SDK targeting package unavailable")
notices.append("\nMicrosoft.Windows.SDK.NET.Ref " + sdk_version + "\n© Microsoft Corporation. All rights reserved.\nLicense: WindowsSDK-LICENSE.rtf (included); https://aka.ms/WinSDKLicenseURL\n")

notices.append("\nRoboto — Google, Apache-2.0\n" + (root / "Roboto-LICENSE.txt").read_text(encoding="utf-8"))
notices.append("\nSSH.NET 2026.0.1 — MIT\n" + (root / "SSH.NET-LICENSE.txt").read_text(encoding="utf-8"))
notices.append('\nWintun 0.14.1 prebuilt binary\n' + (root / 'Wintun-LICENSE.txt').read_text(encoding='utf-8'))
notices.append('\nPinned routing data\n' + (root / 'engine/routingdata/LICENSES.txt').read_text(encoding='utf-8'))
output.write_text("FreeTurn Windows local development package dependency notices\n" + "\n".join(notices), encoding="utf-8")
print(f"Collected {len(notices)} dependency notice files")
