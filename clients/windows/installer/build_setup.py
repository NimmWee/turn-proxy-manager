"""Build an offline Windows Setup around the unchanged frozen preview payload.

No installation, elevation, service changes or downloads are performed here.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--compiler", required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[2]
    lock = json.loads((source / "toolchain.lock.json").read_text(encoding="utf-8"))
    compiler = Path(args.compiler).resolve()
    for name, digest in lock["compilerFiles"].items():
        path = compiler / name
        if not path.resolve().is_relative_to(compiler) or sha(path.read_bytes()) != digest:
            raise RuntimeError("Pinned compiler component mismatch")
    version = lock["payloadVersion"]
    archive = root / f"clients/windows/artifacts/FreeTurn-Windows-{version}-preview-win-x64.zip"
    if sha(archive.read_bytes()) != lock["payloadZIP_SHA256"]:
        raise RuntimeError("Frozen payload mismatch")
    target = root / f"clients/windows/artifacts/FreeTurn-Setup-{version}-preview-win-x64.exe"
    sources_target = target.with_name(f"FreeTurn-Setup-{version}-Sources.zip")
    if target.exists() or sources_target.exists() or target.with_suffix(".sha256").exists():
        raise RuntimeError("Existing setup artifact is preserved; choose a new installer revision before rebuilding")
    stage = root / f".local-cache/windows-setup/{version}"
    stage.mkdir(parents=True, exist_ok=True)
    package = stage / "payload"
    package.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as frozen:
        names = frozen.namelist()
        if len(names) != 16 or len(set(names)) != len(names) or any(Path(n).name != n or ":" in n or "\\" in n for n in names):
            raise RuntimeError("Unexpected payload archive shape")
        for name in names:
            (package / name).write_bytes(frozen.read(name))
    for line in (package / "SHA256SUMS.txt").read_text(encoding="utf-8-sig").splitlines():
        digest, name = line.split("  ", 1)
        if name not in names or sha((package / name).read_bytes()) != digest:
            raise RuntimeError("Payload manifest mismatch")
    with zipfile.ZipFile(package / "Windows-Client-Sources.zip") as sources:
        (stage / "FreeTurn.ico").write_bytes(sources.read("clients/windows/ui/Assets/FreeTurn.ico"))
    guard = source / "guard"
    for action in ([args.go, "test", "-mod=readonly", "./..."], [args.go, "vet", "-mod=readonly", "./..."],
                   [args.go, "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", str(stage / "FreeTurn.SetupGuard.exe"), "."]):
        subprocess.run(action, cwd=guard, check=True)
    (stage / ".freeturn-setup-v1").write_text("FreeTurn desktop setup v1\n", encoding="ascii")
    (stage / "payload.iss").write_text("\n".join(f'Source: "{{#PackageDir}}\\{n}"; DestDir: "{{app}}"; Flags: ignoreversion' for n in names), encoding="utf-8")
    source_files = [p for p in sorted(source.rglob("*")) if p.is_file() and p.suffix in (".go", ".mod", ".sum", ".py", ".iss", ".json", ".md", ".txt") and "__pycache__" not in p.parts]
    source_hashes = {}
    with zipfile.ZipFile(stage / "FreeTurn-Setup-Sources.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in source_files:
            name = path.relative_to(source).as_posix()
            raw = path.read_bytes()
            item = zipfile.ZipInfo(name, (2026, 11, 18, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            bundle.writestr(item, raw)
            source_hashes[name] = sha(raw)
        bundle.writestr("LICENSE", (package / "Android-LICENSE.txt").read_bytes())
    parts = [int(p) for p in version.split(".")]
    ms, ls = parts[0] * 65536 + parts[1], parts[2] * 65536
    output = stage / "output"
    output.mkdir(exist_ok=True)
    command = [str(compiler / "ISCC.exe"), f"/DPackageDir={package}", f"/DStageDir={stage}",
               f"/DOutputDirectory={output}", f"/DAppVersion={version}", f"/DAppVersionMS={ms}", f"/DAppVersionLS={ls}", str(source / "FreeTurn.iss")]
    subprocess.run(command, check=True)
    built = output / target.name
    if sha(archive.read_bytes()) != lock["payloadZIP_SHA256"]:
        raise RuntimeError("Frozen payload changed")
    shutil.copyfile(built, target)
    shutil.copyfile(stage / "FreeTurn-Setup-Sources.zip", sources_target)
    report = {"version": version, "setupSHA256": sha(target.read_bytes()), "sizeMiB": round(target.stat().st_size / 2**20, 2),
              "payloadSHA256": lock["payloadZIP_SHA256"], "guardSHA256": sha((stage / "FreeTurn.SetupGuard.exe").read_bytes()),
              "setupSourcesSHA256": sha(sources_target.read_bytes()), "sources": source_hashes,
              "installUpgradeUninstallUAC": "NOT RUN", "signed": False, "networkChangedByBuild": False}
    (stage / "build-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    target.with_suffix(".sha256").write_text(report["setupSHA256"] + "  " + target.name + "\n", encoding="ascii")
    print(json.dumps({k: v for k, v in report.items() if k != "sources"}, indent=2))


if __name__ == "__main__":
    main()
