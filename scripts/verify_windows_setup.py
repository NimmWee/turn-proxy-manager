"""Verify local setup/source artifacts without executing an installer."""
import hashlib
import argparse
import json
from pathlib import Path
import re
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    source = root / "clients/windows/installer"
    lock = json.loads((source / "toolchain.lock.json").read_text(encoding="utf-8"))
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version",default=lock["payloadVersion"])
    parser.add_argument("--archive-only",action="store_true",help="Historical frozen sources, without comparing the latest working tree")
    args=parser.parse_args()
    version=args.version
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",version):parser.error("Invalid version")
    artifacts = root / "clients/windows/artifacts"
    report = json.loads((root / f".local-cache/windows-setup/{version}/build-report.json").read_text(encoding="utf-8"))
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    setup = artifacts / f"FreeTurn-Setup-{version}-preview-win-x64.exe"
    assert setup.read_bytes()[:2] == b"MZ" and digest(setup.read_bytes()) == report["setupSHA256"]
    assert setup.with_suffix(".sha256").read_text(encoding="ascii").split()[0] == report["setupSHA256"]
    frozen = artifacts / f"FreeTurn-Windows-{version}-preview-win-x64.zip"
    assert digest(frozen.read_bytes()) == report["payloadSHA256"]
    if version==lock["payloadVersion"]:assert report["payloadSHA256"]==lock["payloadZIP_SHA256"]
    bundle = artifacts / f"FreeTurn-Setup-{version}-Sources.zip"
    assert digest(bundle.read_bytes()) == report["setupSourcesSHA256"]
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == set(report["sources"]) | {"LICENSE"}
        for name, expected in report["sources"].items():
            path = source / name
            assert path.resolve().is_relative_to(source.resolve())
            assert digest(archive.read(name))==expected,name
            if not args.archive_only:assert digest(path.read_bytes())==expected,name
    print(json.dumps({"setupHash": "PASS", "sourceArchiveCorrespondence": "PASS", "sourceFiles": len(report["sources"]),
                      "version":version,"currentSourcesCompared":not args.archive_only,"frozenPayloadUnchanged": True, "signed": False, "installUpgradeUninstallUAC": "NOT RUN",
                      "setupExecuted": False}, indent=2))


if __name__ == "__main__":
    main()
