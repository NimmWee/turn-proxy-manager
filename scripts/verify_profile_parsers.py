"""Offline round-trip through the actual pinned Go share parser, on the build PC."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ftm.legacy import baseline_module
from ftm.profile_codec import decode, encode, json_schema
from tests.fixtures import legacy_state

GO_TEST = '''package uri

import (
    "encoding/json"
    "os"
    "reflect"
    "testing"
)

func TestFTMProfiles(t *testing.T) {
    raw, err := os.ReadFile(os.Getenv("FTM_COMPAT_INPUT"))
    if err != nil { t.Fatal("fixture input unavailable") }
    var links []string
    if json.Unmarshal(raw, &links) != nil { t.Fatal("invalid fixture envelope") }
    output := make([]string, 0, len(links))
    for _, link := range links {
        parsed, err := Parse(link)
        if err != nil { t.Fatal("pinned parser rejected an FTM profile") }
        encoded := parsed.String()
        again, err := Parse(encoded)
        if err != nil || !reflect.DeepEqual(parsed, again) { t.Fatal("pinned parser round-trip changed fields") }
        output = append(output, encoded)
    }
    data, err := json.Marshal(output)
    if err != nil { t.Fatal("fixture result unavailable") }
    if os.WriteFile(os.Getenv("FTM_COMPAT_OUTPUT"), data, 0600) != nil { t.Fatal("fixture output unavailable") }
}
'''


def source(repo, pin):
    if not re.fullmatch(r"[a-f0-9]{40}", pin["commit"]):
        raise ValueError("Invalid source pin")
    result = subprocess.run(["git", "-C", str(repo), "show", pin["commit"] + ":" + pin["path"]],
                            capture_output=True, timeout=20)
    if result.returncode or hashlib.sha256(result.stdout).hexdigest() != pin["sha256"]:
        raise ValueError("Pinned parser source unavailable or changed")
    return result.stdout


def verify(core_repo, android_repo):
    lock = json.loads((ROOT / "profile-formats.lock.json").read_text())
    upstreams = {item["name"]: item["commit"] for item in json.loads((ROOT / "upstreams.lock.json").read_text())["repositories"]}
    if any(lock[name]["commit"] != upstreams[name] for name in ("core", "android")):
        raise ValueError("Parser pins differ from the audited upstreams")
    core = source(core_repo, lock["core"])
    source(android_repo, lock["android"])
    if json.loads((ROOT / "schemas/freeturn-link-v1.schema.json").read_text(encoding="utf-8")) != json_schema():
        raise ValueError("Exported JSON Schema differs from codec definitions")
    compiler = shutil.which("go")
    if compiler is None:
        raise ValueError("Go compiler unavailable; actual parser execution NOT RUN")
    payload = decode(baseline_module().profile_links(legacy_state())["android"])
    unicode_profile = dict(payload, name="Семейный сервер ✦", n=1, spc=1)
    kcp_profile = dict(payload, kcp={"nodelay": 1, "interval": 20, "resend": 2, "nc": 1,
                                     "sndwnd": 1024, "rcvwnd": 1024, "mtu": 1280, "acknodelay": True})
    profiles = [payload, unicode_profile, kcp_profile]
    with tempfile.TemporaryDirectory(prefix="ftm-profile-compat-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        (root / "uri.go").write_bytes(core)
        (root / "uri_ftm_test.go").write_text(GO_TEST)
        (root / "go.mod").write_text("module ftm-profile-compat\n\ngo 1.23.0\n")
        # Keep the upstream license beside the unchanged source, even here.
        license_file = subprocess.run(["git", "-C", str(core_repo), "show", lock["core"]["commit"] + ":LICENSE"],
                                      capture_output=True, timeout=20)
        if license_file.returncode:
            raise ValueError("Pinned upstream license unavailable")
        (root / "LICENSE").write_bytes(license_file.stdout)
        input_file, output_file = root / "input.json", root / "output.json"
        input_file.write_text(json.dumps([encode(value) for value in profiles]))
        input_file.chmod(0o600)
        env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOPROXY="off", GO111MODULE="on",
                   FTM_COMPAT_INPUT=str(input_file), FTM_COMPAT_OUTPUT=str(output_file))
        result = subprocess.run([compiler, "test", "-count=1", "./..."], cwd=root, env=env,
                                capture_output=True, timeout=150)
        if result.returncode:
            raise ValueError("Actual pinned Go parser round-trip failed; fixture data withheld")
        links = json.loads(output_file.read_bytes())
        if len(links) != len(profiles) or any(decode(link) != expected for link, expected in zip(links, profiles)):
            raise ValueError("Python/Go profile fields differ")
    version = subprocess.run([compiler, "version"], capture_output=True, text=True, timeout=10).stdout.strip()
    return {"result": "PASS", "actual_pinned_go_parser": True, "synthetic_profile_roundtrips": len(profiles),
            "wireguard_cid_vk_obfuscation_fields_preserved": True, "json_schema_matches_codec": True,
            "android_source_sha256_verified": True, "android_parser_runtime_tested": False,
            "vpn_e2e_tested": False, "compiler": version, "dependency_downloads": False,
            "core_commit": lock["core"]["commit"], "android_commit": lock["android"]["commit"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-repo", type=Path, default=ROOT / ".references/core")
    parser.add_argument("--android-repo", type=Path, default=ROOT / ".references/android")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.core_repo.absolute(), args.android_repo.absolute()), indent=2))
    except (ValueError, OSError, subprocess.TimeoutExpired):
        print("Profile parser verification failed or unavailable; fixture data withheld", file=sys.stderr)
        raise SystemExit(1)
