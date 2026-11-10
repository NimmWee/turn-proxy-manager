"""Real HTTPS auth and fail-closed public-enable rollback on the test VPS."""

import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, "/opt/ftm/current")
from ftm import https_edge
from ftm.agent import _atomic, _run
from ftm.installer import read_private_json
from ftm.legacy import baseline_module


def verify(checkpoint, digest):
    app = baseline_module()
    state = app.load_state("main")
    conf, directory = app.paths("main")
    protected = [conf / name for name in ("wireguard.conf", "clients.json", "obf.key")]
    protected += [directory / "state.json", directory / "profiles/iphone-import.txt", Path("/var/lib/ftm-agent/managed.json")]
    before = {path: path.read_bytes() for path in protected}
    pids = {name: _run(["systemctl", "show", name, "-p", "MainPID", "--value"]) for name in ("vps-vk", "ssh")}
    paths = [Path("/etc/ftm") / name for name in ("web.json", "https.json", "Caddyfile")]
    paths += [Path("/root/ftm-web-login.json")]
    private = {path: path.read_bytes() for path in paths}
    if read_private_json(paths[0])["version"] != 1:
        raise RuntimeError("This scenario starts from the verified private panel")
    original_wait = https_edge.wait_ready
    failed = False

    def fail_once(host, *, tls):
        nonlocal failed
        if tls and not failed:
            failed = True
            raise RuntimeError("Injected post-write TLS readiness failure")
        return original_wait(host, tls=tls)

    with patch.object(https_edge, "wait_ready", side_effect=fail_once):
        try:
            https_edge.enable(checkpoint, digest)
        except RuntimeError as error:
            if str(error) != "HTTPS enable failed; previous private configuration recovered":
                raise
        else:
            raise RuntimeError("Enable failure injection was not observed")
    if not failed or any(path.read_bytes() != raw for path, raw in private.items()):
        raise RuntimeError("Enable rollback changed the private identity")
    try:
        result = https_edge.enable(checkpoint, digest)
        note = read_private_json("/root/ftm-web-login.json")
        origin = "https://" + state["endpoint"]
        base = origin + note["panel_path"] + "api"
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

        def call(path, *, body=None, headers=None, expected=200):
            request = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                             headers={"Content-Type": "application/json", **(headers or {})})
            try:
                response = opener.open(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            if response.status != expected:
                raise RuntimeError("HTTPS auth scenario returned an unexpected status")
            raw = response.read()
            return response, json.loads(raw) if raw else None

        call("/status", expected=401)
        payload = {"username": note["username"], "password": note["password"]}
        call("/auth/login", body=payload, headers={"Origin": "http://" + state["endpoint"]}, expected=403)
        response, login = call("/auth/login", body=payload, headers={"Origin": origin})
        cookie = response.headers.get("Set-Cookie", "")
        if not all(value in cookie for value in ("Secure", "HttpOnly", "SameSite=strict")):
            raise RuntimeError("HTTPS session cookie flags are incomplete")
        call("/users")
        call("/users", body={"name": "Must not be created"}, headers={"Origin": origin}, expected=403)
        call("/users", body={"name": "Must not be created"},
             headers={"Origin": "https://untrusted.example", "X-CSRF-Token": login["csrf"]}, expected=403)
        call("/auth/logout", body={}, headers={"Origin": origin, "X-CSRF-Token": login["csrf"]})
        call("/users", expected=401)
        repeat = https_edge.enable(checkpoint, digest)
        if repeat["changed"]:
            raise RuntimeError("Repeated enable unnecessarily restarted the API")
        logs = _run(["journalctl", "-u", "ftm-caddy", "-u", "ftm-api", "--since", "10 minutes ago", "--no-pager", "-o", "cat"])
        if note["password"] in logs or note["panel_path"].rstrip("/") in logs:
            raise RuntimeError("Public edge logged a credential or secret route")
        if any(path.read_bytes() != raw for path, raw in before.items()):
            raise RuntimeError("Public enable changed the working VPN identity")
        if any(_run(["systemctl", "show", name, "-p", "MainPID", "--value"]) != pid for name, pid in pids.items()):
            raise RuntimeError("Public enable restarted VPN or SSH")
    except BaseException:
        _run(["systemctl", "stop", "ftm-caddy", "ftm-api"])
        for path, raw in private.items():
            _atomic(path, raw)
        _run(["systemctl", "reset-failed", "ftm-api", "ftm-caddy"])
        _run(["systemctl", "start", "ftm-api"])
        original_wait(state["endpoint"], tls=False)
        _run(["systemctl", "start", "ftm-caddy"])
        original_wait(state["endpoint"], tls=True)
        raise
    return {"result": "PASS", "enable_post_write_rollback": True, "real_https_login_logout": True,
            "secure_httponly_strict_cookie": True, "csrf_and_http_foreign_origin_rejected": True,
            "secret_path_and_password_not_in_service_logs": True, "repeat_enable_no_restart": True,
            "vpn_profile_and_vpn_ssh_pids_unchanged": True, "public_api_enabled": result["public_api_enabled"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--offsite-sha256", required=True)
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify(args.checkpoint, args.offsite_sha256)
        report = Path("/root/ftm-https-enable-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception as error:
        print("HTTPS scenario failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
