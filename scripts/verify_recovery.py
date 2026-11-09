"""Disruptive recovery/rollback test for the explicitly authorized test VPS only."""

import argparse
import contextlib
import datetime
import fcntl
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ftm.legacy import baseline_module
from ftm.ssh_protection import configure
from ftm.baseline_deploy import check_baseline_only
from scripts.verify_baseline import verify_baseline


def verify():
    verify_baseline(ROOT)
    check_baseline_only()
    app = baseline_module()
    conf, state_dir = app.paths("main")
    if conf.resolve() != Path("/etc/vps-vk/main") or state_dir.resolve() != Path("/var/lib/vps-vk/main"):
        raise ValueError("Unexpected baseline paths")
    original = app.load_state("main")
    secret = Path("/root/ftm-test-backup.pass").read_text().strip()
    recovered = app.parse_backup(app.decrypt_backup(Path("/root/ftm-test.vkbackup").read_bytes(), secret))
    del secret
    if recovered != original:
        raise ValueError("Backup differs from active state; refusing disruptive test")
    app.check_keypairs(recovered)
    ssh_before = app.run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]).stdout.strip()
    profiles_before = app.profile_links(original)
    original_obf = (conf / "obf.key").read_bytes()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    checkpoint = Path("/root") / ("ftm-recovery-" + stamp)
    checkpoint.mkdir(mode=0o700)
    args = argparse.Namespace(instance="main", endpoint=original["endpoint"],
                              port=original["port"], backend_port=original["backend_port"],
                              subnet=original["subnet"], adopt_legacy=False, vk_link_file=None,
                              bundle=str(ROOT / "vendor/vps"), qr=True)
    previous_hook = app.configure_fail2ban
    previous_units = app.render_units
    app.configure_fail2ban = configure
    detached = False
    with Path("/run/lock/vps-vk.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            check_baseline_only()
            app.run(["systemctl", "stop", *app.units(original)])
            conf.rename(checkpoint / "original-conf")
            detached = True
            state_dir.rename(checkpoint / "original-state")
            with contextlib.redirect_stdout(io.StringIO()):
                app.install(args, restored=recovered)
            if app.load_state("main") != original or app.profile_links(app.load_state("main")) != profiles_before:
                raise RuntimeError("Restore changed issued profiles")
            with contextlib.redirect_stdout(io.StringIO()):
                if app.status(app.load_state("main")) != 0:
                    raise RuntimeError("Restored VPN health failed")

            def fail_after_config(state):
                app.atomic_write(conf / "obf.key", "b" * 64 + "\n", 0o640)
                raise RuntimeError("FTM_INJECTED_AFTER_CONFIG")

            app.render_units = fail_after_config
            injected = False
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    app.install(args)
            except RuntimeError as error:
                if str(error) != "FTM_INJECTED_AFTER_CONFIG":
                    raise
                injected = True
            finally:
                app.render_units = previous_units
            if not injected or (conf / "obf.key").read_bytes() != original_obf:
                raise RuntimeError("Rollback did not restore configuration")
            if app.load_state("main") != original or app.profile_links(app.load_state("main")) != profiles_before:
                raise RuntimeError("Rollback changed issued profiles")
            with contextlib.redirect_stdout(io.StringIO()):
                if app.status(app.load_state("main")) != 0:
                    raise RuntimeError("Rollback health failed")
            if app.run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]).stdout.strip() != ssh_before:
                raise RuntimeError("SSH process changed")
            return {"result": "PASS", "restore_with_absent_state": True,
                    "same_host_restore": True, "second_clean_host_tested": False,
                    "keys_and_issued_profiles_unchanged": True, "injected_failure_rolled_back": True,
                    "vpn_healthy_after_rollback": True, "ssh_pid_unchanged": True,
                    "checkpoint": str(checkpoint), "iphone_reconnect_after_test": "not_yet_observed"}
        except BaseException:
            # Emergency path uses our exact, detached baseline directories; no recursive deletion.
            app.render_units = previous_units
            if detached:
                app.run(["systemctl", "stop", *app.units(original)], check=False)
                for path, name in [(conf, "conf"), (state_dir, "state")]:
                    old = checkpoint / ("original-" + name)
                    if old.exists():
                        if path.exists():
                            path.rename(checkpoint / ("failed-" + name))
                        old.rename(path)
                app.render_config(original)
                app.render_units(original)
                app.run(["systemctl", "daemon-reload"])
                app.run(["systemctl", "start", app.units(original)[0]])
            raise
        finally:
            app.configure_fail2ban = previous_hook
            app.render_units = previous_units


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    options = parser.parse_args()
    if not options.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires explicit --test-vps-apply and root; interrupts the test VPN")
    try:
        print(json.dumps(verify(), indent=2))
    except BaseException as error:
        print("Recovery verification failed: " + type(error).__name__ + "; details withheld", file=sys.stderr)
        raise SystemExit(1)
