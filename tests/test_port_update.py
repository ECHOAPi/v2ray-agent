"""Exercise real updater staging and shared locks; all downloads/backends are inert.

Synthetic policy time proves renewal semantics, not actual nft packet forwarding.
"""
import datetime as dt
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest

from test_port_installer import function
from test_port_policies import FakeRunner
from port_manager import __main__ as cli
from port_manager.core import Manager
from port_manager.policies import PolicyManager


REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")
OLD_REVISION = "a" * 40
NEW_REVISION = "b" * 40
OTHER_REVISION = "c" * 40
MODULES = ("__init__.py", "__main__.py", "core.py", "subscriptions.py", "policies.py", "rate_limits.py")
HELPERS = ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "agentPreparationDigest",
           "agentPrepare", "portManagerPackageReady", "portManagerDownloadPackage",
           "portManagerActivatePackage", "portManagerInstallPackage", "agentDownloadScript", "updateV2RayAgent")


class UpdateTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = 0

    def cache(self, root, revision):
        package = root / "port-manager-lib" / revision
        (package / "port_manager").mkdir(parents=True)
        for name in MODULES:
            (package / "port_manager" / name).write_text("CACHED = True\n")
        (package / ".complete").touch()

    def fixture(self, rel, *, cached=False, installed=True):
        self.case += 1
        root = Path(self.temp.name) / str(self.case)
        (root / "bin").mkdir(parents=True)
        (root / "xray/conf").mkdir(parents=True)
        (root / "xray/conf/07_VLESS_vision_reality_inbounds.json").write_text(json.dumps({"inbounds": [{
            "tag": "reality", "protocol": "vless", "listen": "::", "port": 443,
            "settings": {"clients": [{"id": "test-account", "email": "alice"}]},
            "streamSettings": {"security": "reality", "network": "tcp"},
        }]}))
        script = f'#!/usr/bin/env bash\nPORT_MANAGER_REVISION="{OLD_REVISION}"\necho old\n'
        if installed:
            (root / "install.sh").write_text(script)
            (root / "install.sh").chmod(0o700)
            self.cache(root, OLD_REVISION)
            (root / "port-manager-lib/current").symlink_to(OLD_REVISION)
        if cached:
            self.cache(root, NEW_REVISION)
        source = (REPO / rel).read_text()
        helpers = "\n".join(function(source, name) for name in HELPERS)
        helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
        (root / "helpers.sh").write_text(helpers)
        (root / "downloaded-script").write_text(
            f'#!/usr/bin/env bash\nPORT_MANAGER_REVISION="{NEW_REVISION}"\necho updated\n')
        curl = root / "bin/curl"
        curl.write_text('''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["UPDATE_TEST_ROOT"])
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith("https://"))
destination = Path(args[args.index("-o") + 1])
stage = "script" if "/master/" in url else url.rsplit("/", 1)[1]
try:
    os.fstat(9)
    fd_closed = False
except OSError:
    fd_closed = True
with (root / "downloads.jsonl").open("a") as stream:
    stream.write(json.dumps({"stage": stage, "url": url, "fd_closed": fd_closed}) + "\\n")
if not fd_closed:
    sys.exit(91)
if stage == os.environ.get("UPDATE_PAUSE_STAGE"):
    (root / "download-paused").write_text(stage)
    if not sys.stdin.readline():
        sys.exit(92)
if stage == os.environ.get("UPDATE_FAIL_STAGE"):
    destination.write_text("incomplete download\\n")
    sys.exit(22)
destination.write_bytes((root / "downloaded-script").read_bytes() if stage == "script"
                       else ("MODULE = " + repr(stage) + "\\n").encode())
''')
        curl.chmod(0o700)
        systemctl = root / "bin/systemctl"
        systemctl.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >>"$UPDATE_TEST_ROOT/systemctl.calls"\n')
        systemctl.chmod(0o700)
        return root, script

    def start(self, root, *, pause="", fail="", operation="updateV2RayAgent", setup=""):
        environment = dict(os.environ, UPDATE_TEST_ROOT=str(root), UPDATE_PAUSE_STAGE=pause,
                           UPDATE_FAIL_STAGE=fail, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"])
        script = 'echoContent() { printf "%s\\n" "$2"; }\n'
        script += '. ' + shlex.quote(str(root / "helpers.sh")) + '\n' + setup
        script += '\nagentWriteLock || exit 1\n' + operation
        proc = subprocess.Popen(["bash", "-c", script], env=environment, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def cleanup():
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)

        self.addCleanup(cleanup)
        if pause:
            deadline = time.monotonic() + 5
            while not (root / "download-paused").exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not (root / "download-paused").exists():
                out, err = proc.communicate(timeout=5)
                self.fail(f"Download did not reach {pause}: {out} {err}")
            self.assertIsNone(proc.poll(), "download must remain paused")
        return proc

    def finish(self, proc, expected):
        out, err = proc.communicate("continue\n", timeout=10)
        self.assertEqual(proc.returncode, expected, out + err)
        return out, err

    def assert_no_staging(self, root):
        self.assertEqual(list(root.glob(".install.*")), [])
        self.assertEqual(list(root.glob(".install-backup.*")), [])
        self.assertEqual(list((root / "port-manager-lib").glob(".candidate.*")), [])
        self.assertEqual(list((root / "port-manager-lib").glob(".link.*")), [])

    def downloads(self, root):
        path = root / "downloads.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_policy_renews_through_paused_script_and_package_downloads(self):
        for rel in INSTALLERS:
            for stage in ("script", "core.py"):
                with self.subTest(rel=rel, stage=stage):
                    root, old_script = self.fixture(rel)
                    runner = FakeRunner()
                    now = [dt.datetime(2026, 9, 8, 1, tzinfo=dt.timezone.utc)]
                    policies = PolicyManager(root, runner, clock=lambda: now[0])
                    self.addCleanup(policies.close)
                    manager = Manager(root, runner=runner, policies=policies)
                    entries = manager.list()
                    self.assertEqual(len(entries), 1)
                    with cli.shared_lock(root, timeout=1):
                        policies.batch_update(entries, {"quota_bytes": 1000})
                    original_lease = policies._meta("lease_until")
                    app = cli.Application(manager, policies=policies, output=io.StringIO())
                    proc = self.start(root, pause=stage)
                    for second in (11, 22, 33):
                        with cli.shared_lock(root, timeout=1):
                            pass
                        now[0] = dt.datetime(2026, 9, 8, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=second)
                        runner.add_usage(entries[0]["port_id"], 10, 15)
                        result = cli.reconcile_once(app)
                        self.assertEqual(result["recovery"], [])
                        state = policies.status(entries)[0]
                        self.assertTrue(state["available"], state)
                        self.assertNotIn("daemon_lease_elapsed", state["reasons"])
                    self.assertLess(original_lease, now[0].timestamp())
                    self.assertGreater(policies._meta("lease_until"), now[0].timestamp())
                    self.assertEqual(state["used_bytes"], 75)
                    self.assertIsNone(proc.poll())
                    self.assertEqual((root / "install.sh").read_text(), old_script)
                    self.assertEqual(os.readlink(root / "port-manager-lib/current"), OLD_REVISION)
                    self.finish(proc, 0)
                    self.assertTrue(all(row["fd_closed"] for row in self.downloads(root)))
                    self.assertEqual(os.readlink(root / "port-manager-lib/current"), NEW_REVISION)
                    self.assert_no_staging(root)

    def test_slow_download_failure_preserves_script_and_active_module(self):
        for rel in INSTALLERS:
            for stage in ("script", "core.py"):
                with self.subTest(rel=rel, stage=stage):
                    root, old_script = self.fixture(rel)
                    proc = self.start(root, pause=stage, fail=stage)
                    with cli.shared_lock(root, timeout=1):
                        pass
                    self.finish(proc, 1)
                    self.assertEqual((root / "install.sh").read_text(), old_script)
                    self.assertEqual(os.readlink(root / "port-manager-lib/current"), OLD_REVISION)
                    self.assertFalse((root / "port-manager-lib" / NEW_REVISION).exists())
                    self.assertFalse((root / "systemctl.calls").exists())
                    self.assert_no_staging(root)

    def test_concurrent_configuration_script_or_pointer_change_rejects_preparation(self):
        for rel in INSTALLERS:
            for stage in ("script", "core.py"):
                for changed in ("configuration", "script", "pointer"):
                    with self.subTest(rel=rel, stage=stage, changed=changed):
                        root, old_script = self.fixture(rel)
                        proc = self.start(root, pause=stage)
                        with cli.shared_lock(root, timeout=1):
                            if changed == "configuration":
                                target = root / "xray/conf/07_VLESS_vision_reality_inbounds.json"
                                content = json.loads(target.read_text())
                                content["inbounds"][0]["port"] = 8443
                                target.write_text(json.dumps(content))
                            elif changed == "script":
                                (root / "install.sh").write_text("# concurrent installer update\n")
                            else:
                                self.cache(root, OTHER_REVISION)
                                replacement = root / "port-manager-lib/concurrent-pointer"
                                replacement.symlink_to(OTHER_REVISION)
                                replacement.replace(root / "port-manager-lib/current")
                        _, err = self.finish(proc, 1)
                        self.assertIn("changed during preparation", err)
                        expected_script = "# concurrent installer update\n" if changed == "script" else old_script
                        self.assertEqual((root / "install.sh").read_text(), expected_script)
                        expected_pointer = OTHER_REVISION if changed == "pointer" else OLD_REVISION
                        self.assertEqual(os.readlink(root / "port-manager-lib/current"), expected_pointer)
                        if changed == "configuration":
                            self.assertEqual(json.loads(target.read_text())["inbounds"][0]["port"], 8443)
                        self.assertFalse((root / "port-manager-lib" / NEW_REVISION).exists())
                        self.assertFalse((root / "systemctl.calls").exists())
                        self.assert_no_staging(root)

    def test_successful_update_with_cached_or_downloaded_package(self):
        for rel in INSTALLERS:
            for cached in (False, True):
                with self.subTest(rel=rel, cached=cached):
                    root, old_script = self.fixture(rel, cached=cached)
                    proc = self.start(root)
                    self.finish(proc, 0)
                    self.assertEqual((root / "install.sh").read_bytes(), (root / "downloaded-script").read_bytes())
                    self.assertEqual((root / "install.sh.previous").read_text(), old_script)
                    self.assertEqual((root / "install.sh").stat().st_mode & 0o777, 0o700)
                    self.assertEqual(os.readlink(root / "port-manager-lib/current"), NEW_REVISION)
                    self.assertTrue((root / "port-manager-lib" / NEW_REVISION / ".complete").exists())
                    calls = self.downloads(root)
                    self.assertEqual([call["stage"] for call in calls], ["script"] + ([] if cached else list(MODULES)))
                    self.assertTrue(all(call["fd_closed"] for call in calls))
                    requested = "shell/install_en.sh" if rel.startswith("shell/") else "install.sh"
                    self.assertTrue(calls[0]["url"].endswith("/master/" + requested))
                    self.assertEqual((root / "systemctl.calls").read_text(),
                                     "try-restart --no-block v2ray-agent-port-policy.service\n")
                    self.assert_no_staging(root)

    def test_final_script_publication_failure_restores_module_pointer(self):
        for rel in INSTALLERS:
            for installed in (False, True):
                with self.subTest(rel=rel, installed=installed):
                    root, old_script = self.fixture(rel, cached=True, installed=installed)
                    target = shlex.quote(str(root / "install.sh"))
                    setup = '''mv() {
    if [[ "${@: -1}" == TARGET ]]; then
        readlink "$UPDATE_TEST_ROOT/port-manager-lib/current" >"$UPDATE_TEST_ROOT/pointer-at-script-publish"
        if flock -n "$UPDATE_TEST_ROOT/.write.lock" true; then
            printf "UNLOCKED_COMMIT\\n" >&2
        fi
        return 73
    fi
    command mv "$@"
}
'''.replace("TARGET", target)
                    proc = self.start(root, setup=setup)
                    _, err = self.finish(proc, 1)
                    self.assertNotIn("UNLOCKED_COMMIT", err)
                    self.assertEqual((root / "pointer-at-script-publish").read_text().strip(), NEW_REVISION)
                    if installed:
                        self.assertEqual((root / "install.sh").read_text(), old_script)
                        self.assertEqual((root / "install.sh.previous").read_text(), old_script)
                        self.assertEqual(os.readlink(root / "port-manager-lib/current"), OLD_REVISION)
                    else:
                        self.assertFalse((root / "install.sh").exists())
                        self.assertFalse((root / "port-manager-lib/current").is_symlink())
                    self.assertFalse((root / "systemctl.calls").exists())
                    self.assert_no_staging(root)

    def test_first_package_bootstrap_releases_lock_during_download(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                root, _ = self.fixture(rel, installed=False)
                proc = self.start(root, pause="core.py", operation=f"portManagerInstallPackage {NEW_REVISION}")
                with cli.shared_lock(root, timeout=1):
                    pass
                self.assertFalse((root / "port-manager-lib/current").is_symlink())
                self.finish(proc, 0)
                self.assertEqual(os.readlink(root / "port-manager-lib/current"), NEW_REVISION)
                self.assertEqual([row["stage"] for row in self.downloads(root)], list(MODULES))
                self.assertTrue(all(row["fd_closed"] for row in self.downloads(root)))
                self.assert_no_staging(root)

    def test_first_package_bootstrap_failure_never_activates_partial_cache(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                root, _ = self.fixture(rel, installed=False)
                proc = self.start(root, pause="core.py", fail="core.py",
                                  operation=f"portManagerInstallPackage {NEW_REVISION}")
                with cli.shared_lock(root, timeout=1):
                    pass
                self.finish(proc, 1)
                self.assertFalse((root / "port-manager-lib/current").is_symlink())
                self.assertFalse((root / "port-manager-lib" / NEW_REVISION).exists())
                self.assertEqual(list((root / "port-manager-lib").rglob(".complete")), [])
                self.assert_no_staging(root)

    def test_package_cache_hit_does_not_download(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                root, _ = self.fixture(rel, cached=True)
                proc = self.start(root, operation=f"portManagerInstallPackage {NEW_REVISION}")
                self.finish(proc, 0)
                self.assertEqual(self.downloads(root), [])
                self.assertEqual(os.readlink(root / "port-manager-lib/current"), NEW_REVISION)
                self.assert_no_staging(root)

    def test_invalid_downloaded_script_or_revision_preserves_installation(self):
        for rel in INSTALLERS:
            for content in ("if then invalid syntax\n", '#!/bin/bash\nPORT_MANAGER_REVISION="invalid"\n'):
                with self.subTest(rel=rel, content=content):
                    root, old_script = self.fixture(rel)
                    (root / "downloaded-script").write_text(content)
                    proc = self.start(root)
                    self.finish(proc, 1)
                    self.assertEqual((root / "install.sh").read_text(), old_script)
                    self.assertEqual(os.readlink(root / "port-manager-lib/current"), OLD_REVISION)
                    self.assertEqual([row["stage"] for row in self.downloads(root)], ["script"])
                    self.assert_no_staging(root)


if __name__ == "__main__":
    unittest.main()
