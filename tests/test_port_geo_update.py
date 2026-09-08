"""Geo preparation/compensation using real Bash and locks, synthetic assets/services."""
import datetime as dt
import io
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import unittest

import test_port_update as update_fixture
from test_port_installer import function
from test_port_policies import FakeRunner
from port_manager import __main__ as cli
from port_manager.core import Manager
from port_manager.policies import PolicyManager

REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")
HELPERS = ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "agentPreparationDigest",
           "agentPrepare", "agentGeoDigest", "agentGeoRecoveryClear", "agentDownloadGeo",
           "agentPublishGeo", "updateGeoSite")


class GeoUpdateTests(unittest.TestCase):
    def setUp(self):
        # Reuse the inert installed-node fixture, not its TestCase discovery.
        self.fixture_owner = update_fixture.UpdateTests()
        self.fixture_owner.setUp()
        self.addCleanup(self.register_fixture_cleanup)

    def register_fixture_cleanup(self):
        # Report cleanup errors on this case instead of swallowing them in an
        # unrun helper TestCase. Preserve LIFO process-before-directory cleanup.
        for callback, args, kwargs in self.fixture_owner._cleanups:
            self.addCleanup(callback, *args, **kwargs)
        self.fixture_owner._cleanups.clear()

    def fixture(self, rel):
        root, _ = self.fixture_owner.fixture(rel)
        source = (REPO / rel).read_text()
        helpers = "\n".join(function(source, name) for name in HELPERS)
        helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
        (root / "helpers.sh").write_text(helpers)
        for name in ("geosite.dat", "geoip.dat"):
            (root / "xray" / name).write_text("old-" + name)
            (root / "xray" / name).chmod(0o640)
        (root / "xray/geo-custom.dat").write_text("unrelated asset")
        curl = root / "bin/curl"
        curl.write_text('''#!/usr/bin/env python3
import hashlib, json, os, sys
from pathlib import Path
root = Path(os.environ["UPDATE_TEST_ROOT"])
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith("https://"))
destination = Path(args[args.index("-o") + 1])
stage = url.rsplit("/", 1)[1]
try:
    os.fstat(9)
    closed = False
except OSError:
    closed = True
with (root / "downloads.jsonl").open("a") as out:
    out.write(json.dumps({"stage": stage, "url": url, "fd_closed": closed,
                         "mode": destination.parent.stat().st_mode & 0o777}) + "\\n")
if not closed:
    sys.exit(91)
if stage == os.environ.get("UPDATE_PAUSE_STAGE"):
    (root / "download-paused").write_text(stage)
    if not sys.stdin.readline():
        sys.exit(92)
if stage == os.environ.get("UPDATE_FAIL_STAGE"):
    destination.write_text("partial")
    sys.exit(22)
if stage == "latest":
    destination.write_text(os.environ.get("GEO_RELEASE", '{"tag_name":"202609080001"}'))
elif stage.endswith(".sha256sum"):
    name = stage.removesuffix(".sha256sum")
    digest = hashlib.sha256(("new-" + name).encode()).hexdigest()
    data = digest + "  " + name + "\\n"
    mode = os.environ.get("GEO_CHECKSUM", "")
    if mode == "wrong":
        data = "0" * 64 + "  " + name
    elif mode == "traversal":
        data = digest + "  ../" + name
    elif mode == "multiline":
        data += digest + "  another-file\\n"
    elif mode == "malformed":
        data = "not a checksum"
    destination.write_text(data)
else:
    destination.write_text("" if os.environ.get("GEO_EMPTY") else "new-" + stage)
''')
        curl.chmod(0o700)
        xray = root / "xray/xray"
        xray.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["UPDATE_TEST_ROOT"])
args = sys.argv[1:]
stage = "check" if "-config" in args else "config"
assets = Path(os.environ["xray.location.asset"])
assert str(assets) == os.environ["XRAY_LOCATION_ASSET"]
assert assets.name.startswith(".geo-update.")
assert (assets / "geosite.dat").read_text() == "new-geosite.dat"
assert (assets / "geoip.dat").read_text() == "new-geoip.dat"
assert args[:2] == ["run", "-test"]
try:
    os.fstat(9)
    sys.exit(91)
except OSError:
    pass
if stage == "check":
    config = json.loads((assets / "check.json").read_text())
    assert len(config["routing"]["rules"]) == 2
else:
    assert args[-1] == str(root / "xray/conf")
with (root / "validation.calls").open("a") as out:
    out.write(stage + "\\n")
if stage == os.environ.get("UPDATE_PAUSE_STAGE"):
    (root / "download-paused").write_text(stage)
    if not sys.stdin.readline():
        sys.exit(92)
sys.exit(1 if stage == os.environ.get("GEO_INVALID_TEST") else 0)
''')
        xray.chmod(0o700)
        systemctl = root / "bin/systemctl"
        systemctl.write_text('''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ["UPDATE_TEST_ROOT"])
args = sys.argv[1:]
try:
    os.fstat(9)
    sys.exit(91)
except OSError:
    pass
with (root / "systemctl.calls").open("a") as out:
    out.write(json.dumps(args) + "\\n")
if args == ["restart", "xray"]:
    if os.environ.get("GEO_HANG_RESTART"):
        time.sleep(60)
    sys.exit(1 if os.environ.get("GEO_FAIL_RESTART") else 0)
if args == ["is-active", "--quiet", "xray"]:
    sys.exit(1 if os.environ.get("GEO_INACTIVE") else 0)
if args == ["--no-block", "restart", "xray"]:
    sys.exit(0)
sys.exit(92)
''')
        systemctl.chmod(0o700)
        mv = root / "bin/mv"
        mv.write_text('''#!/usr/bin/env python3
import os, signal, sys
from pathlib import Path
name = Path(sys.argv[-2]).name
if name == "geoip.dat" and os.environ.get("GEO_MV_SIGNAL"):
    os.kill(os.getppid(), int(os.environ["GEO_MV_SIGNAL"]))
    sys.exit(1)
if name == "geoip.dat" and os.environ.get("GEO_FAIL_MV"):
    sys.exit(1)
if name.endswith(".restore") and os.environ.get("GEO_FAIL_RESTORE"):
    sys.exit(1)
os.execv("/bin/mv", ["mv"] + sys.argv[1:])
''')
        mv.chmod(0o700)
        return root

    def start(self, root, pause="", fail="", setup="", **variables):
        settings = f"release=ubuntu\nconfigPath={shlex.quote(str(root / 'xray/conf') + '/')}\n"
        settings += "\n".join(f"export {name}={shlex.quote(str(value))}" for name, value in variables.items())
        return self.fixture_owner.start(root, pause=pause, fail=fail, operation="updateGeoSite",
                                        setup=settings + "\n" + setup)

    def finish(self, proc, expected):
        return self.fixture_owner.finish(proc, expected)

    def assert_old(self, root, *, staging=False):
        for name in ("geosite.dat", "geoip.dat"):
            self.assertEqual((root / "xray" / name).read_text(), "old-" + name)
            self.assertEqual((root / "xray" / name).stat().st_mode & 0o777, 0o640)
        self.assertEqual((root / "xray/geo-custom.dat").read_text(), "unrelated asset")
        if not staging:
            self.assertEqual(list((root / "xray").glob(".geo-update.*")), [])

    def test_success_validates_both_assets_and_config_before_restarting_only_xray(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            self.finish(self.start(root), 0)
            for name in ("geosite.dat", "geoip.dat"):
                self.assertEqual((root / "xray" / name).read_text(), "new-" + name)
                self.assertEqual((root / "xray" / name).stat().st_mode & 0o777, 0o640)
            self.assertEqual((root / "validation.calls").read_text(), "check\nconfig\n")
            calls = [json.loads(line) for line in (root / "systemctl.calls").read_text().splitlines()]
            self.assertEqual(calls, [["restart", "xray"], ["is-active", "--quiet", "xray"]])
            self.assertEqual((root / "xray/geo-custom.dat").read_text(), "unrelated asset")
            self.assertEqual(list((root / "xray").glob(".geo-update.*")), [])
            for download in self.fixture_owner.downloads(root):
                self.assertTrue(download["fd_closed"])
                self.assertEqual(download["mode"], 0o700)

    def test_every_network_failure_preserves_old_assets_without_reload(self):
        for rel in INSTALLERS:
            for stage in ("latest", "geosite.dat", "geosite.dat.sha256sum", "geoip.dat", "geoip.dat.sha256sum"):
                with self.subTest(rel=rel, stage=stage):
                    root = self.fixture(rel)
                    out, _ = self.finish(self.start(root, fail=stage), 1)
                    self.assert_old(root)
                    self.assertFalse((root / "systemctl.calls").exists())
                    self.assertNotIn("restart checked", out)

    def test_bad_release_metadata_is_rejected(self):
        for rel in INSTALLERS:
            for value in ("{}", '{"tag_name":null}', '{"tag_name":"../escape"}', "not JSON"):
                root = self.fixture(rel)
                self.finish(self.start(root, GEO_RELEASE=value), 1)
                self.assert_old(root)
                self.assertFalse((root / "systemctl.calls").exists())

    def test_checksums_cannot_select_other_files_or_accept_corruption(self):
        for rel in INSTALLERS:
            for mode in ("wrong", "traversal", "multiline", "malformed"):
                root = self.fixture(rel)
                self.finish(self.start(root, GEO_CHECKSUM=mode), 1)
                self.assert_old(root)
                self.assertFalse((root / "validation.calls").exists())

    def test_empty_asset_or_core_validation_failure_preserves_old_files(self):
        for rel in INSTALLERS:
            for variables in ({"GEO_EMPTY": "1"}, {"GEO_INVALID_TEST": "check"}, {"GEO_INVALID_TEST": "config"}):
                root = self.fixture(rel)
                self.finish(self.start(root, **variables), 1)
                self.assert_old(root)
                self.assertFalse((root / "systemctl.calls").exists())

    def test_real_policy_reconciles_beyond_30_seconds_during_geo_preparation(self):
        for rel in INSTALLERS:
            for stage in ("geosite.dat", "config"):
                with self.subTest(rel=rel, stage=stage):
                    root = self.fixture(rel)
                    now = [dt.datetime(2026, 9, 8, 1, tzinfo=dt.timezone.utc)]
                    runner = FakeRunner()
                    policies = PolicyManager(root, runner, clock=lambda: now[0])
                    self.addCleanup(policies.close)
                    manager = Manager(root, runner=runner, policies=policies)
                    entries = manager.list()
                    with cli.shared_lock(root, timeout=1):
                        policies.batch_update(entries, {"quota_bytes": 1000})
                    original_lease = policies._meta("lease_until")
                    app = cli.Application(manager, policies=policies, output=io.StringIO())
                    proc = self.start(root, pause=stage)
                    self.assert_old(root, staging=True)
                    for second in (11, 22, 33):
                        with cli.shared_lock(root, timeout=1):
                            pass
                        now[0] = dt.datetime(2026, 9, 8, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=second)
                        runner.add_usage(entries[0]["port_id"], 10, 15)
                        self.assertEqual(cli.reconcile_once(app)["recovery"], [])
                        state = policies.status(entries)[0]
                        self.assertTrue(state["available"], state)
                        self.assertNotIn("daemon_lease_elapsed", state["reasons"])
                    self.assertLess(original_lease, now[0].timestamp())
                    self.assertGreater(policies._meta("lease_until"), now[0].timestamp())
                    self.assertEqual(state["used_bytes"], 75)
                    self.finish(proc, 0)

    def test_slow_download_failure_remains_unlocked_and_preserves_old_files(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            proc = self.start(root, pause="geoip.dat", fail="geoip.dat")
            with cli.shared_lock(root, timeout=1):
                pass
            self.assert_old(root, staging=True)
            self.finish(proc, 1)
            self.assert_old(root)
            self.assertFalse((root / "systemctl.calls").exists())

    def test_concurrent_config_geo_binary_or_script_change_rejects_stale_candidate(self):
        for rel in INSTALLERS:
            for path in ("xray/conf/other.json", "xray/geosite.dat", "xray/xray", "install.sh"):
                root = self.fixture(rel)
                proc = self.start(root, pause="geosite.dat")
                with cli.shared_lock(root, timeout=1):
                    target = root / path
                    target.write_text(target.read_text() + "\n# changed\n" if target.exists() else "{}")
                    changed = target.read_bytes()
                self.finish(proc, 1)
                self.assertEqual(target.read_bytes(), changed)
                self.assertEqual((root / "xray/geoip.dat").read_text(), "old-geoip.dat")
                self.assertFalse((root / "systemctl.calls").exists())
                self.assertEqual(list((root / "xray").glob(".geo-update.*")), [])

    def test_partial_publish_failure_restores_both_files(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            self.finish(self.start(root, GEO_FAIL_MV=1), 1)
            self.assert_old(root)

    def test_failed_or_inactive_service_restores_old_files_and_reports_failure(self):
        for rel in INSTALLERS:
            for variables in ({"GEO_FAIL_RESTART": 1}, {"GEO_INACTIVE": 1}):
                root = self.fixture(rel)
                out, err = self.finish(self.start(root, **variables), 1)
                self.assert_old(root)
                self.assertIn("verify Xray service status", err)
                self.assertNotIn("restart checked", out)

    def test_restart_timeout_is_bounded_and_restores_old_files(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            self.finish(self.start(root, GEO_HANG_RESTART=1), 1)
            self.assert_old(root)

    def test_backup_failure_does_not_publish_or_restart(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            self.finish(self.start(root, setup="cp() { return 1; }"), 1)
            self.assert_old(root)
            self.assertFalse((root / "systemctl.calls").exists())

    def test_restoration_failure_keeps_private_evidence_and_blocks_retry(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            _, err = self.finish(self.start(root, GEO_FAIL_MV=1, GEO_FAIL_RESTORE=1), 1)
            self.assertIn("recovery files retained", err)
            stages = list((root / "xray").glob(".geo-update.*"))
            self.assertEqual(len(stages), 1)
            self.assertEqual(stages[0].stat().st_mode & 0o777, 0o700)
            self.assertTrue((stages[0] / "KEEP_RECOVERY").is_file())
            self.assertEqual((stages[0] / "geosite.dat.previous").read_text(), "old-geosite.dat")
            calls = (root / "downloads.jsonl").read_text()
            self.finish(self.start(root), 1)
            self.assertEqual((root / "downloads.jsonl").read_text(), calls)

    def test_catchable_signals_during_publication_compensate(self):
        for rel in INSTALLERS:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                root = self.fixture(rel)
                self.finish(self.start(root, GEO_MV_SIGNAL=int(signum)), 1)
                self.assert_old(root)

    def test_sigkill_during_publication_leaves_recovery_marker(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            self.finish(self.start(root, GEO_MV_SIGNAL=int(signal.SIGKILL)), 1)
            stages = list((root / "xray").glob(".geo-update.*"))
            self.assertEqual(len(stages), 1)
            self.assertTrue((stages[0] / "KEEP_RECOVERY").is_file())
            self.finish(self.start(root), 1)

    def test_absent_old_file_is_not_invented_on_rollback(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            (root / "xray/geoip.dat").unlink()
            self.finish(self.start(root, GEO_FAIL_RESTART=1), 1)
            self.assertFalse((root / "xray/geoip.dat").exists())
            self.assertEqual((root / "xray/geosite.dat").read_text(), "old-geosite.dat")

    def test_unsupported_or_symlinked_inputs_do_not_start_download(self):
        for rel in INSTALLERS:
            for scenario in ("alpine", "path", "symlink"):
                root = self.fixture(rel)
                setup = "release=alpine" if scenario == "alpine" else ""
                if scenario == "path":
                    setup = "configPath=/some/other/path/"
                if scenario == "symlink":
                    (root / "xray/geoip.dat").unlink()
                    (root / "xray/geoip.dat").symlink_to(root / "xray/geo-custom.dat")
                self.finish(self.start(root, setup=setup), 1)
                self.assertFalse((root / "downloads.jsonl").exists())

    def test_cron_propagates_geo_failure_without_success_timestamp(self):
        for rel in INSTALLERS:
            root = self.fixture(rel)
            body = function((REPO / rel).read_text(), "cronFunction").replace("/etc/v2ray-agent", str(root))
            for code in (0, 1):
                log = root / "crontab_updateGeoSite.log"
                log.unlink(missing_ok=True)
                result = subprocess.run(["bash", "-c", body +
                    '\nechoContent() { printf "%s\\n" "$2"; }\n' +
                    f'updateGeoSite() {{ return {code}; }}\ncronName=UpdateGeo\ncronFunction'],
                    text=True, capture_output=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(bool(log.read_text().strip()), code == 0)
