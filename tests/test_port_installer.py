"""Exercise extracted installer functions against temporary paths only."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]


def function(text, name):
    start = text.index(name + "() {")
    return text[start:text.index("\n}", start) + 2]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, script):
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True)

    def test_merge_failure_keeps_last_good_config(self):
        for rel in ("install.sh", "shell/install_en.sh"):
            for fail_at in ("merge", "check", "none"):
                with self.subTest(rel=rel, fail_at=fail_at):
                    root = self.root / (rel.replace("/", "_") + fail_at)
                    conf = root / "sing-box/conf"
                    conf.mkdir(parents=True)
                    (conf / "config.json").write_text('{"original":true}\n')
                    binary = root / "sing-box/sing-box"
                    binary.write_text('#!/bin/bash\n'
                                      f'[[ "$1" == "{fail_at}" ]] && exit 1\n'
                                      'if [[ "$1" == "merge" ]]; then printf \'{"candidate":true}\\n\' > "$2"; fi\n'
                                      'exit 0\n')
                    binary.chmod(0o700)
                    body = function((REPO / rel).read_text(), "singBoxMergeConfig")
                    body = body.replace("/etc/v2ray-agent", str(root))
                    result = self.execute('echoContent() { :; }; initSingBoxHTTPClientConfig() { :; };\n' + body + '\nsingBoxMergeConfig')
                    self.assertEqual(result.returncode, 0 if fail_at == "none" else 1, result.stderr)
                    expected = '{"candidate":true}\n' if fail_at == "none" else '{"original":true}\n'
                    self.assertEqual((conf / "config.json").read_text(), expected)
                    self.assertEqual(list(conf.glob(".merged.*")), [])

    def test_input_releases_shared_lock_and_refuses_stale_config(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        root = self.root / "installed"
        (root / "xray/conf").mkdir(parents=True)
        config = root / "xray/conf/entry.json"
        config.write_text('{"port":443}')
        source = (REPO / "install.sh").read_text()
        helpers = "\n".join(function(source, name) for name in
                            ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "read"))
        helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
        marker = self.root / "prompt"
        script = helpers + f'\nagentWriteLock || exit 1\ntouch "{marker}"\nread -r -p "Value:" answer\necho SHOULD_NOT_RUN'
        proc = subprocess.Popen(["bash", "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            with (root / ".write.lock").open("r+") as lock:
                acquired = False
                while time.monotonic() < deadline:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                self.assertTrue(acquired, "prompt retained shared write lock")
                config.write_text('{"port":8443}')
                fcntl.flock(lock, fcntl.LOCK_UN)
            out, err = proc.communicate("yes\n", timeout=5)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("Configuration changed", err)
            self.assertNotIn("SHOULD_NOT_RUN", out)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_failed_update_preserves_script(self):
        for rel in ("install.sh", "shell/install_en.sh"):
            with self.subTest(rel=rel):
                root = self.root / rel.replace("/", "_")
                root.mkdir()
                previous = root / "install.sh"
                previous.write_text("original script\n")
                body = function((REPO / rel).read_text(), "updateV2RayAgent").replace("/etc/v2ray-agent", str(root))
                result = self.execute('echoContent() { :; }; curl() { return 22; };\n' + body + '\nupdateV2RayAgent')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(previous.read_text(), "original script\n")
                self.assertEqual(list(root.glob(".install.*")), [])

    def test_silent_subscription_generates_all_formats(self):
        for rel in ("install.sh", "shell/install_en.sh"):
            with self.subTest(rel=rel):
                root = self.root / rel.replace("/", "_")
                for parent in ("subscribe", "subscribe_local"):
                    for fmt in ("default", "clashMeta", "clashMetaProfiles", "sing-box", "sing-box_profiles"):
                        (root / parent / fmt).mkdir(parents=True)
                (root / "subscribe_local/subscribeSalt").write_text("test-salt\n")
                body = function((REPO / rel).read_text(), "subscribe").replace("/etc/v2ray-agent", str(root))
                setup = r'''
readInstallProtocolType() { :; }
installSubscribe() { :; }
readNginxSubscribe() { :; }
echoContent() { :; }
showAccounts() {
  printf 'vless://test@localhost:443#user\n' >ROOT/subscribe_local/default/user
  printf '  - {name: user, type: vless, port: 443}\n' >ROOT/subscribe_local/clashMeta/user
  printf '[{"tag":"user","type":"vless","server_port":443}]' >ROOT/subscribe_local/sing-box/user
}
clashMetaConfig() { printf 'generated' >"ROOT/subscribe/clashMetaProfiles/$2"; }
wget() { printf '{"outbounds":[{"tag":"select","outbounds":[]}]}' >"$2"; }
coreInstallType=1
subscribeType=https
currentHost=localhost
release=alpine
'''.replace("ROOT", str(root))
                result = self.execute(setup + body + '\nsubscribe false false')
                self.assertEqual(result.returncode, 0, result.stderr)
                for fmt in ("default", "clashMeta", "clashMetaProfiles", "sing-box", "sing-box_profiles"):
                    files = list((root / "subscribe" / fmt).iterdir())
                    self.assertEqual(len(files), 1, (rel, fmt, result.stderr))
                    self.assertGreater(files[0].stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
