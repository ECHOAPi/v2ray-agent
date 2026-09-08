"""Exercise extracted installer functions against temporary paths only."""
import fcntl
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shell"))
from port_manager.__main__ import shared_lock


def function(text, name):
    start = text.index(name + "() {")
    return text[start:text.index("\n}", start) + 2]


def full_function(text, name):
    """Include heredoc JSON braces; stop at the next top-level function."""
    start = text.index(name + "() {")
    body = text.index("\n", start) + 1
    following = re.search(r"(?m)^[A-Za-z_][A-Za-z_0-9]*\(\) \{", text[body:])
    return text[start:body + following.start()] if following else text[start:]


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
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        for rel in ("install.sh", "shell/install_en.sh"):
            with self.subTest(rel=rel):
                root = self.root / rel.replace("/", "_")
                root.mkdir()
                previous = root / "install.sh"
                previous.write_text("original script\n")
                source = (REPO / rel).read_text()
                body = "\n".join(function(source, name) for name in (
                    "agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "agentPreparationDigest",
                    "agentPrepare", "agentDownloadScript", "updateV2RayAgent"))
                body = body.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
                result = self.execute('echoContent() { :; }; curl() { echo DOWNLOAD_FAILED >&2; return 22; };\n' + body + '\nupdateV2RayAgent')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DOWNLOAD_FAILED", result.stderr)
                self.assertEqual(previous.read_text(), "original script\n")
                self.assertEqual(list(root.glob(".install.*")), [])

    def test_prompt_digest_ignores_runtime_files_but_detects_config_and_credentials(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        scenarios = ("none", "logs", "binary", "config", "created", "deleted", "key", "subscription")
        for rel in ("install.sh", "shell/install_en.sh"):
            for change in scenarios:
                with self.subTest(rel=rel, change=change):
                    root = self.root / (rel.replace("/", "_") + change)
                    for dirname in ("xray/conf", "sing-box/conf/config", "subscribe_local"):
                        (root / dirname).mkdir(parents=True)
                    config = root / "xray/conf/entry.json"
                    config.write_text('{"port":443}')
                    (root / "xray/conf/reality_key").write_text("private-key")
                    (root / "subscribe_local/subscribeSalt").write_text("original-salt")
                    source = (REPO / rel).read_text()
                    helpers = "\n".join(function(source, name) for name in
                                        ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "read"))
                    helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
                    marker = root / "prompt"
                    script = helpers + f'\nagentWriteLock || exit 1\ntouch "{marker}"\nread -r -p "Value:" answer\necho CONTINUED'
                    proc = subprocess.Popen(["bash", "-c", script], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        deadline = time.monotonic() + 5
                        while not marker.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(marker.exists())
                        with shared_lock(root, timeout=5):
                            if change == "logs":
                                for name in ("xray/error.log", "sing-box/conf/box.log", "sing-box/conf/config/ignored.log"):
                                    (root / name).write_text("normal runtime log growth\n")
                            elif change == "binary":
                                (root / "xray/xray").write_bytes(b"updated-core")
                                (root / "xray/geoip.dat").write_bytes(b"updated-geo")
                            elif change == "config":
                                config.write_text('{"port":8443}')
                            elif change == "created":
                                (root / "sing-box/conf/config/added.json").write_text('{}')
                            elif change == "deleted":
                                config.unlink()
                            elif change == "key":
                                (root / "xray/conf/reality_key").write_text("rotated-private-key")
                            elif change == "subscription":
                                (root / "subscribe_local/subscribeSalt").write_text("rotated-salt")
                        out, err = proc.communicate("yes\n", timeout=5)
                        changed = change not in ("none", "logs", "binary")
                        self.assertEqual(proc.returncode, 1 if changed else 0, err)
                        self.assertEqual("Configuration changed" in err, changed, err)
                        self.assertEqual("CONTINUED" in out, not changed, out)
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.communicate()

    def test_digest_failure_aborts_even_when_caller_ignores_read_status(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        for rel in ("install.sh", "shell/install_en.sh"):
            with self.subTest(rel=rel):
                root = self.root / rel.replace("/", "_")
                (root / "xray/conf").mkdir(parents=True)
                (root / "xray/conf/entry.json").write_text('{"port":443}')
                source = (REPO / rel).read_text()
                helpers = "\n".join(function(source, name) for name in
                                    ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "read"))
                helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
                script = helpers + '''
agentWriteLock || exit 1
sha256sum() { echo DIGEST_FAILURE >&2; return 74; }
answer=stale_default
read -r -p "Value:" answer || :
echo "CONTINUED_WITH_$answer"
'''
                result = subprocess.run(["bash", "-c", script], input="yes\n", text=True,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("DIGEST_FAILURE", result.stderr)
                self.assertNotIn("CONTINUED", result.stdout)
                with shared_lock(root, timeout=0):
                    pass

    def test_real_log_menus_release_lock_and_revalidate_before_continuing(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        for rel in ("install.sh", "shell/install_en.sh"):
            for menu, choice in (("checkLog", 2), ("checkLog", 3),
                                 ("singBoxVersionManageMenu", 5), ("singBoxVersionManageMenu", 6)):
                for change in (False, True):
                    with self.subTest(rel=rel, menu=menu, choice=choice, change=change):
                        root = self.root / f'{rel.replace("/", "_")}-{menu}-{choice}-{change}'
                        for dirname in ("xray/conf", "sing-box/conf/config"):
                            (root / dirname).mkdir(parents=True)
                        config = root / "xray/conf/00_log.json"
                        config.write_text('{"log":{"level":"warning"}}')
                        logfile = root / ("xray/access.log" if menu == "checkLog" and choice == 2 else
                                          "xray/error.log" if menu == "checkLog" else "sing-box/conf/box.log")
                        logfile.write_text("REAL_TAIL_OUTPUT\n")
                        source = (REPO / rel).read_text()
                        helpers = "\n".join(function(source, name) for name in
                                            ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "agentReadOnly", "read"))
                        helpers += "\n" + full_function(source, menu)
                        if menu == "singBoxVersionManageMenu":
                            helpers += "\n" + full_function(source, "singBoxLog")
                        helpers = helpers.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
                        pidfile = root / "tail.pid"
                        script = helpers + f'''
echoContent() {{ :; }}
handleSingBox() {{ :; }}
tail() {{
    if ( : >&9 ) 2>/dev/null; then echo FD_LEAK >&2; return 97; fi
    command tail "$@" &
    local child=$!
    echo "$child" >"{pidfile}"
    wait "$child"
}}
coreInstallType=1
configPath="{root}/xray/conf/"
singBoxConfigPath="{root}/sing-box/conf/config/"
agentWriteLock || exit 1
{menu} 1
[[ $agentLockHeld == 1 ]] || exit 98
flock -n "{root}/.write.lock" -c true && exit 99
echo CONTINUED
'''
                        output = root / "output"
                        with output.open("w") as stdout:
                            proc = subprocess.Popen(["bash", "-c", script], stdin=subprocess.PIPE,
                                                    stdout=stdout, stderr=subprocess.PIPE, text=True,
                                                    start_new_session=True)
                            try:
                                proc.stdin.write(f"{choice}\n")
                                proc.stdin.flush()
                                deadline = time.monotonic() + 5
                                while (not pidfile.exists() or "REAL_TAIL_OUTPUT" not in output.read_text()) and time.monotonic() < deadline and proc.poll() is None:
                                    time.sleep(0.01)
                                if proc.poll() is not None:
                                    _, err = proc.communicate(timeout=5)
                                    self.fail(f"log menu exited before tail started: {err}")
                                self.assertIn("REAL_TAIL_OUTPUT", output.read_text(), "real tail did not start")
                                # Exercise the exact lock used by the policy daemon while real tail -f is alive.
                                with shared_lock(root, timeout=0):
                                    if change:
                                        config.write_text('{"log":{"level":"debug"}}')
                                    else:
                                        with logfile.open("a") as stream:
                                            stream.write("normal log growth\n")
                                os.kill(int(pidfile.read_text()), signal.SIGTERM)
                                _, err = proc.communicate(timeout=5)
                                self.assertNotIn("FD_LEAK", err)
                                self.assertEqual(proc.returncode, 1 if change else 0, err)
                                self.assertEqual("Configuration changed" in err, change, err)
                                self.assertEqual("CONTINUED" in output.read_text(), not change)
                            finally:
                                if proc.poll() is None:
                                    os.killpg(proc.pid, signal.SIGKILL)
                                proc.communicate()

    def test_silent_subscription_generates_all_formats(self):
        for rel in ("install.sh", "shell/install_en.sh"):
            with self.subTest(rel=rel):
                root = self.root / rel.replace("/", "_")
                for parent in ("subscribe", "subscribe_local"):
                    for fmt in ("default", "clashMeta", "clashMetaProfiles", "sing-box", "sing-box_profiles"):
                        (root / parent / fmt).mkdir(parents=True)
                (root / "subscribe_local/subscribeSalt").write_text("test-salt\n")
                source = (REPO / rel).read_text()
                body = '\n'.join(function(source, name) for name in
                                 ("agentGenerateSubscriptions", "agentPublishSubscriptions", "subscribe"))
                body = body.replace("/etc/v2ray-agent", str(root))
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
clashMetaConfig() { printf 'generated' >"${subscriptionOutputRoot}/clashMetaProfiles/$2"; }
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
