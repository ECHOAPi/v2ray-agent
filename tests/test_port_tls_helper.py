"""Run the actual TLS helper functions with temporary paths and fake services."""
import fcntl
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "shell/init_tls.sh").read_text()


@unittest.skipUnless(os.geteuid() == 0, "helper deliberately requires root")
class TLSHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.etc = self.root / "etc"
        self.nginx = self.etc / "nginx"
        self.conf = self.nginx / "conf.d"
        self.conf.mkdir(parents=True)
        self.config = self.nginx / "nginx.conf"
        self.lock = self.nginx / ".v2ray-agent-tls.lock"
        self.original = "# original configuration\nserver_name example.com;\n"
        self.config.write_text(self.original)
        self.config.chmod(0o640)
        self.existing = self.conf / "5NX2O9XQKP.conf"
        self.existing.write_text("# existing unrelated configuration\n")
        self.attacker = self.root / "tmp/mack-a/nginx"
        self.attacker.mkdir(parents=True)
        (self.attacker / "nginx.conf").write_text("# attacker supplied configuration\n")
        self.calls = self.root / "nginx-calls"
        self.acme = self.root / "fake-acme"
        self.acme.write_text("""#!/usr/bin/env bash
if { : >&8; } 2>/dev/null; then
    echo 'ACME inherited the helper lock descriptor' >&2
    exit 99
fi
if [[ "$1" == --issue ]]; then
    [[ "$FAKE_PHASE" != issue ]]
    exit $?
fi
while (( $# )); do
    case "$1" in
        --fullchainpath) cert=$2; shift ;;
        --keypath) key=$2; shift ;;
    esac
    shift
done
[[ "$FAKE_PHASE" == missing-key ]] || printf 'PRIVATE KEY\\n' > "$key"
[[ "$FAKE_PHASE" == missing-cert ]] || printf 'CERTIFICATE\\n' > "$cert"
[[ "$FAKE_PHASE" != installcert ]]
""")
        self.acme.chmod(0o700)
        self.script = SOURCE.rsplit("\ncheckSystem\ninit", 1)[0]
        self.script = self.script.replace("/etc", str(self.etc))
        self.script = self.script.replace("/tmp/mack-a", str(self.root / "tmp/mack-a"))
        self.script = self.script.replace("~/.acme.sh/acme.sh", shlex.quote(str(self.acme)))
        self.script += f"""
echoColor() {{ printf '%s\\n' "$2"; }}
sleep() {{ :; }}
ps() {{ [[ "$FAKE_RUNNING" == 1 ]] && printf 'root 1 0 nginx\\n'; }}
curl() {{ [[ "$FAKE_PHASE" != probe ]] && printf '5NX2O9XQKP\\n'; }}
nginx() {{
    if {{ : >&8; }} 2>/dev/null; then
        echo 'Nginx inherited the helper lock descriptor' >&2
        return 99
    fi
    printf '%s\\n' "$*" >> {shlex.quote(str(self.calls))}
    if [[ $# == 0 ]]; then
        command cp -- {shlex.quote(str(self.config))} {shlex.quote(str(self.root / 'last-start-config'))}
        [[ "$FAKE_PHASE" != nginx-start ]] || return 73
    else
        [[ "$FAKE_PHASE" != nginx-stop ]] || return 73
    fi
    return 0
}}
"""

    def tearDown(self):
        self.temp.cleanup()

    def run_helper(self, body, phase="none", running=False):
        return subprocess.run(
            ["bash", "-c", self.script + "\n" + body],
            input="example.com\n", text=True, capture_output=True, timeout=5,
            env={**os.environ, "FAKE_PHASE": phase, "FAKE_RUNNING": str(int(running))},
        )

    def assert_restored(self):
        self.assertEqual(self.config.read_text(), self.original)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)
        self.assertEqual(self.existing.read_text(), "# existing unrelated configuration\n")
        self.assertEqual(list(self.conf.glob("v2ray-agent-acme.*.conf")), [])
        self.assertEqual(self.backups(), [])
        self.assertEqual((self.attacker / "nginx.conf").read_text(), "# attacker supplied configuration\n")
        self.assert_lock_available()

    def backups(self):
        return [path for path in self.nginx.glob(".v2ray-agent-tls.*") if path.is_dir()]

    def assert_lock_available(self):
        if self.lock.exists():
            with self.lock.open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)

    def test_success_ignores_fixed_public_backup_and_keeps_private_certificates(self):
        result = self.run_helper("installTLS", running=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assert_restored()
        outputs = list(self.nginx.glob("v2ray-agent-tls-certificates.*"))
        self.assertEqual(len(outputs), 1)
        self.assertEqual(stat.S_IMODE(outputs[0].stat().st_mode), 0o700)
        for extension, content in (("key", "PRIVATE KEY\n"), ("crt", "CERTIFICATE\n")):
            output = outputs[0] / f"example.com.{extension}"
            self.assertEqual(output.read_text(), content)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual((self.root / "last-start-config").read_text(), self.original)
        self.assertNotIn("/tmp/mack-a", SOURCE)

    def test_probe_and_certificate_failures_restore_originals(self):
        for phase in ("probe", "issue", "installcert", "missing-key", "missing-cert", "nginx-start", "nginx-stop"):
            with self.subTest(phase=phase):
                result = self.run_helper("installTLS", phase=phase, running=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_restored()
                self.assertEqual(list(self.nginx.glob("v2ray-agent-tls-certificates.*")), [])
                self.assertEqual((self.root / "last-start-config").read_text(), self.original)

    def test_exit_and_catchable_signals_restore_own_backup(self):
        for ending, code in (("exit 17", 17), ("kill -s HUP $$", 129),
                             ("kill -s INT $$", 130), ("kill -s TERM $$", 143)):
            with self.subTest(ending=ending):
                result = self.run_helper(f"""
bakConfig || exit 1
[[ $(stat -c %a "$tlsBackupDir") == 700 ]] || exit 2
printf 'changed configuration\\n' > {shlex.quote(str(self.config))}
tlsChallengeConfig=$(mktemp {shlex.quote(str(self.conf / 'v2ray-agent-acme.XXXXXXXXXX.conf'))})
{ending}
""")
                self.assertEqual(result.returncode, code, result.stderr)
                self.assert_restored()

    def test_symlink_backup_in_public_tmp_cannot_overwrite_target(self):
        target = self.root / "unrelated-file"
        target.write_text("never modify\n")
        (self.attacker / "nginx.conf").unlink()
        (self.attacker / "nginx.conf").symlink_to(target)
        result = self.run_helper("installTLS")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_text(), self.original)
        self.assertEqual(target.read_text(), "never modify\n")
        self.assertTrue((self.attacker / "nginx.conf").is_symlink())

    def test_rejects_untrusted_directories_and_configuration(self):
        for path in (self.etc, self.nginx, self.conf, self.config):
            with self.subTest(path=path.name):
                old_mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(old_mode | 0o020)
                result = self.run_helper("bakConfig")
                path.chmod(old_mode)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_restored()
        # Some isolated runners cannot chown fixtures. Inject only the metadata
        # result while still invoking the real ownership check and backup entry.
        result = self.run_helper(f"""
stat() {{
    if [[ "${{@: -1}}" == {shlex.quote(str(self.config))} ]]; then
        printf '65534 640\\n'
    else
        command stat "$@"
    fi
}}
bakConfig
""")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_restored()

    def test_rejects_symlinked_directory_and_main_config(self):
        saved = self.root / "saved-conf"
        self.conf.rename(saved)
        self.conf.symlink_to(saved, target_is_directory=True)
        result = self.run_helper("bakConfig")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.conf.unlink()
        saved.rename(self.conf)
        saved_config = self.root / "saved-nginx.conf"
        self.config.rename(saved_config)
        self.config.symlink_to(saved_config)
        result = self.run_helper("bakConfig")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(saved_config.read_text(), self.original)
        self.assertEqual(self.backups(), [])

    def test_backup_copy_failure_prevents_any_configuration_change(self):
        result = self.run_helper("cp() { return 73; }; installTLS")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_restored()
        self.assertFalse(self.calls.exists())

    def test_backup_directory_failure_prevents_any_configuration_change(self):
        result = self.run_helper("mktemp() { return 73; }; installTLS")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_restored()
        self.assertFalse(self.calls.exists())

    def test_failed_restore_retains_trusted_original_and_reports_failure(self):
        result = self.run_helper(f"""
bakConfig || exit 1
printf 'changed configuration\\n' > {shlex.quote(str(self.config))}
tlsChallengeConfig=$(mktemp {shlex.quote(str(self.conf / 'v2ray-agent-acme.XXXXXXXXXX.conf'))})
mv() {{ return 73; }}
exit 0
""")
        self.assertEqual(result.returncode, 1, result.stdout)
        backups = self.backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "nginx.conf").read_text(), self.original)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o700)
        self.assertIn(str(backups[0]), result.stdout)
        self.assertEqual(list(self.conf.glob("v2ray-agent-acme.*.conf")), [])
        self.assert_lock_available()

    def test_busy_helper_cannot_snapshot_or_modify_another_runs_config(self):
        for exit_code in (0, 17):
            with self.subTest(exit_code=exit_code):
                marker = self.root / "first-is-ready"
                marker.unlink(missing_ok=True)
                first = subprocess.Popen(
                    ["bash", "-c", self.script + f"""
bakConfig || exit 1
printf 'first helper temporary configuration\\n' > {shlex.quote(str(self.config))}
touch {shlex.quote(str(marker))}
read -r continuation
exit {exit_code}
"""], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env={**os.environ, "FAKE_PHASE": "none", "FAKE_RUNNING": "0"},
                )
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and first.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists(), "first helper never reached its protected section")
                    self.assertEqual(stat.S_IMODE(self.lock.stat().st_mode), 0o600)
                    with self.lock.open("r+") as lock:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    second = self.run_helper("installTLS")
                    self.assertNotEqual(second.returncode, 0, second.stdout)
                    self.assertIn("另一个 TLS", second.stdout)
                    self.assertEqual(self.config.read_text(), "first helper temporary configuration\n")
                    self.assertEqual(len(self.backups()), 1)
                    out, err = first.communicate("continue\n", timeout=5)
                    self.assertEqual(first.returncode, exit_code, out + err)
                    self.assert_restored()
                finally:
                    if first.poll() is None:
                        first.terminate()
                        first.communicate(timeout=5)

    def test_rejects_unsafe_existing_lock_without_touching_target(self):
        target = self.root / "lock-target"
        target.write_text("unrelated data\n")
        self.lock.symlink_to(target)
        result = self.run_helper("bakConfig")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(target.read_text(), "unrelated data\n")
        self.lock.unlink()
        self.lock.write_text("do not truncate\n")
        self.lock.chmod(0o644)
        result = self.run_helper("bakConfig")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.lock.read_text(), "do not truncate\n")
        self.lock.chmod(0o600)
        os.link(self.lock, self.root / "second-lock-link")
        result = self.run_helper("bakConfig")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.lock.read_text(), "do not truncate\n")
        self.assert_restored()

    def test_repeated_runs_keep_separate_certificates(self):
        for _ in range(2):
            result = self.run_helper("installTLS")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored()
        self.assertEqual(len(list(self.nginx.glob("v2ray-agent-tls-certificates.*"))), 2)


if __name__ == "__main__":
    unittest.main()
