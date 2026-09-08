"""Real bilingual Salt selection, staged publication, and public URL revocation."""
import base64
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import yaml
from test_port_installer import function, full_function

REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")
FORMATS = ("default", "clashMeta", "clashMetaProfiles", "sing-box", "sing-box_profiles")


def token(salt):
    return hashlib.md5(("alice" + salt + "\n").encode()).hexdigest()


class SubscriptionRevokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.index = 0

    def tearDown(self):
        self.temp.cleanup()

    def run_subscription(self, rel, *, answer="n\nnew-salt\n", failure=None, root=None):
        self.index += 1
        if root is None:
            root = self.root / str(self.index)
            for parent in ("subscribe", "subscribe_local"):
                for fmt in FORMATS:
                    (root / parent / fmt).mkdir(parents=True)
            (root / "subscribe_local/subscribeSalt").write_text("old-salt\n")
            for fmt in FORMATS:
                (root / "subscribe" / fmt / token("old-salt")).write_text("old " + fmt)
                (root / "subscribe" / fmt / "custom-note.txt").write_text("unrelated")
        if failure == "symlink":
            outside = root / "unrelated-secret"
            outside.write_text("must remain")
            victim = root / "subscribe/sing-box" / token("old-salt")
            victim.unlink()
            victim.symlink_to(outside)
        source = (REPO / rel).read_text()
        code = "\n".join(function(source, name) for name in
                         ("agentGenerateSubscriptions", "agentPublishSubscriptions", "subscribe"))
        code += "\n" + full_function(source, "clashMetaConfig")
        code = code.replace("/etc/v2ray-agent", str(root))
        if failure == "publish":
            code = code.replace("            os.replace(candidate, target)",
                                '            if fmt == "clashMeta":\n                raise OSError("injected publication failure")\n'
                                '            os.replace(candidate, target)')
        elif failure == "salt":
            code = code.replace('    os.replace(stage / "salt", salt)',
                                '    raise OSError("injected Salt publication failure")')
        elif failure in ("SIGINT", "SIGTERM", "SIGHUP", "SIGKILL"):
            # Deliver a real signal immediately after the second public rename.
            code = code.replace('            os.replace(candidate, target)',
                                '            os.replace(candidate, target)\n'
                                '            if fmt == "clashMeta":\n'
                                f'                os.kill(os.getpid(), signal.{failure})')
        elif failure == "KeyboardInterrupt":
            code = code.replace('            os.replace(candidate, target)',
                                '            os.replace(candidate, target)\n'
                                '            if fmt == "clashMeta":\n'
                                '                raise KeyboardInterrupt("injected keyboard interrupt")')
        setup = r'''
readInstallProtocolType() { :; }
installSubscribe() { :; }
readNginxSubscribe() { :; }
echoContent() { printf '%s\n' "$2"; }
showAccounts() {
  printf 'vless://secret@example.test:443#alice\n' >ROOT/subscribe_local/default/alice
  printf '  - {name: alice, type: vless, server: example.test, port: 443}\n' >ROOT/subscribe_local/clashMeta/alice
  printf '[{"tag":"alice","type":"vless","server":"example.test","server_port":443,"uuid":"secret"}]' >ROOT/subscribe_local/sing-box/alice
}
wget() { printf '{"outbounds":[{"tag":"select","outbounds":[]},{"tag":"direct","type":"direct"}]}' >"$2"; }
coreInstallType=1
subscribeType=https
currentHost=example.test
release=alpine
'''.replace("ROOT", shlex.quote(str(root)))
        if failure == "download":
            setup += '\nwget() { printf "partial" >"$2"; return 1; }\n'
        elif failure == "json":
            setup += '\nwget() { printf "invalid json" >"$2"; }\n'
        elif failure == "accounts":
            setup += '\nshowAccounts() { return 1; }\n'
        elif failure == "empty":
            setup += '\nshowAccounts() { :; }\n'
        proc = subprocess.run(["bash", "-c", setup + code + '\nsubscribe'],
                              input=answer, text=True, capture_output=True)
        return proc, root

    def assert_old_publication(self, root):
        self.assertEqual((root / "subscribe_local/subscribeSalt").read_text(), "old-salt\n")
        for fmt in FORMATS:
            folder = root / "subscribe" / fmt
            self.assertEqual({p.name for p in folder.iterdir()}, {token("old-salt"), "custom-note.txt"})
            self.assertEqual((folder / token("old-salt")).read_text(), "old " + fmt)
            self.assertEqual((folder / "custom-note.txt").read_text(), "unrelated")
        self.assertFalse(list(root.glob(".subscription-stage.*")))

    def assert_new_publication(self, proc, root, salt):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Subscriptions updated", proc.stdout)
        self.assertEqual((root / "subscribe_local/subscribeSalt").read_text(), salt + "\n")
        for fmt in FORMATS:
            folder = root / "subscribe" / fmt
            self.assertEqual({p.name for p in folder.iterdir()}, {token(salt), "custom-note.txt"})
            self.assertEqual((folder / "custom-note.txt").read_text(), "unrelated")
        encoded = (root / "subscribe/default" / token(salt)).read_bytes()
        self.assertEqual(base64.b64decode(encoded), b"vless://secret@example.test:443#alice\n")
        full = json.loads((root / "subscribe/sing-box" / token(salt)).read_text())
        self.assertEqual(full["outbounds"][0]["outbounds"], ["alice"])
        self.assertEqual(full["outbounds"][-1]["uuid"], "secret")
        profile = json.loads((root / "subscribe/sing-box_profiles" / token(salt)).read_text())
        self.assertEqual(profile, [full["outbounds"][-1]])
        clash = yaml.safe_load((root / "subscribe/clashMeta" / token(salt)).read_text())
        self.assertEqual(len(clash["proxies"]), 1)
        clash_profile = yaml.safe_load((root / "subscribe/clashMetaProfiles" / token(salt)).read_text())
        provider = clash_profile["proxy-providers"][salt + "_provider"]
        self.assertEqual(provider["url"], "https://example.test/s/clashMeta/" + token(salt))
        self.assertFalse(list(root.glob(".subscription-stage.*")))

    def test_rotation_revokes_all_five_old_url_formats_and_keeps_custom_files(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel)
                self.assert_new_publication(proc, root, "new-salt")

    def test_reusing_salt_replaces_outputs_without_appending_duplicates(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel, answer="y\n")
                self.assert_new_publication(proc, root, "old-salt")
                proc, _ = self.run_subscription(rel, answer="y\n", root=root)
                self.assert_new_publication(proc, root, "old-salt")

    def test_generation_failures_do_not_revoke_public_urls_or_save_salt(self):
        for rel in INSTALLERS:
            for failure in ("download", "json", "accounts", "empty"):
                with self.subTest(rel=rel, failure=failure):
                    proc, root = self.run_subscription(rel, failure=failure)
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertNotIn("Subscriptions updated", proc.stdout)
                    self.assertNotIn("https://example.test/s/", proc.stdout)
                    self.assert_old_publication(root)

    def test_partial_replacement_failure_restores_previous_same_salt_bytes(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel, answer="y\n", failure="publish")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("injected publication failure", proc.stderr)
                self.assertNotIn("Subscriptions updated", proc.stdout)
                self.assert_old_publication(root)

    def test_salt_write_failure_restores_revoked_urls_and_removes_new_urls(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel, failure="salt")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("injected Salt publication failure", proc.stderr)
                self.assert_old_publication(root)

    def test_symlink_in_generated_namespace_aborts_before_publication(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel, failure="symlink")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Unsafe generated subscription", proc.stderr)
                self.assertEqual((root / "unrelated-secret").read_text(), "must remain")
                self.assertEqual((root / "subscribe_local/subscribeSalt").read_text(), "old-salt\n")
                self.assertTrue((root / "subscribe/sing-box" / token("old-salt")).is_symlink())
                for fmt in FORMATS:
                    self.assertFalse((root / "subscribe" / fmt / token("new-salt")).exists())

    def test_interruptions_after_public_rename_restore_old_publication(self):
        for rel in INSTALLERS:
            for signum in ("SIGINT", "SIGTERM", "SIGHUP", "KeyboardInterrupt"):
                with self.subTest(rel=rel, signum=signum):
                    proc, root = self.run_subscription(rel, failure=signum)
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("injected keyboard interrupt" if signum == "KeyboardInterrupt" else "interrupted by signal", proc.stderr)
                    self.assertNotIn("Subscriptions updated", proc.stdout)
                    self.assert_old_publication(root)

    def test_sigkill_keeps_complete_private_recovery_mapping_and_blocks_retry(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                proc, root = self.run_subscription(rel, failure="SIGKILL")
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("Subscriptions updated", proc.stdout)
                stages = list(root.glob(".subscription-stage.*"))
                self.assertEqual(len(stages), 1)
                stage = stages[0]
                self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
                self.assertTrue((stage / "KEEP_RECOVERY").is_file())
                manifest = json.loads((stage / "recovery.json").read_text())
                self.assertEqual(manifest["root"], str(root))
                entries = {entry["target"]: entry["backup"] for entry in manifest["entries"]}
                self.assertEqual(len(entries), 11)
                for fmt in FORMATS:
                    old = entries[f"subscribe/{fmt}/" + token("old-salt")]
                    self.assertEqual((stage / old).read_text(), "old " + fmt)
                    self.assertIsNone(entries[f"subscribe/{fmt}/" + token("new-salt")])
                self.assertEqual((stage / entries["subscribe_local/subscribeSalt"]).read_text(), "old-salt\n")
                # The hard kill really interrupted a partially published set.
                self.assertTrue((root / "subscribe/default" / token("new-salt")).is_file())
                self.assertFalse((root / "subscribe/sing-box" / token("new-salt")).exists())
                previous = {str(path): path.read_bytes() for path in (root / "subscribe").rglob("*") if path.is_file()}
                retry, _ = self.run_subscription(rel, root=root)
                self.assertNotEqual(retry.returncode, 0)
                self.assertIn("Unfinished subscription publication", retry.stderr)
                self.assertTrue((stage / "KEEP_RECOVERY").is_file())
                self.assertEqual(previous, {str(path): path.read_bytes() for path in (root / "subscribe").rglob("*") if path.is_file()})


if __name__ == "__main__":
    unittest.main()
