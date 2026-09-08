"""Audit A08/A09/A14/A16: run real shell functions with inert host backends."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from test_port_installer import function

REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")


class HostSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "bin").mkdir()
        self.job = f"30 1 * * * /bin/bash {self.root}/install.sh RenewTLS >> {self.root}/crontab_tls.log 2>&1"
        self.write_command("sudo", '#!/bin/bash\nexec "$@"\n')
        self.write_command("iptables", '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["HOST_TEST_ROOT"])
args = sys.argv[1:]
with (root / "iptables.calls").open("a") as out:
    out.write(json.dumps(args) + "\\n")
if args[:4] != ["-w", "5", "-t", "nat"] or args[5] != "PREROUTING":
    sys.exit(91)
state = json.loads((root / "rules.json").read_text())
operation, spec = args[4], args[6:]
if os.environ.get("NAT_FAIL") == operation:
    sys.exit(4)
if spec not in state:
    sys.exit(1)
if operation == "-D":
    state.remove(spec)
    (root / "rules.json").write_text(json.dumps(state))
elif operation != "-C":
    sys.exit(92)
''')
        self.write_command("netfilter-persistent", '''#!/bin/bash
printf "%s\\n" "$*" >>"$HOST_TEST_ROOT/save.calls"
[[ "$NAT_FAIL" != save ]]
''')
        self.write_command("crontab", '''#!/usr/bin/env python3
import json, os, pwd, sys
from pathlib import Path
root = Path(os.environ["HOST_TEST_ROOT"])
state = root / "crontab"
log = root / "cron.calls"
with log.open("a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
mode = os.environ.get("CRON_MODE", "")
if sys.argv[1:] == ["-l"]:
    if mode == "changed" and len(log.read_text().splitlines()) == 2:
        state.write_text("# concurrent administrator job\\n")
    if mode == "read-error":
        print("crontab: permission denied", file=sys.stderr)
        sys.exit(1)
    if state.exists():
        sys.stdout.write(state.read_text())
        sys.exit(0)
    print("no crontab for " + pwd.getpwuid(os.geteuid()).pw_name, file=sys.stderr)
    sys.exit(1)
if mode == "write-error":
    sys.exit(1)
state.write_bytes(Path(sys.argv[1]).read_bytes())
''')

    def write_command(self, name, source):
        target = self.root / "bin" / name
        target.write_text(source)
        target.chmod(0o700)

    def shell(self, rel, names, command, setup="", **variables):
        source = (REPO / rel).read_text()
        body = "\n".join(function(source, name) for name in names)
        body = body.replace("/etc/v2ray-agent", str(self.root))
        environment = dict(os.environ, HOST_TEST_ROOT=str(self.root),
                           PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"], **variables)
        return subprocess.run(["bash", "-c", 'echoContent() { printf "%s\\n" "$2"; }\n' + body +
                               "\n" + setup + "\n" + command],
                              env=environment, capture_output=True, text=True, timeout=10)

    @staticmethod
    def rule(kind="hysteria2", port="443", start="30000", end="30002"):
        return ["-p", "udp", "--dport", start + ":" + end, "-m", "comment", "--comment",
                "mack-a_" + kind + "_portHopping", "-j", "DNAT", "--to-destination", ":" + port]

    def nat(self, rel, **env):
        return self.shell(rel, ("deletePortHoppingRules",),
                          "deletePortHoppingRules hysteria2 30000 30002 443", "release=ubuntu", **env)

    def test_nat_deletes_exact_rule_and_duplicates_preserving_order(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                unrelated = [["-j", "OTHER_FIRST"], self.rule(port="8443"), self.rule(kind="tuic"), ["-j", "LAST"]]
                (self.root / "rules.json").write_text(json.dumps(unrelated[:2] + [self.rule()] +
                                                               unrelated[2:] + [self.rule()]))
                result = self.nat(rel)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((self.root / "rules.json").read_text()), unrelated)
                calls = [json.loads(line) for line in (self.root / "iptables.calls").read_text().splitlines()]
                self.assertTrue(all(call[6:] == self.rule() for call in calls))
                self.assertNotIn("--line-numbers", (self.root / "iptables.calls").read_text())

    def test_nat_absent_rule_does_not_save_or_delete(self):
        (self.root / "rules.json").write_text("[]")
        for rel in INSTALLERS:
            result = self.nat(rel)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "save.calls").exists())
        self.assertNotIn('"-D"', (self.root / "iptables.calls").read_text())

    def test_nat_backend_failures_are_not_success(self):
        for rel in INSTALLERS:
            for failed in ("-C", "-D", "save"):
                with self.subTest(rel=rel, failed=failed):
                    (self.root / "rules.json").write_text(json.dumps([self.rule()]))
                    result = self.nat(rel, NAT_FAIL=failed)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(json.loads((self.root / "rules.json").read_text()),
                                     [] if failed == "save" else [self.rule()])

    def test_nat_rejects_invalid_inputs_before_any_command(self):
        for rel in INSTALLERS:
            for values in (["unknown", "1", "2", "443"], ["tuic", "0", "2", "443"],
                           ["tuic", "2", "1", "443"], ["tuic", "1+1", "3", "443"],
                           ["tuic", "1", "2", "65536"], ["tuic", "01", "2", "443"],
                           ["tuic", "1", "2", "$(touch /not-a-command)"]):
                with self.subTest(rel=rel, values=values):
                    result = self.shell(rel, ("deletePortHoppingRules",),
                                        "deletePortHoppingRules " + shlex.join(values), "release=ubuntu")
                    self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.root / "iptables.calls").exists())

    def test_nat_menu_stops_on_delete_failure(self):
        setup = """find() { echo /usr/sbin/iptables; }
readPortHopping() { hysteria2PortHoppingStart=30000; hysteria2PortHoppingEnd=30002; }
read() { selectPortHoppingStatus=2; }
deletePortHoppingRules() { return 1; }
singBoxHysteria2Port=443
"""
        for rel in INSTALLERS:
            result = self.shell(rel, ("portHoppingMenu",), "portHoppingMenu hysteria2", setup)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn("删除成功", result.stdout)

    def test_centos_deletion_uses_bounded_exact_forward_ports(self):
        self.write_command("firewall-cmd", '#!/bin/bash\nprintf "%s\\n" "$*" >>"$HOST_TEST_ROOT/firewall.calls"\n')
        for rel in INSTALLERS:
            (self.root / "firewall.calls").write_text("")
            result = self.shell(rel, ("deletePortHoppingRules",), "deletePortHoppingRules tuic 2 4 443", "release=centos")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.root / "firewall.calls").read_text().splitlines(),
                             [f"--permanent --remove-forward-port=port={p}:proto=udp:toport=443" for p in (2, 3, 4)]
                             + ["--reload"])

    def test_package_guard_is_exact_and_fail_closed(self):
        for rel in INSTALLERS:
            for code in (0, 1, 2):
                with self.subTest(rel=rel, code=code):
                    result = self.shell(rel, ("agentPackageManagerReady",), "agentPackageManagerReady",
                                        f'pgrep() {{ printf "%s\\n" "$*" >&2; return {code}; }}')
                    self.assertEqual(result.returncode, 0 if code == 1 else 1, result.stderr)
                    self.assertIn("-x apt|apt-get|dpkg|unattended-upgr|yum|dnf", result.stderr)

    def test_busy_package_manager_stops_installer_without_killing(self):
        setup = """pgrep() { return 0; }
dpkg() { echo UNEXPECTED_DPKG; exit 90; }
kill() { echo UNEXPECTED_KILL; exit 91; }
release=ubuntu
"""
        for rel in INSTALLERS:
            result = self.shell(rel, ("agentPackageManagerReady", "installTools"), "installTools 1", setup)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn("UNEXPECTED", result.stdout)
            self.assertNotIn("kill -9", function((REPO / rel).read_text(), "installTools"))
            self.assertNotIn("/var/run/yum.pid", function((REPO / rel).read_text(), "installTools"))

    def test_dpkg_failure_stops_installer(self):
        for rel in INSTALLERS:
            result = self.shell(rel, ("agentPackageManagerReady", "installTools"), "installTools 1",
                                "pgrep() { return 1; }; dpkg() { return 17; }; release=ubuntu")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse((self.root / "install.log").exists())

    def cron(self, rel, **env):
        return self.shell(rel, ("agentReadCrontab", "installCronTLS"), "installCronTLS 1", **env)

    def test_tls_cron_preserves_unrelated_jobs_and_is_idempotent(self):
        untouched = ("MAILTO=ops@example.test\n# acme.sh v2ray-agent reminder\n"
                     "35 1 * * * /bin/bash /etc/v2ray-agent/install.sh UpdateGeo\n"
                     "*/5 * * * * /usr/local/bin/v2ray-agent-monitor\n"
                     "7 0 * * * /root/.acme.sh/acme.sh --cron\n"
                     + self.job + " --custom-option\n")
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                original = untouched + self.job + "\n" + self.job + " # v2ray-agent:tls-renewal\n"
                (self.root / "crontab").write_text(original)
                result = self.cron(rel)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = untouched + self.job + " # v2ray-agent:tls-renewal\n"
                self.assertEqual((self.root / "crontab").read_text(), expected)
                backup = self.root / "backup_crontab.cron"
                self.assertEqual(backup.read_text(), original)
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.cron(rel).returncode, 0)
                self.assertEqual((self.root / "crontab").read_text(), expected)
                self.assertEqual(list(self.root.glob(".cron-tls.*")), [])

    def test_cron_known_absent_and_control_panel_skip(self):
        for rel in INSTALLERS:
            (self.root / "crontab").unlink(missing_ok=True)
            self.assertEqual(self.cron(rel).returncode, 0)
            self.assertEqual((self.root / "crontab").read_text(), self.job + " # v2ray-agent:tls-renewal\n")
            (self.root / "cron.calls").unlink()
            result = self.cron(rel, btDomain="panel.example")
            self.assertEqual(result.returncode, 0)
            self.assertFalse((self.root / "cron.calls").exists())

    def test_cron_read_write_and_concurrent_edit_failures_preserve_jobs(self):
        for rel in INSTALLERS:
            for mode in ("read-error", "write-error", "changed"):
                with self.subTest(rel=rel, mode=mode):
                    (self.root / "cron.calls").write_text("")
                    (self.root / "crontab").write_text("# existing job\n")
                    result = self.cron(rel, CRON_MODE=mode)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    expected = "# concurrent administrator job\n" if mode == "changed" else "# existing job\n"
                    self.assertEqual((self.root / "crontab").read_text(), expected)
                    self.assertNotIn("installed;", result.stdout)
                    self.assertEqual(list(self.root.glob(".cron-tls.*")), [])

    def test_cron_backup_symlink_is_replaced_not_followed(self):
        outside = self.root / "unrelated"
        outside.write_text("preserve me")
        backup = self.root / "backup_crontab.cron"
        for rel in INSTALLERS:
            backup.unlink(missing_ok=True)
            backup.symlink_to(outside)
            (self.root / "crontab").write_text("# job\n")
            self.assertEqual(self.cron(rel).returncode, 0)
            self.assertFalse(backup.is_symlink())
            self.assertEqual(outside.read_text(), "preserve me")

    def test_retired_ufw_script_does_not_run_host_commands(self):
        for name in ("iptables", "ip6tables", "ufw", "systemctl", "sudo"):
            self.write_command(name, '#!/bin/bash\nprintf "%s\\n" "$0 $*" >>"$HOST_TEST_ROOT/unsafe.calls"\nexit 99\n')
        result = subprocess.run(["bash", str(REPO / "shell/ufw_remove.sh")], capture_output=True, text=True,
                                env=dict(os.environ, HOST_TEST_ROOT=str(self.root),
                                         PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"]))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no firewall or service was changed", result.stderr)
        self.assertFalse((self.root / "unsafe.calls").exists())
