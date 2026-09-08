"""Run the real bilingual account menu against isolated protocol fragments."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from test_port_installer import function

REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")
ALICE = "a6a5f475-81fa-4ae2-9aab-9d5e9e104001"
BOB = "c6a5f475-81fa-4ae2-9aab-9d5e9e104002"


def config(kind="xray", protocol="vless", suffix="VLESS_TCP/TLS_Vision", reverse=False, reality=False):
    users = []
    for name, credential in (("alice", ALICE), ("bob", BOB)):
        key = "password" if protocol in ("trojan", "hysteria2", "anytls", "naive", "socks") else ("id" if kind == "xray" else "uuid")
        label = "email" if kind == "xray" else ("username" if protocol in ("naive", "socks") else "name")
        users.append({key: credential, label: name + "-" + suffix, "custom": {"preserve": name}})
        if protocol == "tuic":
            users[-1]["password"] = "independent-" + name
    if reverse:
        users.reverse()
    inbound = {"tag": suffix, "listen": "127.0.0.1", "extra": {"keep": [1, 2]}}
    if kind == "xray":
        inbound.update(protocol=protocol, port=443, settings={"clients": users, "decryption": "none"},
                       streamSettings={"network": "tcp", "realitySettings": {"serverNames": ["example.test"], "target": "example.test:443", "publicKey": "public"}})
    else:
        inbound.update(type=protocol, listen_port=443, users=users,
                       tls={"server_name": "example.test", "reality": {"handshake": {"server_port": 443}}})
    inbounds = ([{"tag": "forward", "port": 8443, "settings": {"address": "127.0.0.1"}}] if reality else []) + [inbound]
    return {"inbounds": inbounds, "metadata": {"must": "survive"}}


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = 0

    def tearDown(self):
        self.temp.cleanup()

    def run_menu(self, rel, fragments, selection="1", core="1", command_setup=""):
        self.case += 1
        root = self.root / str(self.case)
        xray = root / "xray"
        singbox = root / "singbox"
        for path in (xray, singbox, root / "nginx"):
            path.mkdir(parents=True)
        (root / "nginx/sing_box_VMess_HTTPUpgrade.conf").write_text("listen 443;\n")
        originals = {}
        for (directory, name), value in fragments.items():
            path = (xray if directory == "xray" else singbox) / (name + ".json")
            content = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
            path.write_text(content)
            path.chmod(0o640)
            originals[path] = content
        source = (REPO / rel).read_text()
        recognition = function(source, "readInstallProtocolType")
        # This sandbox lacks /proc/self/fd. Preserve the recognition loop and
        # matching logic, supplying the same pipeline through a regular file.
        pipeline = 'find ${configPath} -name "*inbounds.json" | sort | awk -F "[.]" \'{print $1}\''
        recognition = recognition.replace('    while read -r row; do', '    ' + pipeline + ' >"${protocolList}"\n    while read -r row; do', 1)
        recognition = recognition.replace('done < <(' + pipeline + ')', 'done <"${protocolList}"')
        script = '\n'.join((
            'echoContent() { printf "%s\\n" "$2"; }',
            'reloadCore() { printf "RELOADED\\n"; }',
            'readNginxSubscribe() { subscribePort=; }',
            'manageAccount() { :; }',
            f'configPath={shlex.quote(str(xray if core == "1" else singbox) + "/")}',
            f'singBoxConfigPath={shlex.quote(str(singbox) + "/")}',
            f'nginxConfigPath={shlex.quote(str(root / "nginx") + "/")}',
            f'protocolList={shlex.quote(str(root / "protocols"))}',
            f'coreInstallType={core}', recognition,
            function(source, "agentRevokeAccount"), function(source, "removeUser"),
            command_setup, 'readInstallProtocolType',
            'printf "PROTOCOLS=%s FRONT=%s\\n" "$currentInstallProtocolType" "$frontingType"',
            'removeUser',
        ))
        result = subprocess.run(["bash", "-c", script], input=selection + "\n", text=True, capture_output=True)
        return result, originals, root

    def assert_revoked(self, originals):
        for path, text in originals.items():
            expected = json.loads(text)
            for inbound in expected["inbounds"]:
                users = inbound.get("settings", {}).get("clients", inbound.get("users"))
                if users is not None:
                    users[:] = [user for user in users if (user.get("id") or user.get("uuid") or user.get("password")) != ALICE]
            self.assertEqual(json.loads(path.read_text()), expected, str(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(list(path.parent.glob(".account-*")), [])

    def assert_untouched(self, result, originals):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("RELOADED", result.stdout)
        for path, text in originals.items():
            self.assertEqual(path.read_text(), text, str(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(list(path.parent.glob(".account-*")), [])

    def test_normal_vision_and_trojan_grpc_preserve_json(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "04_trojan_gRPC_inbounds"): config(protocol="trojan", suffix="Trojan_gRPC"),
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("PROTOCOLS=,0,2, FRONT=02_VLESS_TCP_inbounds", result.stdout)
                self.assertIn("RELOADED", result.stdout)
                self.assert_revoked(originals)

    def test_xhttp_reordered_accounts_use_credential(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "12_VLESS_XHTTP_inbounds"): config(suffix="VLESS_Reality_XHTTP", reverse=True),
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("PROTOCOLS=,0,12, FRONT=02_VLESS_TCP_inbounds", result.stdout)
                self.assert_revoked(originals)

    def test_mixed_core_reality_and_httpupgrade_keep_unrelated_fields(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "07_VLESS_vision_reality_inbounds"): config(suffix="vless_reality_vision", reverse=True, reality=True),
                    ("xray", "11_VMess_HTTPUpgrade_inbounds"): config(protocol="vmess", suffix="VMess_HTTPUpgrade", reverse=True),
                    ("singbox", "06_hysteria2_inbounds"): config("singbox", "hysteria2", "singbox_hysteria2", True),
                    ("singbox", "09_tuic_inbounds"): config("singbox", "tuic", "singbox_tuic", True),
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_revoked(originals)

    def test_singbox_all_account_types_and_duplicate_directory(self):
        protocols = {
            "02_VLESS_TCP": ("vless", "VLESS_TCP/TLS_Vision"),
            "03_VLESS_WS": ("vless", "VLESS_WS"),
            "04_trojan_TCP": ("trojan", "Trojan_TCP"),
            "05_VMess_WS": ("vmess", "VMess_WS"),
            "06_hysteria2": ("hysteria2", "singbox_hysteria2"),
            "07_VLESS_vision_reality": ("vless", "VLESS_Reality_Vision"),
            "08_VLESS_vision_gRPC": ("vless", "VLESS_Reality_gPRC"),
            "09_tuic": ("tuic", "singbox_tuic"),
            "10_naive": ("naive", "singbox_naive"),
            "11_VMess_HTTPUpgrade": ("vmess", "VMess_HTTPUpgrade"),
            "13_anytls": ("anytls", "anytls"),
            "20_socks5": ("socks", "socks5"),
        }
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                fragments = {("singbox", key + "_inbounds"): config("singbox", protocol, suffix, key != "13_anytls")
                             for key, (protocol, suffix) in protocols.items()}
                result, originals, _ = self.run_menu(rel, fragments, core="2")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_revoked(originals)

    def test_xhttp_only_has_account_source(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "12_VLESS_XHTTP_inbounds"): config(suffix="VLESS_Reality_XHTTP"),
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_revoked(originals)

    def test_invalid_input_never_changes_configuration(self):
        for rel in INSTALLERS:
            for selection in ("", "0", "-1", "3", "01", "1+1", "1]", "99999999999999999999999"):
                with self.subTest(rel=rel, selection=selection):
                    result, originals, _ = self.run_menu(rel, {("xray", "02_VLESS_TCP_inbounds"): config()}, selection)
                    self.assert_untouched(result, originals)

    def test_malformed_sibling_leaves_every_fragment_untouched(self):
        for rel in INSTALLERS:
            for malformed in ('{"inbounds":[', {"inbounds": [{"settings": {"clients": {"broken": True}}}]},
                              {"inbounds": [{"tag": "missing-accounts"}]}, json.dumps(config()) + json.dumps(config()),
                              json.dumps({"inbounds": [{"tag": "missing-accounts"}]}) + json.dumps(config(protocol="trojan"))):
                with self.subTest(rel=rel, malformed=malformed):
                    result, originals, _ = self.run_menu(rel, {
                        ("xray", "02_VLESS_TCP_inbounds"): config(),
                        ("xray", "04_trojan_gRPC_inbounds"): malformed,
                    })
                    self.assert_untouched(result, originals)

    def test_publish_failure_rolls_back_prior_fragments(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "04_trojan_gRPC_inbounds"): config(protocol="trojan", suffix="Trojan_gRPC"),
                    ("xray", "12_VLESS_XHTTP_inbounds"): config(suffix="VLESS_Reality_XHTTP"),
                }, command_setup='moveCount=0; mv() { moveCount=$((moveCount + 1)); [[ "$moveCount" != 2 ]] || return 1; command mv "$@"; }')
                self.assert_untouched(result, originals)

    def test_interrupt_during_publish_restores_fragments(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "04_trojan_gRPC_inbounds"): config(protocol="trojan", suffix="Trojan_gRPC"),
                }, command_setup='moveCount=0; mv() { moveCount=$((moveCount + 1)); command mv "$@" || return; [[ "$moveCount" != 1 ]] || kill -TERM "$BASHPID"; }')
                self.assert_untouched(result, originals)

    def test_reload_failure_is_reported_after_committed_revocation(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                }, command_setup='reloadCore() { return 1; }; manageAccount() { printf "SHOULD_NOT_RUN\\n"; }')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)
                self.assert_revoked(originals)

    def test_matching_names_do_not_revoke_another_credential(self):
        for rel in INSTALLERS:
            with self.subTest(rel=rel):
                sibling = config(suffix="VLESS_Reality_XHTTP")
                sibling["inbounds"][0]["settings"]["clients"][0]["id"] = "other-independent-account"
                result, originals, _ = self.run_menu(rel, {
                    ("xray", "02_VLESS_TCP_inbounds"): config(),
                    ("xray", "12_VLESS_XHTTP_inbounds"): sibling,
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_revoked(originals)


if __name__ == "__main__":
    unittest.main()
