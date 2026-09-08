"""Parse actual bilingual client-generator output from isolated directories."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

import yaml

from test_port_installer import full_function


REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")


class ClientDefaultsTests(unittest.TestCase):
    def run_generator(self, source, root, name, setup, arguments):
        body = full_function(source, name).replace("/etc/v2ray-agent", str(root))
        script = "\n".join((
            'echoContent() { :; }', body, setup,
            " ".join((name, *(shlex.quote(value) for value in arguments))),
        ))
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)

    def test_clash_full_profile_uses_private_listeners_and_valid_providers(self):
        for rel in INSTALLERS:
            with self.subTest(installer=rel), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                profiles = root / "subscribe/clashMetaProfiles"
                profiles.mkdir(parents=True)
                url = "https://subscribe.example.test/s/clashMeta/account-hash"
                self.run_generator((REPO / rel).read_text(), root, "clashMetaConfig",
                                   "subscribeSalt=fixtureSalt", [url, "account-hash"])
                profile = yaml.safe_load((profiles / "account-hash").read_text())
                self.assertIs(profile["allow-lan"], False)
                self.assertEqual(profile["bind-address"], "127.0.0.1")
                self.assertEqual(profile["lan-allowed-ips"], ["127.0.0.1/32", "::1/128"])
                self.assertEqual(profile["mixed-port"], 7890)
                self.assertEqual(profile["external-controller"], "127.0.0.1:9090")
                self.assertIs(profile["external-controller-cors"]["allow-private-network"], False)
                self.assertEqual(profile["dns"]["listen"], "127.0.0.1:1053")
                self.assertIs(profile["dns"]["enable"], True)
                providers = profile["proxy-providers"]
                self.assertEqual(list(providers), ["fixtureSalt_provider"])
                provider = providers["fixtureSalt_provider"]
                self.assertEqual(provider["url"], url)
                self.assertEqual(provider["path"], "./fixtureSalt_provider.yaml")
                self.assertEqual(provider["type"], "http")
                self.assertIs(provider["health-check"]["enable"], True)
                self.assertTrue(profile["rules"])
                for group in profile["proxy-groups"]:
                    for used_provider in group.get("use", []):
                        self.assertIn(used_provider, providers)

    def test_trojan_grpc_verifies_certificate_and_preserves_nodes_across_formats(self):
        for rel in INSTALLERS:
            for address in ("cdn.example.test", "192.0.2.25"):
                with self.subTest(installer=rel, address=address), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    local = root / "subscribe_local"
                    for kind in ("default", "clashMeta", "sing-box"):
                        (local / kind).mkdir(parents=True)
                    # An existing outbound must survive appending another protocol.
                    previous = {"type": "direct", "tag": "preserved", "bind_interface": "eth0"}
                    (local / "sing-box/alice").write_text(json.dumps([previous]))
                    (local / "clashMeta/alice").write_text("proxies:\n")
                    self.run_generator((REPO / rel).read_text(), root, "defaultBase64Code",
                                       "currentHost=certificate.example.test\ncurrentPath=fixture",
                                       ["trojangrpc", "8443", "alice-Trojan_gRPC", "example-password", address])
                    outbounds = json.loads((local / "sing-box/alice").read_text())
                    self.assertEqual(len(outbounds), 2)
                    self.assertEqual(outbounds[0], previous)
                    node = outbounds[1]
                    self.assertEqual(node["type"], "trojan")
                    self.assertEqual(node["tag"], "alice-Trojan_gRPC")
                    self.assertEqual(node["server"], address)
                    self.assertEqual(node["server_port"], 8443)
                    self.assertEqual(node["password"], "example-password")
                    self.assertIs(node["tls"]["enabled"], True)
                    self.assertFalse(node["tls"].get("insecure", False))
                    self.assertEqual(node["tls"]["server_name"], "certificate.example.test")
                    self.assertEqual(node["transport"]["type"], "grpc")
                    self.assertEqual(node["transport"]["service_name"], "fixturetrojangrpc")
                    clash = yaml.safe_load((local / "clashMeta/alice").read_text())["proxies"][0]
                    self.assertEqual(clash["server"], address)
                    self.assertEqual(clash["sni"], node["tls"]["server_name"])
                    self.assertEqual(clash["port"], node["server_port"])
                    self.assertEqual(clash["password"], node["password"])
                    self.assertFalse(clash.get("skip-cert-verify", False))
                    uri = urlsplit((local / "default/alice").read_text().strip())
                    self.assertEqual(uri.hostname, address)
                    self.assertEqual(uri.port, node["server_port"])
                    self.assertEqual(parse_qs(uri.query)["sni"], [node["tls"]["server_name"]])
                    self.assertEqual(parse_qs(uri.query)["serviceName"], [node["transport"]["service_name"]])


if __name__ == "__main__":
    unittest.main()
