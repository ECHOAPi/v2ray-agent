import base64
import copy
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shell"))
from port_manager.subscriptions import SubscriptionError, stage_subscriptions


class SubscriptionStageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "installed"
        self.root.mkdir()
        self.stage = Path(self.tmp.name) / "stage"
        self.salt = "unchanged-salt"
        self.entry = {"core": "xray", "file": "xray/conf/reality.json", "index": 0,
                      "source_index": 1, "port": 443, "kind": "xray-reality-forward"}
        self.accounts = [
            {"email": "alice-VLESS_Reality", "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
            {"email": "bob-VLESS_Reality", "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
        ]
        self.write(self.entry["file"], json.dumps({"inbounds": [
            {"protocol": "dokodemo-door", "port": 443, "settings": {"address": "127.0.0.1", "port": 45987}},
            {"protocol": "vless", "port": 45987, "settings": {"clients": self.accounts},
             "streamSettings": {"security": "reality", "network": "tcp"}},
        ]}))
        self.write("subscribe_local/subscribeSalt", self.salt + "\n")
        for account in self.accounts:
            self.bundle(account)

    def write(self, relative, value):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
        return target

    def digest(self, bundle):
        return hashlib.md5((bundle + self.salt + "\n").encode()).hexdigest()

    def bundle(self, account, protocol="vless", transport="tcp"):
        name = account.get("email", account.get("name"))
        user = name.split("-", 1)[0]
        token = self.digest(user)
        credentials = account.get("id", account.get("uuid", account.get("password")))
        if protocol == "tuic":
            credentials += ":" + account["password"]
        query = "security=reality&type=" + transport if protocol == "vless" else "sni=example.test"
        uri = f"{protocol}://{credentials}@[2001:db8::1]:443?{query}#{name}\n"
        remote_uri = "trojan://remote-pass@remote.test:443?security=tls#remote\n"
        self.write(f"subscribe_local/default/{user}", uri)
        self.write(f"subscribe/default/{token}", base64.b64encode((uri + remote_uri).encode()).decode() + "\n")
        node = {"name": name, "type": protocol, "server": "2001:db8::1", "port": 443}
        if protocol in ("vless", "tuic"):
            node["uuid"] = account.get("id", account.get("uuid"))
        if protocol in ("hysteria2", "tuic"):
            node["password"] = account["password"]
        if protocol == "vless":
            node.update({"network": transport, "reality-opts": {"public-key": "public", "short-id": "abcd"}})
        remote = {"name": "remote", "type": "trojan", "server": "remote.test", "port": 443, "password": "remote-pass"}
        self.write(f"subscribe_local/clashMeta/{user}", yaml.safe_dump([node]))
        self.write(f"subscribe/clashMeta/{token}", yaml.safe_dump({"proxies": [node, remote]}))
        self.write(f"subscribe/clashMetaProfiles/{token}", yaml.safe_dump({
            "mixed-port": 7890, "proxy-providers": {"stable_provider": {
                "type": "http", "url": f"https://sub.example.test:8443/s/clashMeta/{token}", "path": "./stable_provider.yaml"}},
            "proxy-groups": [{"name": "select", "type": "select", "use": ["stable_provider"]}],
        }))
        sing = {"tag": name, "type": protocol, "server": node["server"], "server_port": 443}
        for key in ("uuid", "password"):
            if key in node:
                sing[key] = node[key]
        if protocol == "vless":
            sing["tls"] = {"enabled": True, "reality": {"enabled": True, "public_key": "public"}}
            if transport != "tcp":
                sing["transport"] = {"type": transport}
        remote_sing = {"tag": "remote", "type": "trojan", "server": "remote.test", "server_port": 443, "password": "remote-pass"}
        singles = [sing, remote_sing] if transport != "xhttp" else [remote_sing]
        self.write(f"subscribe_local/sing-box/{user}", json.dumps(singles))
        self.write(f"subscribe/sing-box_profiles/{token}", json.dumps(singles))
        self.write(f"subscribe/sing-box/{token}", json.dumps({"outbounds": [
            {"type": "selector", "tag": "select", "outbounds": [n["tag"] for n in singles]}, *singles
        ], "route": {"final": "select"}}))

    def candidates(self):
        return {str(path.relative_to(self.root)): candidate.read_text()
                for path, candidate in stage_subscriptions(self.root, self.entry, 8444, self.stage)}

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}

    def test_complete_two_user_forwarded_reality_preserves_originals_and_remote_nodes(self):
        before = self.snapshot()
        candidates = self.candidates()
        self.assertEqual(len(candidates), 16)
        self.assertEqual(before, self.snapshot())
        for user in ("alice", "bob"):
            token = self.digest(user)
            lines = base64.b64decode(candidates[f"subscribe/default/{token}"]).decode().splitlines()
            self.assertIn("@[2001:db8::1]:8444?", lines[0])
            self.assertEqual(lines[1], "trojan://remote-pass@remote.test:443?security=tls#remote")
            self.assertEqual(candidates[f"subscribe/clashMetaProfiles/{token}"].encode(), before[f"subscribe/clashMetaProfiles/{token}"])
            clash = yaml.safe_load(candidates[f"subscribe/clashMeta/{token}"])["proxies"]
            self.assertEqual(clash[0]["port"], 8444)
            self.assertEqual(clash[1]["port"], 443)
            full_sing = json.loads(candidates[f"subscribe/sing-box/{token}"])
            self.assertEqual(full_sing["outbounds"][1]["server_port"], 8444)
            self.assertEqual(full_sing["outbounds"][2]["server_port"], 443)
            self.assertEqual(full_sing["route"], {"final": "select"})

    def test_missing_second_user_output_aborts_before_candidate_write(self):
        (self.root / "subscribe" / "sing-box" / self.digest("bob")).unlink()
        before = self.snapshot()
        with self.assertRaises(SubscriptionError):
            self.candidates()
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.stage.exists())

    def test_stale_published_target_credentials_aborts(self):
        path = self.root / "subscribe" / "clashMeta" / self.digest("bob")
        document = yaml.safe_load(path.read_text())
        document["proxies"][0]["uuid"] = "different"
        path.write_text(yaml.safe_dump(document))
        with self.assertRaisesRegex(SubscriptionError, "凭据"):
            self.candidates()
        self.assertFalse(self.stage.exists())

    def test_same_credentials_at_different_remote_host_unchanged(self):
        token = self.digest("alice")
        path = self.root / "subscribe" / "clashMeta" / token
        document = yaml.safe_load(path.read_text())
        remote = copy.deepcopy(document["proxies"][0])
        remote["name"] += "_remote"
        remote["server"] = "elsewhere.test"
        document["proxies"].append(remote)
        path.write_text(yaml.safe_dump(document))
        changed = yaml.safe_load(self.candidates()[f"subscribe/clashMeta/{token}"])
        self.assertEqual(changed["proxies"][-1], remote)

    def test_duplicate_target_aborts(self):
        path = self.root / "subscribe" / "sing-box_profiles" / self.digest("alice")
        nodes = json.loads(path.read_text())
        nodes.append(copy.deepcopy(nodes[0]))
        path.write_text(json.dumps(nodes))
        with self.assertRaises(SubscriptionError):
            self.candidates()

    def test_wrong_provider_download_reference_aborts(self):
        path = self.root / "subscribe" / "clashMetaProfiles" / self.digest("alice")
        document = yaml.safe_load(path.read_text())
        document["proxy-providers"]["stable_provider"]["url"] = "https://elsewhere.test/s/clashMeta/wrong"
        path.write_text(yaml.safe_dump(document))
        with self.assertRaisesRegex(SubscriptionError, "provider"):
            self.candidates()

    def test_xhttp_does_not_invent_unsupported_sing_box_nodes(self):
        config = json.loads((self.root / self.entry["file"]).read_text())
        config["inbounds"][1]["streamSettings"]["network"] = "xhttp"
        self.write(self.entry["file"], json.dumps(config))
        for account in self.accounts:
            self.bundle(account, transport="xhttp")
        before = self.snapshot()
        candidates = self.candidates()
        for relative, value in candidates.items():
            if "/sing-box" in relative:
                self.assertEqual(value.encode(), before[relative])
        self.assertIn(":8444?", candidates["subscribe_local/default/alice"])

    def test_xhttp_with_no_sing_box_generation_is_supported(self):
        config = json.loads((self.root / self.entry["file"]).read_text())
        config["inbounds"][1]["streamSettings"]["network"] = "xhttp"
        self.write(self.entry["file"], json.dumps(config))
        for account in self.accounts:
            self.bundle(account, transport="xhttp")
        for folder in ("subscribe_local/sing-box", "subscribe/sing-box", "subscribe/sing-box_profiles"):
            shutil.rmtree(self.root / folder)
        self.assertEqual(len(self.candidates()), 10)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "upstream generator requires jq and bash")
    def test_actual_upstream_subscription_generators_and_full_templates(self):
        repository = Path(__file__).resolve().parents[1]
        install = (repository / "install.sh").read_text()
        blocks = []
        for function in ("defaultBase64Code", "clashMetaConfig"):
            match = re.search(r"(?ms)^" + function + r"\(\) \{\n.*?^\}", install)
            self.assertIsNotNone(match)
            blocks.append(match.group().replace("/etc/v2ray-agent", str(self.root)))
        for directory in ("default", "clashMeta", "sing-box"):
            for path in (self.root / "subscribe_local" / directory).iterdir():
                path.unlink()
        script = "\n".join(blocks) + "\n" + "\n".join([
            "echoContent() { :; }", "getPublicIP() { echo 203.0.113.10; }",
            "coreInstallType=1", "currentHost=example.test", "xrayVLESSRealityServerName=example.test",
            "currentRealityPublicKey=public", "currentRealityMldsa65Verify=pqv",
            "subscribeSalt=" + shlex.quote(self.salt),
        ]) + "\n"
        for account in self.accounts:
            user = account["email"].split("-", 1)[0]
            token = self.digest(user)
            script += "defaultBase64Code vlessReality 443 " + shlex.quote(account["email"]) + " " + shlex.quote(account["id"]) + "\n"
            script += "clashMetaConfig " + shlex.quote("https://sub.example.test:8443/s/clashMeta/" + token) + " " + shlex.quote(token) + "\n"
        process = subprocess.run(["bash"], input=script, text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, "isolated upstream generator failed")
        for account in self.accounts:
            user = account["email"].split("-", 1)[0]
            token = self.digest(user)
            raw = (self.root / f"subscribe_local/default/{user}").read_bytes()
            self.write(f"subscribe/default/{token}", base64.b64encode(raw).decode() + "\n")
            local_clash = (self.root / f"subscribe_local/clashMeta/{user}").read_text()
            self.write(f"subscribe/clashMeta/{token}", "proxies:\n" + local_clash)
            local_sing = (self.root / f"subscribe_local/sing-box/{user}").read_text()
            self.write(f"subscribe/sing-box_profiles/{token}", local_sing)
            nodes = json.loads(local_sing)
            full = json.loads((repository / "documents/sing-box.json").read_text())
            for outbound in full["outbounds"]:
                if "outbounds" in outbound:
                    outbound["outbounds"] += [node["tag"] for node in nodes]
            full["outbounds"] += nodes
            self.write(f"subscribe/sing-box/{token}", json.dumps(full))
        candidates = self.candidates()
        self.assertEqual(len(candidates), 16)
        self.assertIn("@203.0.113.10:8444?", candidates["subscribe_local/default/alice"])

    def test_tuic_updates_uuid_password_pair(self):
        self.entry.update({"core": "sing-box", "file": "sing-box/conf/config/tuic.json", "index": 0, "source_index": 0})
        account = {"name": "alice-TUIC", "uuid": "a1", "password": "secret"}
        self.write(self.entry["file"], json.dumps({"inbounds": [{"type": "tuic", "listen_port": 443, "users": [account]}]}))
        self.bundle(account, protocol="tuic")
        changed = self.candidates()
        self.assertIn("tuic://a1:secret@[2001:db8::1]:8444?", changed["subscribe_local/default/alice"])
        self.assertEqual(len(changed), 8)

    def test_hysteria2_hopping_aborts(self):
        self.entry.update({"core": "sing-box", "file": "sing-box/conf/config/hy2.json", "index": 0, "source_index": 0})
        account = {"name": "alice-HY2", "password": "secret"}
        self.write(self.entry["file"], json.dumps({"inbounds": [{"type": "hysteria2", "listen_port": 443, "users": [account]}]}))
        self.bundle(account, protocol="hysteria2")
        path = self.root / "subscribe_local/default/alice"
        path.write_text(path.read_text().replace("?", "?mport=400-500&"))
        with self.assertRaisesRegex(SubscriptionError, "跳跃"):
            self.candidates()

    def test_duplicate_yaml_keys_rejected_without_secret_echo(self):
        self.write("subscribe_local/clashMeta/alice", "- type: vless\n  type: trojan\n  password: private-secret\n")
        with self.assertRaises(SubscriptionError) as raised:
            self.candidates()
        self.assertNotIn("private-secret", str(raised.exception))

    def test_symlink_output_rejected(self):
        path = self.root / "subscribe" / "default" / self.digest("alice")
        path.unlink()
        path.symlink_to(self.root / "subscribe_local/default/alice")
        with self.assertRaises(SubscriptionError):
            self.candidates()

    def test_noop_does_not_require_subscription_initialization(self):
        (self.root / "subscribe_local/subscribeSalt").unlink()
        self.assertEqual(stage_subscriptions(self.root, self.entry, 443, self.stage), [])


if __name__ == "__main__":
    unittest.main()
