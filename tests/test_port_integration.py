"""Compose real inventory, subscription and policy adapters with inert fixtures."""
import base64
import copy
import datetime as dt
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shell"))
from port_manager.core import inventory
from port_manager.policies import PolicyError, PolicyManager
from port_manager.rate_limits import RateLimiter
from port_manager.subscriptions import SubscriptionError, stage_subscriptions


class ComposedPortAdaptersTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "installed"
        self.root.mkdir()

    def put(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
        return destination

    def fixture(self, kind):
        core = "xray" if kind.startswith("xray") else "sing-box"
        protocol = "hysteria2" if "hysteria2" in kind else "tuic" if "tuic" in kind else "vless"
        transport = "xhttp" if "xhttp" in kind else "tcp"
        users = [{"name": name + "-" + protocol, "uuid": "test-id-" + name, "password": "test-pass-" + name}
                 for name in ("alice", "bob")]
        filename = ("06_hysteria2_inbounds.json" if protocol == "hysteria2" else
                    "09_tuic_inbounds.json" if protocol == "tuic" else
                    "12_VLESS_XHTTP_inbounds.json" if transport == "xhttp" else
                    "07_VLESS_vision_reality_inbounds.json")
        if core == "xray":
            inbound = {"tag": "VLESSReality", "protocol": "vless", "listen": "::", "port": 443,
                       "settings": {"clients": [{"email": user["name"], "id": user["uuid"]} for user in users], "fallbacks": []},
                       "streamSettings": {"security": "reality", "network": transport}}
            inbounds = [inbound]
            if kind == "xray-reality-forward":
                inbound.pop("tag")
                inbound.update(listen="127.0.0.1", port=45987)
                inbounds.insert(0, {"tag": "dokodemo-in-VLESSReality", "protocol": "dokodemo-door", "port": 443,
                                    "settings": {"address": "127.0.0.1", "port": 45987, "network": "tcp"}})
            fragment = "xray/conf/" + filename
        else:
            inbound = {"tag": "test-" + protocol, "type": protocol, "listen": "::", "listen_port": 443,
                       "users": [{key: value for key, value in user.items() if key == "name" or
                                  (key == "uuid" and protocol in ("vless", "tuic")) or
                                  (key == "password" and protocol in ("hysteria2", "tuic"))} for user in users],
                       "tls": {"enabled": True}}
            if protocol == "vless":
                inbound["tls"]["reality"] = {"enabled": True}
            inbounds = [inbound]
            fragment = "sing-box/conf/config/" + filename
        self.put(fragment, json.dumps({"inbounds": inbounds}))
        self.put("subscribe_local/subscribeSalt", "same-salt\n")
        for user in users:
            bundle = user["name"].split("-", 1)[0]
            digest = hashlib.md5((bundle + "same-salt\n").encode()).hexdigest()
            auth = user["uuid"] if protocol == "vless" else user["password"]
            if protocol == "tuic":
                auth = user["uuid"] + ":" + user["password"]
            query = "security=reality&type=" + transport if protocol == "vless" else "sni=example.test"
            raw = f"{protocol}://{auth}@203.0.113.9:443?{query}#{user['name']}\n"
            clash = {"type": protocol, "name": user["name"], "server": "203.0.113.9", "port": 443}
            sing = {"type": protocol, "tag": user["name"], "server": "203.0.113.9", "server_port": 443}
            for key in ("uuid", "password"):
                if (key == "uuid" and protocol in ("vless", "tuic")) or (key == "password" and protocol in ("hysteria2", "tuic")):
                    clash[key] = sing[key] = user[key]
            if protocol == "vless":
                clash.update(network=transport, **{"reality-opts": {"public-key": "public"}})
                sing["tls"] = {"enabled": True, "reality": {"enabled": True}}
            nodes = [] if transport == "xhttp" else [sing]
            self.put("subscribe_local/default/" + bundle, raw)
            self.put("subscribe/default/" + digest, base64.b64encode(raw.encode()).decode())
            self.put("subscribe_local/clashMeta/" + bundle, yaml.safe_dump([clash]))
            self.put("subscribe/clashMeta/" + digest, yaml.safe_dump({"proxies": [clash]}))
            self.put("subscribe/clashMetaProfiles/" + digest, yaml.safe_dump({
                "proxy-providers": {"original": {"type": "http", "url": "https://sub.test/s/clashMeta/" + digest}},
                "proxy-groups": [{"name": "select", "type": "select", "use": ["original"]}]}))
            self.put("subscribe_local/sing-box/" + bundle, json.dumps(nodes))
            self.put("subscribe/sing-box_profiles/" + digest, json.dumps(nodes))
            self.put("subscribe/sing-box/" + digest, json.dumps({"outbounds": nodes}))
        return next(entry for entry in inventory(self.root) if entry["kind"] == kind)

    def test_all_advertised_inventory_kinds_compose_and_keep_identity_after_change(self):
        kinds = ("xray-reality-forward", "xray-reality", "xray-xhttp", "sing-box-reality",
                 "sing-box-hysteria2", "sing-box-tuic")
        original_root = self.root
        for kind in kinds:
            with self.subTest(kind=kind):
                self.root = original_root / kind
                self.root.mkdir()
                entry = self.fixture(kind)
                self.assertTrue(entry["supported"], entry["reason"])
                policies = PolicyManager(self.root, clock=lambda: dt.datetime(2026, 9, 8, tzinfo=dt.timezone.utc))
                changes = policies.preview([entry], {"quota_bytes": 1_000_000_000, "expires_at": "2026-10-01"})
                self.assertEqual(changes[0]["new"]["mapping"]["port_id"], entry["port_id"])
                self.assertEqual(changes[0]["new"]["expires_at"], "2026-10-01T16:00:00+00:00")
                self.assertEqual(RateLimiter(self.root)._entry(entry)["port_id"], entry["port_id"])
                self.assertFalse((self.root / "port-manager").exists(), "preview must not enroll or write state")
                original = json.loads((self.root / entry["file"]).read_text())
                pairs = stage_subscriptions(self.root, entry, 8444, self.root / "private-stage")
                self.assertEqual(len(pairs), 16)
                for path, candidate in pairs:
                    path.write_bytes(candidate.read_bytes())
                changed = copy.deepcopy(original)
                field = "port" if entry["core"] == "xray" else "listen_port"
                changed["inbounds"][entry["index"]][field] = 8444
                self.put(entry["file"], json.dumps(changed))
                refreshed = next(row for row in inventory(self.root) if row["port_id"] == entry["port_id"])
                self.assertEqual(refreshed["port"], 8444)
                self.assertTrue(refreshed["supported"])
                source = entry["source_index"]
                accounts_field = "settings" if entry["core"] == "xray" else "users"
                self.assertEqual(original["inbounds"][source][accounts_field], changed["inbounds"][source][accounts_field])
                policies.preview([refreshed], {"paused": True})

    def test_internal_reality_target_cannot_receive_independent_policy(self):
        self.fixture("xray-reality-forward")
        internal = next(row for row in inventory(self.root) if row["kind"] == "internal")
        with self.assertRaises(PolicyError):
            PolicyManager(self.root).preview([internal], {"quota_bytes": 5_000_000})

    def test_account_changed_since_subscription_generation_blocks_migration(self):
        entry = self.fixture("sing-box-tuic")
        document = json.loads((self.root / entry["file"]).read_text())
        document["inbounds"][0]["users"][1]["password"] = "new-account-password"
        self.put(entry["file"], json.dumps(document))
        refreshed = next(row for row in inventory(self.root) if row["port_id"] == entry["port_id"])
        self.assertTrue(refreshed["supported"])
        with self.assertRaises(SubscriptionError):
            stage_subscriptions(self.root, refreshed, 8444, self.root / "private-stage")
        self.assertFalse((self.root / "private-stage").exists())


if __name__ == "__main__":
    unittest.main()
