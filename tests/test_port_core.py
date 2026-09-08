"""Host-free transaction/fault-injection checks. No real service is invoked."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from shell.port_manager import core


XRAY = "xray/conf/07_VLESS_vision_reality_inbounds.json"
SB = "sing-box/conf/config/06_hysteria2_inbounds.json"


def put(root, relative, value):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


def reality(port=443):
    return {"inbounds": [{"tag": "dokodemo-in-VLESSReality", "port": port,
                          "protocol": "dokodemo-door",
                          "settings": {"address": "127.0.0.1", "port": 45987, "network": "tcp"}},
                         {"listen": "127.0.0.1", "port": 45987, "protocol": "vless",
                          "settings": {"clients": [{"id": "user-one", "email": "alpha"},
                                                    {"id": "user-two", "email": "beta"}], "fallbacks": []},
                          "streamSettings": {"network": "tcp", "security": "reality",
                                             "realitySettings": {"privateKey": "private", "shortIds": ["", "abcdef"]}}}],
            "routing": {"rules": [{"port": "443", "outboundTag": "unchanged"}]}}


class FakeRunner:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.restarts = 0
        self.fail_restart = False
        self.extra_listeners = []
        self.wrong_pid = False
        self.narrow = False
        self.ufw = "Status: inactive\n"
        self.rules = []
        self.nft = {"nftables": []}
        self.custom_args = ""
        self.bad_download_after_restart = False
        self.sync()

    def sync(self):
        self.entries = core.inventory(self.root)

    def run(self, args, input=None):
        args = list(map(str, args))
        self.calls.append(args)
        out, rc = "", 0
        name = Path(args[0]).name
        if name == "systemctl" and args[1] == "show":
            which = args[2].split(".")[0]
            conf = self.root / ("xray/conf" if which == "xray" else "sing-box/conf/config.json")
            flag = "-confdir" if which == "xray" else "-c"
            binary = self.root / which / which
            out = ("ActiveState=active\nMainPID=222\nFragmentPath=/etc/systemd/system/" + which + ".service\n"
                   + "ExecStart={ path=" + str(binary) + "; argv[]=" + str(binary) + " run " + flag + " "
                   + str(conf) + self.custom_args + " ; ignore_errors=no; }\n")
        elif name == "systemctl" and args[1] == "restart":
            self.restarts += 1
            if self.fail_restart and self.restarts == 1:
                rc = 1
            else:
                self.sync()
        elif name == "systemctl" and args[1] == "stop":
            self.entries = [entry for entry in self.entries if entry["core"] != args[2].split(".")[0]]
        elif name == "systemctl" and args[1] == "is-active":
            rc = 0 if args[2] == "nginx.service" else 3
        elif name == "ss":
            records = self.entries + self.extra_listeners
            for e in records:
                if e["core"] not in ("xray", "sing-box") or not isinstance(e["port"], int):
                    continue
                listen = "127.0.0.1" if self.narrow else e["listen"]
                address = "[" + listen + "]" if ":" in listen else listen
                for proto in e["protocols"]:
                    pid = 999 if self.wrong_pid and self.restarts == 1 else 222
                    out += f'{proto} LISTEN 0 512 {address}:{e["port"]} *:* users:(("xray",pid={pid},fd=3))\n'
        elif name == "curl":
            relative = args[-1].split("/s/", 1)[1]
            out = "unrelated cached document" if self.bad_download_after_restart and self.restarts else (self.root / "subscribe" / relative).read_text()
        elif name == "ufw":
            if args[1] == "status":
                out = self.ufw + "\n".join(self.rules)
            elif args[1] == "allow":
                self.rules.append(args[-1])
            elif args[1:3] == ["--force", "delete"]:
                if args[-1] in self.rules:
                    self.rules.remove(args[-1])
                else:
                    rc = 1
        elif name == "firewall-cmd":
            rc = 127
        elif name == "nft":
            out = json.dumps(self.nft)
        elif name in ("iptables-save", "ip6tables-save"):
            out = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        elif name == "sing-box" and args[1] == "merge":
            doc = {"inbounds": []}
            for p in sorted(Path(args[4]).glob("*.json")):
                doc["inbounds"] += core._json(p).get("inbounds", [])
            Path(args[2]).write_text(json.dumps(doc))
        elif name not in ("xray", "sing-box"):
            raise AssertionError("Unexpected host command: " + repr(args))
        return subprocess.CompletedProcess(args, rc, out, "secret stderr must never be logged")


class CoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.original = reality()
        put(self.root, XRAY, self.original)
        put(self.root, "subscribe/default/local.json", {"port": 443, "users": ["one", "two"]})
        nginx = self.root / "nginx/subscribe.conf"
        nginx.parent.mkdir()
        nginx.write_text("server { listen 8080; server_name example.test; location ~ ^/s/(clashMeta|default|clashMetaProfiles|sing-box|sing-box_profiles)/(.*) { alias " + str(self.root / "subscribe") + "/$1/$2; } }")
        self.runner = FakeRunner(self.root)
        self.manager = core.Manager(self.root, runner=self.runner, subscription_stager=self.stage)
        self.id = self.manager.list()[0]["port_id"]

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, root, entry, port, stage):
        stage.mkdir(parents=True, exist_ok=True)
        candidate = stage / "local.json"
        doc = json.loads((root / "subscribe/default/local.json").read_text())
        doc["port"] = port
        candidate.write_text(json.dumps(doc))
        return [(root / "subscribe/default/local.json", candidate)]

    def test_input_boundaries(self):
        for value in ("", "1,2", "1-2", "+22", " 22", "22\n", "65536", "0", "00", True, 1.2, "$(id)"):
            with self.subTest(value=value), self.assertRaises(core.PortError):
                core.port_input(value)
        self.assertEqual(core.port_input("00022"), 22)

    def test_inventory_reality_pair_and_identity(self):
        entries = self.manager.list()
        self.assertTrue(entries[0]["supported"])
        self.assertEqual(entries[0]["source_index"], 1)
        self.assertFalse(entries[1]["supported"])
        doc = reality(444)
        put(self.root, XRAY, doc)
        self.assertEqual(self.id, self.manager.list()[0]["port_id"])

    def test_missing_tag_custom_and_cdn_denied(self):
        doc = {"inbounds": [{"tag": "XHTTP", "port": 8443, "protocol": "vless",
                             "streamSettings": {"network": "xhttp", "security": "reality", "xhttpSettings": {"extra": {"downloadSettings": {}}}}}]}
        put(self.root, "xray/conf/12_VLESS_XHTTP_inbounds.json", doc)
        self.assertFalse([x for x in self.manager.list() if x["tag"] == "XHTTP"][0]["supported"])
        doc["inbounds"][0]["streamSettings"].pop("xhttpSettings")
        put(self.root, "xray/conf/custom.json", doc)
        self.assertFalse([x for x in self.manager.list() if x["file"].endswith("custom.json")][0]["supported"])

    def test_duplicate_json_key_denies_inventory(self):
        (self.root / XRAY).write_text('{"inbounds": [], "inbounds": []}')
        self.assertEqual(self.manager.list()[0]["kind"], "unreadable")

    def test_invalid_nested_objects_are_readonly(self):
        for key in ("settings", "streamSettings", "tls"):
            doc = reality()
            doc["inbounds"][0][key] = None
            put(self.root, XRAY, doc)
            self.assertEqual(self.manager.list()[0]["kind"], "unreadable")

    def test_same_port_is_noop(self):
        result = self.manager.change(self.id, 443)
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(self.runner.calls, [])
        self.assertFalse(self.manager.state.exists())

    def test_change_preserves_all_nonport_data(self):
        self.manager.change(self.id, 8443)
        actual = core._json(self.root / XRAY)
        actual["inbounds"][0]["port"] = 443
        self.assertEqual(actual, self.original)
        self.assertEqual(core._json(self.root / "subscribe/default/local.json")["port"], 8443)
        self.assertEqual(self.runner.restarts, 1)
        self.assertTrue(all(call[:2] != ["systemctl", "restart"] or call[2] == "xray.service" for call in self.runner.calls))
        self.assertEqual(self.manager.history()[-1]["status"], "committed")

    def test_conflict_and_transport_distinction(self):
        self.runner.extra_listeners = [{"core": "xray", "port": 8443, "listen": "::", "protocols": ["udp"]}]
        self.assertFalse(self.manager.check_port(8443, ["tcp"]))
        self.assertTrue(self.manager.check_port(8443, ["udp"]))
        self.runner.extra_listeners[0]["protocols"] = ["tcp"]
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(self.runner.restarts, 0)

    def test_restart_failure_compensates(self):
        self.runner.fail_restart = True
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(core._json(self.root / "subscribe/default/local.json")["port"], 443)
        self.assertEqual(self.manager.history()[-1]["status"], "rolled_back")
        self.assertEqual(self.runner.restarts, 2)

    def test_wrong_process_compensates(self):
        self.runner.wrong_pid = True
        with mock.patch.object(core.time, "sleep"), self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(self.manager.history()[-1]["status"], "rolled_back")

    def test_wildcard_cannot_be_verified_by_loopback(self):
        self.runner.narrow = True
        self.assertEqual(self.manager.listener_status(self.manager.list()[0])["status"], "unverified")

    def test_custom_service_args_rejected(self):
        self.runner.custom_args = " -config /tmp/other.json"
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.restarts)

    def test_missing_subscription_fails_before_changes(self):
        self.manager.subscription_stager = lambda *args: []
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(self.runner.restarts, 0)

    def test_missing_subscription_service_is_preflight_failure(self):
        (self.root / "nginx/subscribe.conf").unlink()
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.restarts)
        self.assertEqual(core._json(self.root / XRAY), self.original)

    def test_wrong_alias_is_preflight_failure(self):
        path = self.root / "nginx/subscribe.conf"
        path.write_text(path.read_text().replace("/subscribe/", "/other/"))
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.restarts)

    def test_download_publication_failure_restores_service_and_files(self):
        self.runner.bad_download_after_restart = True
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(self.runner.restarts, 2)
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(core._json(self.root / "subscribe/default/local.json")["port"], 443)
        self.assertEqual(self.manager.history()[-1]["status"], "rolled_back")

    def test_deferred_recovery_on_other_core_blocks_changes(self):
        with mock.patch.object(self.manager, "recover", return_value=[{"id": "other-core", "status": "restored_awaiting_start"}]), self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.calls)

    def test_stale_account_edit_is_retained(self):
        def editing_stage(*args):
            candidates = self.stage(*args)
            doc = core._json(self.root / XRAY)
            doc["inbounds"][1]["settings"]["clients"].append({"id": "later", "email": "later"})
            put(self.root, XRAY, doc)
            return candidates
        self.manager.subscription_stager = editing_stage
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(len(core._json(self.root / XRAY)["inbounds"][1]["settings"]["clients"]), 3)
        self.assertFalse(self.runner.restarts)

    def test_salt_edit_is_retained_and_blocks_commit(self):
        put(self.root, "subscribe_local/subscribeSalt", "old")
        def editing_stage(*args):
            result = self.stage(*args)
            put(self.root, "subscribe_local/subscribeSalt", "new")
            return result
        self.manager.subscription_stager = editing_stage
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.restarts)

    def test_interruption_recovered_on_next_entry(self):
        with mock.patch.object(self.manager, "_activate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.manager.change(self.id, 8443)
        self.assertEqual(core._json(self.root / XRAY)["inbounds"][0]["port"], 8443)
        self.manager.recover()
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(self.manager.history()[-1]["status"], "rolled_back")

    def test_external_edit_during_recovery_blocks_writes(self):
        with mock.patch.object(self.manager, "_activate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.manager.change(self.id, 8443)
        doc = core._json(self.root / XRAY)
        doc["inbounds"][1]["settings"]["clients"].append({"id": "later"})
        put(self.root, XRAY, doc)
        with self.assertRaises(core.PortError):
            self.manager.recover()
        self.assertEqual(self.manager.history()[-1]["status"], "needs_recovery")

    def test_boot_recovery_defers_runtime_and_finishes_in_daemon(self):
        self.runner.ufw = "Status: active\n"
        with mock.patch.object(self.manager, "_activate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.manager.change(self.id, 8443)
        self.runner.calls.clear()
        self.manager.recover(start_services=False)
        self.assertEqual(core._json(self.root / XRAY), self.original)
        self.assertEqual(self.manager.history()[-1]["status"], "restored_awaiting_start")
        self.assertFalse(any(call[:2] == ["systemctl", "restart"] for call in self.runner.calls))
        self.assertTrue(self.runner.rules, "new rules remain until daemon verifies recovery")
        self.manager.recover()
        self.assertEqual(self.manager.history()[-1]["status"], "rolled_back")
        self.assertFalse(self.runner.rules)

    def test_manual_rollback_preserves_later_accounts(self):
        self.manager.change(self.id, 8443)
        doc = core._json(self.root / XRAY)
        doc["inbounds"][1]["settings"]["clients"].append({"id": "later", "email": "later"})
        put(self.root, XRAY, doc)
        self.runner.sync()
        self.manager.rollback()
        actual = core._json(self.root / XRAY)
        self.assertEqual(actual["inbounds"][0]["port"], 443)
        self.assertEqual(len(actual["inbounds"][1]["settings"]["clients"]), 3)
        with self.assertRaises(core.PortError):
            self.manager.rollback()

    def test_reused_ufw_rule_is_never_mutated(self):
        self.runner.ufw = "Status: active\n8443/tcp ALLOW Anywhere\n8443/tcp (v6) ALLOW Anywhere (v6)\n"
        self.runner.fail_restart = True
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(any(c[0] == "ufw" and c[1] != "status" for c in self.runner.calls))

    def test_new_ufw_rule_removed_on_rollback(self):
        self.runner.ufw = "Status: active\n"
        self.runner.fail_restart = True
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(self.runner.rules, [])

    def test_unknown_native_filter_is_readonly(self):
        self.runner.nft = {"nftables": [{"chain": {"table": "foreign", "name": "input", "policy": "drop"}}]}
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertFalse(self.runner.restarts)

    def test_quota_migration_never_restores_ledger(self):
        class Policies:
            used = 10
            port = 443
            def before_port_change(s, entry):
                s.used += 3
            def after_port_change(s, entry, port):
                s.used += 2
                s.port = port
        policies = Policies()
        self.manager.policies = policies
        self.runner.fail_restart = True
        with self.assertRaises(core.PortError):
            self.manager.change(self.id, 8443)
        self.assertEqual(policies.port, 443)
        self.assertEqual(policies.used, 17)

    def test_singbox_fragment_and_merged_file_commit(self):
        doc = {"inbounds": [{"tag": "hysteria2", "type": "hysteria2", "listen": "::", "listen_port": 8443,
                             "users": [{"name": "one", "password": "pw"}], "tls": {"enabled": True}}]}
        put(self.root, SB, doc)
        put(self.root, "sing-box/conf/config.json", doc)
        self.runner.sync()
        entry = next(x for x in self.manager.list() if x["core"] == "sing-box")
        self.manager.change(entry["port_id"], 8444)
        self.assertEqual(core._json(self.root / SB)["inbounds"][0]["listen_port"], 8444)
        self.assertEqual(core._json(self.root / "sing-box/conf/config.json")["inbounds"][0]["listen_port"], 8444)
        self.assertTrue(any(x[:3] == ["systemctl", "restart", "sing-box.service"] for x in self.runner.calls))

    def direct_tls(self):
        put(self.root, "xray/conf/02_VLESS_TCP_inbounds.json", {"inbounds": [{
            "tag": "VLESSTCP", "protocol": "vless", "port": 9443,
            "settings": {"clients": [{"id": "unchanged-id"}], "fallbacks": []},
            "streamSettings": {"network": "tcp", "security": "tls"}}]})
        self.runner.sync()
        return next(entry for entry in self.manager.list() if entry["tag"] == "VLESSTCP")

    def test_nondefault_additional_tcp_add_delete(self):
        target = self.direct_tls()
        self.manager.additional_add(target["port_id"], 9444)
        added = self.manager.additional_list()
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["target_port"], 9443)
        self.manager.additional_delete(added[0]["port_id"])
        self.assertFalse(self.manager.additional_list())
        self.assertEqual(core._json(self.root / "subscribe/default/local.json")["port"], 443)

    def test_additional_hysteria_companion_added_and_deleted_together(self):
        target = self.direct_tls()
        doc = {"inbounds": [{"tag": "hysteria2", "type": "hysteria2", "listen": "::", "listen_port": 9445,
                             "users": [{"name": "one", "password": "pw"}], "tls": {"enabled": True}}]}
        put(self.root, SB, doc)
        put(self.root, "sing-box/conf/config.json", doc)
        self.runner.sync()
        self.manager.additional_add(target["port_id"], 9444)
        added = self.manager.additional_list()
        self.assertEqual(len(added), 2)
        self.assertEqual(sorted(entry["protocols"] for entry in added), [["tcp"], ["udp"]])
        tcp = next(entry for entry in added if entry["protocols"] == ["tcp"])
        self.manager.additional_delete(tcp["port_id"])
        self.assertFalse(self.manager.additional_list())
        self.assertEqual(core._json(self.root / SB), doc)

    def test_default_additional_entry_is_protected(self):
        target = self.direct_tls()
        self.manager.additional_add(target["port_id"], 9444)
        path = self.root / "xray/conf/02_dokodemodoor_inbounds_9444.json"
        path.rename(path.with_name("02_dokodemodoor_inbounds_9444_default.json"))
        entry = self.manager.additional_list()[0]
        with self.assertRaises(core.PortError):
            self.manager.additional_delete(entry["port_id"])

    def test_base64_subscription_reference_prevents_dangling_extra(self):
        import base64
        target = self.direct_tls()
        self.manager.additional_add(target["port_id"], 9444)
        path = self.root / "subscribe/default/local.json"
        path.write_text(base64.b64encode(b"vless://example@localhost:9444?security=tls").decode())
        entry = self.manager.additional_list()[0]
        with self.assertRaises(core.PortError):
            self.manager.additional_delete(entry["port_id"])
        self.assertTrue(self.manager.additional_list())


if __name__ == "__main__":
    unittest.main()
