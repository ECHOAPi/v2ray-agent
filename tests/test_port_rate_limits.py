"""Contract tests; FakeKernel never runs ip/tc or changes host networking."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("port_rates", Path(__file__).parents[1] /
                                            "shell/port_manager/rate_limits.py")
rates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rates)


class FakeKernel:
    def __init__(self):
        self.links = [{"ifname": "lo", "flags": ["UP", "LOOPBACK"], "addr_info": []},
                      {"ifname": "eth0", "flags": ["UP", "LOWER_UP"], "addr_info": [
                          {"family": "inet", "local": "192.0.2.10", "scope": "global"},
                          {"family": "inet6", "local": "2001:db8::10", "scope": "global"}]}]
        self.objects = {"qdisc": {}, "class": {}, "filter": {}}
        self.commands = []
        self.mutations = []
        self.fail = None

    def run(self, argv, input=None):
        argv = list(argv)
        self.commands.append(argv)
        if argv[:4] in (["ip", "-j", "-d", "address"], ["ip", "-j", "-d", "link"]):
            return self.result(argv, self.links)
        if argv[:2] == ["ip", "-j"] and argv[3:5] == ["rule", "show"]:
            return self.result(argv, [{"priority": p, "table": t, "src": "all"}
                                      for p, t in [(0, "local"), (32766, "main"), (32767, "default")]])
        if argv[:2] == ["ip", "-j"] and argv[3:5] == ["route", "show"]:
            return self.result(argv, [{"dst": "default", "dev": "eth0", "table": "main"}])
        if argv[:2] == ["tc", "-j"]:
            kind, dev = argv[2], argv[5]
            found = deepcopy(self.objects[kind].get(dev, []))
            if kind == "qdisc" and not any(o.get("root") for o in found):
                found.insert(0, {"kind": "noqueue", "handle": "0:", "root": True})
            if kind == "filter":
                found = [o for o in found if o["parent"] == argv[7]]
            return self.result(argv, found)
        self.mutations.append(argv)
        if self.fail and self.fail(argv):
            self.fail = None
            return subprocess.CompletedProcess(argv, 1, "", "injected failure")
        if argv[:2] == ["ip", "link"]:
            return self.link(argv)
        if argv[0] != "tc":
            raise AssertionError("unexpected command: " + repr(argv))
        return self.tc(argv)

    @staticmethod
    def result(argv, value):
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    def link(self, argv):
        action = argv[2]
        if action == "add":
            name = argv[argv.index("name") + 1]
            if any(link["ifname"] == name for link in self.links):
                return subprocess.CompletedProcess(argv, 1, "", "File exists")
            self.links.append({"ifname": name, "flags": [], "linkinfo": {"info_kind": "ifb"}, "addr_info": []})
        else:
            name = argv[argv.index("dev") + 1]
            target = next(link for link in self.links if link["ifname"] == name)
            if action == "del":
                self.links.remove(target)
                for group in self.objects.values():
                    group.pop(name, None)
            elif "alias" in argv:
                target["ifalias"] = argv[argv.index("alias") + 1]
            elif "up" in argv:
                target["flags"] = ["UP"]
            else:
                raise AssertionError(argv)
        return self.result(argv, [])

    def tc(self, argv):
        kind, action = argv[1:3]
        dev = argv[argv.index("dev") + 1]
        group = self.objects[kind].setdefault(dev, [])
        val = lambda key, default=None: argv[argv.index(key) + 1] if key in argv else default
        if kind == "qdisc":
            handle = val("handle", "ffff:" if "ingress" in argv else None)
            parent = val("parent")
            qkind = next((s for s in ("htb", "pfifo", "ingress") if s in argv), None)
            obj = {"kind": qkind, "handle": handle}
            obj["parent" if parent else "root"] = parent if parent else True
            if qkind == "htb":
                obj["options"] = {"default": int(val("default"), 16)}
            if qkind == "pfifo":
                obj["options"] = {"limit": int(val("limit"))}
        elif kind == "class":
            handle = val("classid")
            obj = {"class": "htb", "handle": handle, "parent": val("parent"),
                   "rate": int(val("rate", "0bit")[:-3]) // 8,
                   "ceil": int(val("ceil", "0bit")[:-3]) // 8}
        elif kind == "filter":
            handle = int(val("handle"))
            obj = {"kind": "flower", "protocol": val("protocol"), "pref": int(val("pref")),
                   "parent": val("parent"), "options": {"handle": handle}}
            if action != "del":
                keys = {"eth_type": "ipv4" if val("protocol") == "ip" else "ipv6", "ip_proto": val("ip_proto")}
                for key in ("src_ip", "dst_ip", "src_port", "dst_port"):
                    if key in argv:
                        keys[key] = int(val(key)) if "port" in key else val(key)
                obj["options"]["keys"] = keys
                if "classid" in argv:
                    obj["options"]["classid"] = val("classid")
                else:
                    obj["options"]["actions"] = [{"kind": "mirred", "mirred_action": "redirect",
                                                    "to_dev": argv[-1], "direction": "egress"}]
        else:
            raise AssertionError(argv)
        def matching(existing):
            if kind == "filter":
                return (existing["options"]["handle"] == handle and existing["pref"] == obj["pref"]
                        and existing["protocol"] == obj["protocol"] and existing["parent"] == obj["parent"])
            return existing["handle"] == handle
        old = next((existing for existing in group if matching(existing)), None)
        if action in {"del", "change"} and not old:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if action == "add" and old:
            return subprocess.CompletedProcess(argv, 1, "", "File exists")
        if old:
            group.remove(old)
        if action != "del":
            group.append(obj)
        return self.result(argv, [])


class RateLimitsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.kernel = FakeKernel()
        self.manager = rates.RateLimiter(self.temp.name, self.kernel)
        self.entry = {"port_id": "stable-first", "port": 10001, "listen": "::", "protocols": ["tcp", "udp"],
                      "supported": True, "core": "xray", "file": "inbounds.json", "index": 0, "tag": "node"}

    def state(self):
        return json.loads(self.manager.path.read_text())

    def test_input_contract(self):
        self.assertIs(rates.parse_rate(""), rates.KEEP)
        self.assertIsNone(rates.parse_rate("不限速"))
        self.assertEqual(rates.parse_rate("12.5"), 12_500_000)
        for bad in ["0", "-2", "nan", "inf", "1e2", "$(id)", "1 MB/s", "0.000001"]:
            with self.assertRaises(rates.RateLimitError, msg=bad):
                rates.parse_rate(bad)

    def test_preview_is_read_only(self):
        self.assertTrue(self.manager.status(self.entry)["supported"])
        self.assertFalse(self.manager.directory.exists())
        self.assertFalse(self.kernel.mutations)

    def test_dual_stack_tcp_udp_share_one_class_per_direction(self):
        status = self.manager.set(self.entry, 20_000_000, 100_000_000)
        self.assertTrue(status["applied"], status)
        record = self.state()["entries"]["stable-first"]
        classes = [o for o in record["objects"] if o["type"] == "class"]
        self.assertEqual(len(classes), 2)
        filters = [o for o in record["objects"] if o["type"] == "filter"]
        self.assertEqual(len(filters), 8)
        outgoing = [o for o in filters if o["classid"]]
        incoming = [o for o in filters if o["ifb"]]
        self.assertEqual(len({o["classid"] for o in outgoing}), 1)
        self.assertEqual(len({o["ifb"] for o in incoming}), 1)
        self.assertEqual({o["keys"]["ip_proto"] for o in incoming}, {"tcp", "udp"})
        self.assertTrue(all("src_port" in o["keys"] for o in outgoing))
        self.assertTrue(all("dst_port" in o["keys"] for o in incoming))
        self.assertTrue(all(o["dev"] == "eth0" for o in filters))
        self.assertFalse(status["throughput_verified"])
        self.assertTrue(status["experimental"])
        self.assertTrue(any("非首片" in item for item in status["limitations"]))

    def test_migration_preserves_id_rates_and_objects(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        before = self.state()["entries"]["stable-first"]
        status = self.manager.migrate(self.entry, 10002)
        self.assertTrue(status["applied"], status)
        after = self.state()["entries"]["stable-first"]
        self.assertEqual(after["slot"], before["slot"])
        self.assertEqual(after["upload_bps"], 1_000_000)
        self.assertEqual(after["download_bps"], 2_000_000)
        self.assertEqual([o["dev"] for o in after["objects"]], [o["dev"] for o in before["objects"]])
        self.assertTrue(all(o["keys"].get("src_port", o["keys"].get("dst_port")) == 10002
                            for o in after["objects"] if o["type"] == "filter"))
        self.manager.migrate(self.entry, 10001)
        self.assertTrue(self.manager.status(self.entry)["applied"])

    def test_direction_change_keeps_other_direction_and_unrelated_policy_file(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        policy = self.manager.directory / "policies.sqlite3"
        policy.write_bytes(b"unchanged-test-ledger")
        self.manager.set(self.entry, upload_bps=None)
        after = self.state()["entries"]["stable-first"]
        self.assertIsNone(after["upload_bps"])
        self.assertEqual(after["download_bps"], 2_000_000)
        self.assertEqual(policy.read_bytes(), b"unchanged-test-ledger")
        self.assertFalse(any(l.get("linkinfo", {}).get("info_kind") == "ifb" for l in self.kernel.links))

    def test_unknown_qos_rejected_without_mutating(self):
        self.kernel.objects["qdisc"]["eth0"] = [{"kind": "fq_codel", "handle": "0:", "root": True}]
        result = self.manager.status(self.entry)
        self.assertFalse(result["supported"])
        self.assertIn("QoS", result["reason"])
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, download_bps=1_000_000)
        self.assertEqual(self.kernel.mutations, [])

    def test_unknown_ifb_alias_not_taken_over(self):
        self.manager.set(self.entry, upload_bps=1_000_000)
        next(l for l in self.kernel.links if l["ifname"].startswith("vpm"))["ifalias"] = "someone-else"
        self.kernel.mutations.clear()
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, upload_bps=2_000_000)
        self.assertFalse(self.kernel.mutations)
        self.assertFalse(self.manager.status(self.entry)["applied"])

    def test_multiple_interfaces_rejected(self):
        self.kernel.links.append({"ifname": "eth1", "flags": ["UP"], "addr_info": [
            {"family": "inet", "local": "198.51.100.10", "scope": "global"}]})
        self.assertIn("2 个", self.manager.status(self.entry)["reason"])
        self.assertFalse(self.kernel.mutations)

    def test_failed_class_update_restores_previous_rate(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        self.kernel.fail = lambda argv: argv[:3] == ["tc", "filter", "replace"]
        with self.assertRaises(rates.RateLimitError):
            self.manager.migrate(self.entry, 10003)
        after = self.state()["entries"]["stable-first"]
        self.assertEqual(after["entry"]["port"], 10001)
        self.assertTrue(self.manager.status(self.entry)["applied"])
        self.assertNotIn("pending", self.state())

    def test_second_direction_failure_rolls_back_first_direction(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        self.kernel.fail = lambda argv: (argv[:3] == ["tc", "class", "change"]
                                         and any(value.startswith("vpm") for value in argv))
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, 3_000_000, 4_000_000)
        restored = self.manager.status(self.entry)
        self.assertTrue(restored["applied"], restored)
        self.assertEqual(restored["upload_bps"], 1_000_000)
        self.assertEqual(restored["download_bps"], 2_000_000)
        self.assertEqual(self.kernel.objects["class"]["eth0"][0]["rate"], 250_000)

    def test_reboot_recreates_missing_objects_with_saved_rates(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        self.kernel.links = [l for l in self.kernel.links if not l["ifname"].startswith("vpm")]
        self.kernel.objects = {"qdisc": {}, "class": {}, "filter": {}}
        self.assertFalse(self.manager.status(self.entry)["applied"])
        result = self.manager.reconcile([self.entry])
        self.assertTrue(result[0]["applied"], result)

    def test_boot_policy_drain_allows_missing_queues_before_rate_restore(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        self.kernel.links = [l for l in self.kernel.links if not l["ifname"].startswith("vpm")]
        self.kernel.objects = {"qdisc": {}, "class": {}, "filter": {}}
        self.kernel.mutations.clear()
        result = self.manager.on_policy_block(self.entry)
        self.assertTrue(result["drained"])
        self.assertEqual(result["queues"], 0)
        self.assertEqual(result["missing_queues"], 2)
        self.assertFalse(self.kernel.mutations)
        self.assertTrue(self.manager.reconcile([self.entry])[0]["applied"])

    def test_remove_one_keeps_other_entry_and_shared_parents(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        other = dict(self.entry, port_id="stable-second", port=20001)
        self.manager.set(other, 3_000_000, 4_000_000)
        self.kernel.mutations.clear()
        self.manager.set(self.entry, None, None)
        self.assertTrue(self.manager.status(other)["applied"])
        self.assertFalse(any(cmd[:3] == ["tc", "qdisc", "del"] and "root" in cmd
                             and "eth0" in cmd for cmd in self.kernel.mutations))

    def test_external_class_modification_is_detected(self):
        self.manager.set(self.entry, download_bps=2_000_000)
        self.kernel.objects["class"]["eth0"][0]["ceil"] *= 2
        self.kernel.mutations.clear()
        self.assertFalse(self.manager.status(self.entry)["applied"])
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, download_bps=None)
        self.assertEqual(self.kernel.mutations, [])

    def test_policy_block_drains_only_own_queues(self):
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        other = dict(self.entry, port_id="stable-second", port=20001)
        self.manager.set(other, 3_000_000, 4_000_000)
        self.kernel.mutations.clear()
        self.assertEqual(self.manager.on_policy_block(self.entry)["queues"], 2)
        self.assertEqual(len(self.kernel.mutations), 4)
        self.assertTrue(all(cmd[:2] == ["tc", "qdisc"] for cmd in self.kernel.mutations))
        self.assertTrue(self.manager.status(other)["applied"])

    def test_same_priority_foreign_filter_cannot_hide(self):
        self.manager.set(self.entry, download_bps=2_000_000)
        foreign = deepcopy(self.kernel.objects["filter"]["eth0"][0])
        foreign["options"]["handle"] = 99
        self.kernel.objects["filter"]["eth0"].append(foreign)
        self.kernel.mutations.clear()
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, download_bps=None)
        self.assertFalse(self.kernel.mutations)

    def test_htb_unclassified_packet_stats_do_not_invalidate_ownership(self):
        self.manager.set(self.entry, download_bps=2_000_000)
        root = next(o for o in self.kernel.objects["qdisc"]["eth0"] if o["handle"] == rates.ROOT)
        root["options"]["direct_packets_stat"] = 500
        self.assertTrue(self.manager.status(self.entry)["applied"])
        self.manager.set(self.entry, download_bps=3_000_000)
        root["options"]["direct_packets_stat"] = 800
        self.assertTrue(self.manager.status(self.entry)["applied"])

    def test_symlink_state_and_parent_are_rejected(self):
        victim = Path(self.temp.name) / "victim"
        victim.write_text("do not touch")
        self.manager.directory.mkdir()
        self.manager.path.symlink_to(victim)
        with self.assertRaises(rates.RateLimitError):
            self.manager.set(self.entry, download_bps=1_000_000)
        self.assertEqual(victim.read_text(), "do not touch")
        self.manager.path.unlink()
        self.manager.directory.rmdir()
        self.manager.directory.symlink_to(Path(self.temp.name), target_is_directory=True)
        with self.assertRaises(rates.RateLimitError):
            self.manager.status(self.entry)
        self.assertFalse(self.kernel.mutations)

    def test_interrupted_migration_recovers_before_next_migrate(self):
        class PowerLoss(BaseException):
            pass
        self.manager.set(self.entry, 1_000_000, 2_000_000)
        original_save = self.manager._save
        def crash_after_checkpoint(state):
            original_save(state)
            pending = state.get("pending", {})
            target = pending.get("target", {}).get("entries", {}).get("stable-first", {})
            changed = [o for o in target.get("objects", []) if o.get("type") == "filter"
                       and o.get("fingerprint", {}).get("options", {}).get("keys", {}).get("src_port") == 10005]
            if changed:
                raise PowerLoss()
        self.manager._save = crash_after_checkpoint
        with self.assertRaises(PowerLoss):
            self.manager.migrate(self.entry, 10005)
        self.manager._save = original_save
        self.assertIn("pending", self.state())
        self.assertFalse(self.manager.status(self.entry)["applied"])
        restored = self.manager.migrate(self.entry, 10001)
        self.assertTrue(restored["applied"], restored)
        self.assertNotIn("pending", self.state())
        self.assertEqual(self.state()["entries"]["stable-first"]["entry"]["port"], 10001)

    def test_recovery_refuses_external_change_after_interruption(self):
        self.manager.set(self.entry, download_bps=2_000_000)
        state = self.state()
        state["pending"] = {"old": deepcopy(state), "target": deepcopy(state)}
        self.manager._save(state)
        self.kernel.objects["class"]["eth0"][0]["ceil"] *= 2
        self.kernel.mutations.clear()
        with self.assertRaises(rates.RateLimitError):
            self.manager.recover()
        self.assertFalse(self.kernel.mutations)
        self.assertIn("pending", self.state())


if __name__ == "__main__":
    unittest.main()
