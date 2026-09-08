"""State/failure tests using an in-memory command adapter; never touches nft/tc.

The mock validates ledger and transaction semantics, not kernel syntax or real
traffic enforcement. The deployment matrix requires separate privileged tests.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shell"))
from port_manager.policies import PolicyManager, PolicyError, TABLE, OWNER, parse_expiry, _token


def entry(port_id="test-a", port=443, listen="::", protocols=None):
    return {"port_id": port_id, "core": "xray", "file": "01.json", "index": 0,
            "tag": port_id, "port": port, "listen": listen, "protocols": protocols or ["tcp"],
            "kind": "xray-reality", "supported": True, "reason": ""}


class FakeRunner:
    def __init__(self):
        self.items = None
        self.scripts = []
        self.fail_apply = False
        self.fail_after_apply = False
        self.external_tables = []
        self.boot_id = "boot-one"
        self.unsynchronized = False
        self.commands = []
        self.increment_before_freeze = 0

    def add_usage(self, port_id, up=0, down=0):
        for item in self.items or []:
            if "counter" in item:
                counter = item["counter"]
                if counter["name"].startswith(_token(port_id) + "_"):
                    counter["bytes"] += up if counter["name"].endswith("_u") else down
                    counter["packets"] += 1

    def run(self, args, input=None):
        self.commands.append(args)
        code, out = 0, ""
        if args[0] == "systemd-detect-virt":
            code = 1
        elif args[0] == "timedatectl":
            out = "no" if self.unsynchronized else "yes"
        elif args[0] == "cat":
            out = self.boot_id
        elif args[:2] == ["systemctl", "is-active"]:
            code = 0 if args[-1] == "v2ray-agent-port-policy.service" else 3
        elif args[:4] == ["nft", "-j", "list", "table"]:
            code = 0 if self.items is not None else 1
            out = json.dumps({"nftables": copy.deepcopy(self.items or [])})
        elif args[:4] == ["nft", "-j", "list", "ruleset"]:
            out = json.dumps({"nftables": (self.items or []) + self.external_tables})
        elif args[:3] == ["nft", "-f", "-"]:
            if self.fail_apply:
                self.fail_apply = False
                return subprocess.CompletedProcess(args, 1, "", "injected")
            if self.increment_before_freeze and "flush chain" in input:
                self.add_usage("test-a", self.increment_before_freeze, 0)
                self.increment_before_freeze = 0
            self.scripts.append(input)
            self.apply(input)
            if self.fail_after_apply:
                self.fail_after_apply = False
                code = 1
        return subprocess.CompletedProcess(args, code, out, "")

    def apply(self, script):
        for line in script.splitlines():
            if line.startswith("delete table"):
                self.items = None
            elif line.startswith("add table"):
                self.items = [{"table": {"family": "inet", "name": TABLE, "comment": OWNER}}]
            elif line.startswith("add chain"):
                name = line.split()[4]
                self.items.append({"chain": {"family": "inet", "table": TABLE, "name": name,
                                             "type": "filter", "hook": name, "prio": -10, "policy": "accept"}})
            elif line.startswith("add counter"):
                name, used = re.search(r"add counter inet \S+ (\S+) \{ packets 0 bytes (\d+)", line).groups()
                self.items.append({"counter": {"family": "inet", "table": TABLE, "name": name,
                                               "packets": 0, "bytes": int(used)}})
            elif line.startswith("add quota"):
                name, limit, used = re.search(r"add quota inet \S+ (\S+) \{ over (\d+) bytes used (\d+)", line).groups()
                self.items.append({"quota": {"family": "inet", "table": TABLE, "name": name,
                                             "bytes": int(limit), "used": int(used), "inv": True}})
            elif line.startswith("flush chain"):
                chain = line.split()[-1]
                self.items = [item for item in self.items if not ("rule" in item and item["rule"]["chain"] == chain)]
            elif line.startswith("add rule"):
                tokens = line.split(maxsplit=5)
                self.items.append({"rule": {"family": "inet", "table": TABLE, "chain": tokens[4],
                                            "expr": [{"mock": tokens[5]}]}})
            else:
                raise AssertionError("mock cannot parse nft line: " + line)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runner = FakeRunner()
        self.now = dt.datetime(2026, 9, 8, 1, tzinfo=dt.timezone.utc)
        self.manager = PolicyManager(self.root, self.runner, clock=lambda: self.now)
        self.e = entry()
        # tc separately tests queue drain; quota tests isolate their own backend.
        self.drain = patch.object(PolicyManager, "_drain_blocked")
        self.drain.start()

    def tearDown(self):
        self.drain.stop()
        self.manager.close()
        self.temp.cleanup()

    def enroll(self, **changes):
        return self.manager.batch_update([self.e], changes or {"quota_bytes": 1000})

    def row(self):
        return self.manager._rows()[0]

    def test_preview_is_readonly_and_date_includes_whole_day(self):
        preview = self.manager.preview([self.e], {"expires_at": "2026-12-31", "quota_bytes": 0})
        self.assertEqual(preview[0]["new"]["expires_at"], "2026-12-31T16:00:00+00:00")
        self.assertIn("quota_exhausted", preview[0]["reasons"])
        self.manager.status([self.e])
        self.assertFalse(self.manager.path.exists())
        self.assertFalse(self.runner.scripts)

    def test_invalid_batch_has_no_partial_effect(self):
        other = entry("test-b", 8443)
        with self.assertRaises(PolicyError):
            self.manager.batch_update([self.e, other], {"test-a": {"quota_bytes": 100}, "test-b": {"quota_bytes": -1}})
        self.assertFalse(self.manager.path.exists())
        self.assertFalse(self.runner.scripts)

    def test_zero_is_blocked_and_null_is_unlimited(self):
        self.enroll(quota_bytes=0)
        state = self.manager.status([self.e])[0]
        self.assertEqual(state["state"], "blocked")
        self.assertIn("quota_exhausted", state["reasons"])
        self.enroll(quota_bytes=None)
        self.assertEqual(self.manager.status([self.e])[0]["state"], "active")

    def test_shared_dual_stack_bidirectional_quota_and_private_ledger(self):
        self.e["protocols"] = ["tcp", "udp"]
        self.enroll(quota_bytes=1000)
        objects = [item["quota"] for item in self.runner.items if "quota" in item]
        self.assertEqual(len(objects), 1)
        rules = "\n".join(item["rule"]["expr"][0]["mock"] for item in self.runner.items if "rule" in item)
        self.assertEqual(rules.count("quota name " + objects[0]["name"]), 4)
        self.assertNotIn("meta nfproto ipv4", rules)
        self.assertIn('iifname != "lo"', rules)
        self.assertIn('oifname != "lo"', rules)
        self.assertEqual(self.manager.path.stat().st_mode & 0o777, 0o600)
        self.runner.add_usage("test-a", 400, 300)
        self.manager.reconcile([self.e])
        row = self.row()
        self.assertEqual((row["used_up"], row["used_down"]), (400, 300))
        self.assertIsNone(row["fault"])

    def test_freeze_before_sample_does_not_refund_racing_bytes(self):
        self.enroll()
        self.runner.add_usage("test-a", 100, 200)
        self.runner.increment_before_freeze = 73
        self.enroll(quota_bytes=2000)
        self.assertEqual(self.manager.status([self.e])[0]["used_bytes"], 373)

    def test_reduction_renewal_and_resume_do_not_reset_usage(self):
        self.enroll()
        self.runner.add_usage("test-a", 400, 400)
        self.enroll(quota_bytes=700, paused=True, expires_at="2026-01-01")
        self.enroll(quota_bytes=2000, expires_at="2027-01-01")
        status = self.manager.status([self.e])[0]
        self.assertEqual(status["used_bytes"], 800)
        self.assertEqual(status["reasons"], ["paused"])
        self.enroll(paused=False)
        self.assertTrue(self.manager.status([self.e])[0]["available"])

    def test_missing_generation_latches_fault_and_never_refunds(self):
        self.enroll()
        self.runner.add_usage("test-a", 300, 100)
        self.manager.reconcile([self.e])
        self.runner.items = None
        self.assertFalse(self.manager.status([self.e])[0]["effective"])
        self.manager.reconcile([self.e])
        status = self.manager.status([self.e])[0]
        self.assertEqual(status["used_bytes"], 400)
        self.assertFalse(status["available"])
        self.assertTrue(any("missing_counter" in x for x in status["reasons"]))
        self.enroll(quota_bytes=100000, expires_at=None, paused=False)
        self.assertFalse(self.manager.status([self.e])[0]["available"])

    def test_reset_counter_is_fault_and_preserves_last_trusted_value(self):
        self.enroll()
        self.runner.add_usage("test-a", 500, 0)
        self.manager.reconcile([self.e])
        for item in self.runner.items:
            if "counter" in item:
                item["counter"]["bytes"] = 0
        self.manager.reconcile([self.e])
        self.assertEqual(self.row()["used_up"], 500)
        self.assertEqual(self.row()["fault"], "missing_or_reset_counter")

    def test_normal_shutdown_reboot_restores_without_uncertain_window(self):
        self.enroll()
        self.runner.add_usage("test-a", 200, 250)
        self.manager.prepare_shutdown()
        self.runner.items = None
        self.runner.boot_id = "boot-two"
        self.now += dt.timedelta(minutes=2)
        self.manager.reconcile([self.e])
        self.assertEqual(self.manager.status([self.e])[0]["used_bytes"], 450)
        self.assertIsNone(self.row()["fault"])
        self.assertTrue(self.manager.status([self.e])[0]["available"])

    def test_cycle_rollover_idempotent_and_pause_expiry_persist(self):
        self.enroll(paused=True, expires_at="2026-09-30", quota_bytes=1000)
        self.runner.add_usage("test-a", 600, 200)
        self.manager.prepare_shutdown()
        self.runner.items = None
        self.runner.boot_id = "boot-two"
        self.now = dt.datetime(2026, 9, 30, 16, tzinfo=dt.timezone.utc)
        self.manager.reconcile([self.e])
        self.manager.reconcile([self.e])
        self.assertEqual(self.row()["cycle"], "2026-10")
        self.assertEqual(self.row()["used_up"], 0)
        self.assertEqual(len(self.manager.history()), 1)
        self.assertEqual(self.manager.history()[0]["used_up"], 600)
        self.assertEqual(set(self.manager.status([self.e])[0]["reasons"]), {"paused", "expired"})

    def test_clock_rollback_does_not_unexpire_or_allocate_previous_cycle(self):
        self.enroll(expires_at="2026-09-08T01:00:05+00:00")
        self.now += dt.timedelta(seconds=10)
        self.manager.reconcile([self.e])
        self.now -= dt.timedelta(days=40)
        self.manager.reconcile([self.e])
        self.assertTrue(self.row()["expired"])
        self.assertEqual(self.row()["cycle"], "2026-09")
        self.assertEqual(self.row()["fault"], "clock_anomaly")

    def test_kernel_time_boundary_covers_expiry_month_and_daemon_death(self):
        self.enroll(expires_at="2026-09-08T01:00:12+00:00")
        script = self.runner.scripts[-1]
        self.assertIn("meta time >= " + str(int(self.now.timestamp()) + 12), script)
        self.now += dt.timedelta(seconds=31)
        status = self.manager.status([self.e])[0]
        self.assertIn("daemon_lease_elapsed", status["reasons"])
        self.assertFalse(status["available"])

    def test_port_migration_and_reverse_preserve_usage_and_old_port_guard(self):
        self.enroll(quota_bytes=1000)
        self.runner.add_usage("test-a", 700, 350)
        self.manager.before_port_change(self.e)
        self.manager.after_port_change(self.e, 8443)
        self.assertEqual(self.row()["mapping"]["port"], 8443)
        self.assertEqual(self.row()["used_up"] + self.row()["used_down"], 1050)
        self.assertIn("tcp dport 443 drop", self.runner.scripts[-1])
        self.assertIn("tcp dport 8443 drop", self.runner.scripts[-1])
        self.manager.after_port_change(self.e, 443)
        self.assertEqual(self.row()["mapping"]["port"], 443)
        self.assertEqual(self.row()["used_up"] + self.row()["used_down"], 1050)

    def test_external_port_move_blocks_discovered_mapping(self):
        self.enroll()
        moved = dict(self.e, port=8443)
        self.manager.reconcile([moved])
        self.assertEqual(self.row()["fault"], "listener_mapping_changed")
        self.assertIn("tcp dport 8443 drop", self.runner.scripts[-1])

    def test_unowned_table_or_unrecognized_firewall_refused(self):
        self.runner.external_tables = [{"table": {"name": "administrator_table", "family": "inet"}}]
        with self.assertRaisesRegex(PolicyError, "unadapted"):
            self.enroll()
        self.assertFalse(self.manager.path.exists())
        self.runner.external_tables = []
        self.runner.items = [{"table": {"name": TABLE, "family": "inet", "comment": "someone-else"}}]
        with self.assertRaises(PolicyError):
            self.enroll()
        self.assertFalse(any("delete table" in x for x in self.runner.scripts))

    def test_preexisting_same_transport_port_collision_is_rejected(self):
        self.enroll()
        with self.assertRaisesRegex(PolicyError, "ambiguous"):
            self.manager.preview([entry("test-b", 443, "192.0.2.1")], {"quota_bytes": 5})
        # TCP and UDP sharing only the number remain separate, explicit entries.
        self.manager.preview([entry("test-c", 443, protocols=["udp"])], {"quota_bytes": 5})

    def test_runtime_speed_failure_blocks_rate_only_entry(self):
        state = self.manager.block_runtime(self.e, "rate_execution_failed")
        self.assertTrue(state["effective"])
        self.assertFalse(state["available"])
        self.assertIn("fault:rate_execution_failed", state["reasons"])

    def test_policy_rollback_restores_fields_without_usage_refund(self):
        self.enroll(quota_bytes=1000)
        self.runner.add_usage("test-a", 50, 40)
        original_rebuild = self.manager._rebuild
        calls = 0

        def failing_rebuild(rows, **kwargs):
            nonlocal calls
            calls += 1
            original_rebuild(rows, **kwargs)
            if calls == 1:
                self.runner.add_usage("test-a", 25, 0)
                raise PolicyError("injected post-apply failure")

        with patch.object(self.manager, "_rebuild", side_effect=failing_rebuild):
            with self.assertRaisesRegex(PolicyError, "restored"):
                self.enroll(quota_bytes=5000)
        self.assertEqual(self.row()["quota_bytes"], 1000)
        self.assertEqual(self.row()["used_up"] + self.row()["used_down"], 115)
        self.assertEqual(self.manager._open().execute("SELECT phase FROM journal ORDER BY rowid DESC LIMIT 1").fetchone()[0], "rolled_back")

    def test_existing_status_preview_history_do_not_open_write_connection(self):
        self.enroll()
        self.manager.close()
        before = self.manager.path.stat().st_mtime_ns
        self.manager.status([self.e])
        self.manager.preview([self.e], {"quota_bytes": 2000})
        self.manager.history()
        self.assertIsNone(self.manager.db)
        self.assertEqual(self.manager.path.stat().st_mtime_ns, before)

    def test_fault_correction_cannot_reduce_trusted_usage(self):
        self.enroll()
        self.runner.add_usage("test-a", 100, 200)
        self.manager.reconcile([self.e])
        with patch("port_manager.core.inventory", return_value=[self.e]):
            with self.assertRaisesRegex(PolicyError, "reduce"):
                self.manager.acknowledge_fault(self.e, used_up=99, used_down=200, reason="verified missing window")

    def test_lost_rules_and_failed_rebuild_stop_affected_core(self):
        self.enroll()
        self.runner.items = None
        with patch.object(self.manager, "_apply", side_effect=PolicyError("kernel unavailable")):
            with self.assertRaises(PolicyError):
                self.manager.reconcile([self.e])
        self.assertIn(["systemctl", "stop", "xray.service"], self.runner.commands)
        self.assertFalse(self.manager.status([self.e])[0]["effective"])

    def test_accounting_correction_cannot_reopen_changed_unmetered_mapping(self):
        self.enroll()
        moved = dict(self.e, port=8443)
        self.manager.reconcile([moved])
        with self.assertRaisesRegex(PolicyError, "mapping"):
            self.manager.acknowledge_fault(moved, used_up=0, used_down=0, reason="verified missing window")
        self.assertIn("tcp dport 8443 drop", self.runner.scripts[-1])

    def test_clean_marker_revoked_before_restart_allows_traffic(self):
        self.enroll()
        self.manager.prepare_shutdown()
        self.assertTrue(self.manager._meta("clean_shutdown"))
        self.manager.reconcile([self.e])
        self.assertFalse(self.manager._meta("clean_shutdown"))
        self.runner.items = None
        self.runner.boot_id = "crash-reboot"
        self.manager.reconcile([self.e])
        self.assertEqual(self.row()["fault"], "missing_counter_generation")

    def test_interrupted_cycle_cannot_import_previous_month_counter(self):
        self.enroll()
        self.runner.add_usage("test-a", 600, 200)
        self.manager._freeze_sample()
        self.runner.boot_id = "new-boot"
        self.now = dt.datetime(2026, 9, 30, 16, tzinfo=dt.timezone.utc)
        self.manager._advance_time(self.manager._rows())
        self.assertEqual(self.row()["last_up"], 600)
        self.assertEqual(self.row()["used_up"], 0)
        self.manager.close()  # crash before installing the new generation
        self.manager.reconcile([self.e])
        self.assertEqual(self.row()["used_up"] + self.row()["used_down"], 0)
        self.assertEqual(self.row()["fault"], "interrupted_cycle_transition")
        self.assertEqual(self.manager.history()[0]["used_up"], 600)

    def test_batch_rejects_speed_fields_and_timezone_migration(self):
        with self.assertRaises(PolicyError):
            self.manager.preview([self.e], {"upload_bps": 500})
        self.enroll()
        with self.assertRaises(PolicyError):
            self.manager.preview([self.e], {"timezone": "UTC"})


if __name__ == "__main__":
    unittest.main()
