"""Input ambiguity and shared-lock regression tests for the operator interface."""

import datetime as dt
import fcntl
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shell"))
from port_manager import __main__ as cli


class InputValidationTests(unittest.TestCase):
    def test_ports_have_strict_ascii_decimal_bounds(self):
        for text, expected in (("1", 1), ("443", 443), ("65535", 65535)):
            with self.subTest(text=text):
                self.assertEqual(cli.parse_port(text), expected)
        for text in ("", "0", "65536", "-1", "+443", "443.0", "443x", "1e3", "４４３", "٤٤٣", "443; true"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.parse_port(text)

    def test_quota_blank_keeps_existing_and_unlimited_is_explicit(self):
        self.assertIs(cli.parse_quota(""), cli.KEEP)
        self.assertIs(cli.parse_quota("   "), cli.KEEP)
        for text in ("unlimited", "无限额"):
            with self.subTest(text=text):
                self.assertIsNone(cli.parse_quota(text))

    def test_quota_distinguishes_decimal_gb_and_binary_gib(self):
        for text, expected in (("1", 1_000_000_000), ("1.5", 1_500_000_000), ("2 GB", 2_000_000_000), ("2 GiB", 2_147_483_648)):
            with self.subTest(text=text):
                self.assertEqual(cli.parse_quota(text), expected)
        for text in ("-1", "NaN", "inf", "1e1000", "1 potatoes", "1; true"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.parse_quota(text)

    def test_expiry_blank_keeps_existing_and_never_is_explicit(self):
        self.assertIs(cli.parse_expiry(""), cli.KEEP)
        self.assertIs(cli.parse_expiry("  "), cli.KEEP)
        for text in ("never", "永不到期"):
            with self.subTest(text=text):
                self.assertIsNone(cli.parse_expiry(text))

    def test_expiry_includes_entire_selected_local_date(self):
        result = cli.parse_expiry("2026-09-30", timezone="Asia/Shanghai")
        parsed = dt.datetime.fromisoformat(result.replace("Z", "+00:00"))
        self.assertEqual(parsed.utcoffset(), dt.timedelta(0))
        self.assertEqual(parsed, dt.datetime(2026, 9, 30, 16, tzinfo=dt.timezone.utc))

    def test_expiry_observes_daylight_saving_at_following_midnight(self):
        result = cli.parse_expiry("2026-03-08", timezone="America/New_York")
        parsed = dt.datetime.fromisoformat(result.replace("Z", "+00:00"))
        self.assertEqual(parsed, dt.datetime(2026, 3, 9, 4, tzinfo=dt.timezone.utc))

    def test_invalid_expiry_does_not_become_never(self):
        for text in ("2026-02-29", "2026-13-01", "2026-09-31", "tomorrow", "2026-09-30; true"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.parse_expiry(text)


class EntrySelectionTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            {"port_id": "alpha", "port": 443, "protocols": ["tcp"]},
            {"port_id": "beta", "port": 8443, "protocols": ["tcp"]},
            {"port_id": "gamma", "port": 9443, "protocols": ["udp"]},
        ]

    def assertSelection(self, text, indices, **kwargs):
        selected = cli.select_entries(text, self.entries, **kwargs)
        self.assertEqual(selected, [self.entries[index] for index in indices])
        for result, index in zip(selected, indices):
            self.assertIs(result, self.entries[index])

    def test_index_id_and_unambiguous_port_resolve_to_existing_entry(self):
        self.assertSelection("#1", [0])
        self.assertSelection("alpha", [0])
        self.assertSelection("1", [0])
        self.assertSelection("port:443", [0])
        self.assertSelection("8443", [1])

    def test_lists_and_ranges_resolve_only_existing_entries(self):
        self.assertSelection("alpha,port:9443", [0, 2])
        self.assertSelection("443-9000", [0, 1])

    def test_port_range_skips_unreadable_entries_without_a_numeric_port(self):
        entries = self.entries + [{"port_id": "unreadable", "port": None, "supported": False}]
        self.assertEqual(cli.select_entries("443-9000", entries), self.entries[:2])

    def test_literal_unknown_ports_and_empty_ranges_are_rejected(self):
        for text in ("port:444", "444", "450-500", "missing", "", "alpha,", "#0", "#4"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.select_entries(text, self.entries)

    def test_overlapping_and_duplicate_selections_are_rejected(self):
        for text in ("alpha,alpha", "#1,443", "443-9000,beta"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.select_entries(text, self.entries)

    def test_single_selection_cannot_apply_batch_rate_changes(self):
        self.assertSelection("alpha", [0], single=True)
        for text in ("alpha,beta", "443-9000"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.select_entries(text, self.entries, single=True)

    def test_same_numeric_port_on_distinct_entries_requires_stable_id(self):
        entries = [self.entries[0], {"port_id": "delta", "port": 443, "protocols": ["udp"]}]
        for text in ("443", "port:443"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cli.select_entries(text, entries)
        self.assertEqual(cli.select_entries("delta", entries), [entries[1]])

    def test_bare_number_cannot_choose_between_index_and_different_port(self):
        entries = [self.entries[0], {"port_id": "low-port", "port": 1, "protocols": ["tcp"]}]
        with self.assertRaises(ValueError):
            cli.select_entries("1", entries)
        self.assertEqual(cli.select_entries("#1", entries), [entries[0]])
        self.assertEqual(cli.select_entries("port:1", entries), [entries[1]])


class SharedLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.environment = mock.patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop("PORT_MANAGER_LOCK_FD", None)

    def assertLockHeld(self, path):
        with open(path, "a+") as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assertLockFree(self, path):
        with open(path, "a+") as probe:
            fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe.fileno(), fcntl.LOCK_UN)

    def test_own_lock_excludes_writers_and_releases_after_context(self):
        with cli.shared_lock(self.root):
            self.assertLockHeld(self.root / ".write.lock")
        self.assertLockFree(self.root / ".write.lock")

    def test_valid_inherited_lock_remains_held_after_context(self):
        path = self.root / ".write.lock"
        with open(path, "a+") as owner:
            fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
            os.environ["PORT_MANAGER_LOCK_FD"] = str(owner.fileno())
            with cli.shared_lock(self.root):
                self.assertLockHeld(path)
            self.assertLockHeld(path)
            fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
        self.assertLockFree(path)

    def test_descriptor_for_different_inode_is_rejected(self):
        (self.root / ".write.lock").touch()
        with open(self.root / "unrelated.lock", "a+") as unrelated:
            fcntl.flock(unrelated.fileno(), fcntl.LOCK_EX)
            os.environ["PORT_MANAGER_LOCK_FD"] = str(unrelated.fileno())
            with self.assertRaises(ValueError):
                with cli.shared_lock(self.root):
                    self.fail("accepted unrelated inherited descriptor")

    def test_invalid_descriptor_is_rejected(self):
        for descriptor in ("not-a-descriptor", "-1", "999999"):
            with self.subTest(descriptor=descriptor):
                os.environ["PORT_MANAGER_LOCK_FD"] = descriptor
                with self.assertRaises(ValueError):
                    with cli.shared_lock(self.root):
                        self.fail("accepted invalid inherited descriptor")


class InteractiveSafetyTests(unittest.TestCase):
    def test_cancelled_port_change_does_not_write_or_hold_lock_during_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = {
                "port_id": "alpha",
                "port": 443,
                "core": "xray",
                "file": "07_VLESS_vision_reality_inbounds.json",
                "index": 0,
                "tag": "reality",
                "listen": "0.0.0.0",
                "protocols": ["tcp"],
                "kind": "reality",
                "supported": True,
                "reason": "",
            }

            class FakeManager:
                def __init__(self):
                    self.root = root
                    self.changes = []

                def list(self):
                    return [dict(entry)]

                def recover(self):
                    return []

                def check_port(self, *args, **kwargs):
                    return []

                def history(self):
                    return []

                def change(self, *args, **kwargs):
                    self.changes.append((args, kwargs))
                    raise AssertionError("cancellation must not reach a writer")

            manager = FakeManager()
            answers = iter(("2", "alpha", "8443", "n", "0"))
            prompts = []

            def answer(prompt=""):
                prompts.append(prompt)
                with open(root / ".write.lock", "a+") as probe:
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
                return next(answers)

            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PORT_MANAGER_LOCK_FD", None)
                cli.main(
                    ["--root", str(root)],
                    manager_factory=lambda *args, **kwargs: manager,
                    policies_factory=lambda *args, **kwargs: None,
                    rates_factory=lambda *args, **kwargs: None,
                    input_fn=answer,
                    output=io.StringIO(),
                )
            self.assertEqual(len(prompts), 5)
            self.assertEqual(manager.changes, [])
            self.assertEqual(entry["port"], 443)

    def test_inventory_changed_during_confirmation_requires_new_preview(self):
        for change in ({"port": 444}, {"supported": False}, {"listen": "127.0.0.1"}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                entry = {"port_id": "alpha", "port": 443, "core": "xray", "supported": True, "listen": "::"}
                manager = mock.Mock(root=root)
                manager.list.return_value = [dict(entry)]
                manager.recover.return_value = []

                def confirm(prompt=""):
                    with open(root / ".write.lock", "a+") as probe:
                        fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
                    manager.list.return_value = [dict(entry, **change)]
                    return "YES"

                app = cli.Application(manager, input_fn=confirm, output=io.StringIO())
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("PORT_MANAGER_LOCK_FD", None)
                    with self.assertRaisesRegex(ValueError, "变化|changed"):
                        app.change(entry, 8443)
                manager.change.assert_not_called()
                manager.recover.assert_called_once_with()

    def test_invalid_second_per_entry_policy_aborts_entire_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = [
                {"port_id": "alpha", "port": 443, "core": "xray", "supported": True},
                {"port_id": "beta", "port": 8443, "core": "xray", "supported": True},
            ]
            manager = mock.Mock(root=root)
            manager.list.return_value = entries
            policies = mock.Mock()
            policies.status.return_value = []
            answers = iter(("6", "alpha,beta", "2", "1", "2026-09-30", "2", "invalid-date", "0"))
            prompts = []

            def answer(prompt=""):
                prompts.append(prompt)
                with open(root / ".write.lock", "a+") as probe:
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
                return next(answers)

            output = io.StringIO()
            app = cli.Application(manager, policies, input_fn=answer, output=output)
            self.assertEqual(app.menu(), 0)
            self.assertEqual(len(prompts), 8)
            self.assertIn("操作未完成", output.getvalue())
            policies.preview.assert_not_called()
            policies.batch_update.assert_not_called()
            manager.change.assert_not_called()

    def test_policy_changed_during_confirmation_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = {"port_id": "alpha", "port": 443, "core": "xray", "supported": True}
            manager = mock.Mock(root=Path(directory))
            manager.list.return_value = [entry]
            manager.recover.return_value = []
            policies = mock.Mock()
            policies.preview.return_value = [{"port_id": "alpha", "quota_bytes": 1000}]
            policies.status.side_effect = [
                [{"port_id": "alpha", "version": 1, "quota_bytes": 2000}],
                [{"port_id": "alpha", "version": 2, "quota_bytes": 3000}],
            ]
            app = cli.Application(manager, policies, input_fn=lambda prompt: "YES", output=io.StringIO())
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PORT_MANAGER_LOCK_FD", None)
                with self.assertRaisesRegex(ValueError, "变化|changed"):
                    app.set_policy([entry], {"quota_bytes": 1000})
            policies.batch_update.assert_not_called()


class BackgroundServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "installation"
        self.unit_root = Path(self.tmp.name) / "units"
        module = self.root / "port-manager-lib" / "current" / "port_manager" / "__main__.py"
        module.parent.mkdir(parents=True)
        module.write_text("# Installed port manager module\n")
        self.environment = mock.patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop("PORT_MANAGER_LOCK_FD", None)

    def lock_is_held(self):
        with open(self.root / ".write.lock", "a+") as probe:
            try:
                fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
            return False

    def test_service_installs_units_under_lock_and_starts_after_releasing_lock(self):
        manager = mock.Mock(root=self.root)
        manager.recover.return_value = []
        runner = mock.Mock()
        readiness = {"enabled": False, "active": False}
        calls = []

        def run(argv):
            calls.append(list(argv))
            self.assertEqual(argv[0], "systemctl")
            operation = argv[1]
            code = 0
            if operation == "is-enabled":
                code = 0 if readiness["enabled"] else 1
            elif operation == "is-active":
                code = 0 if readiness["active"] else 3
            elif operation == "show":
                self.assertIn("--property=FragmentPath", argv)
            elif operation == "daemon-reload":
                self.assertTrue(self.lock_is_held(), "daemon-reload must exclude concurrent writers")
            elif operation == "enable":
                self.assertTrue(self.lock_is_held(), "service enable must exclude concurrent writers")
                readiness["enabled"] = True
            elif operation == "start":
                self.assertFalse(self.lock_is_held(), "ExecStartPre must be able to acquire the shared write lock")
                readiness["active"] = True
            else:
                self.fail("unexpected systemctl operation: " + operation)
            return subprocess.CompletedProcess(argv, code, "", "")

        runner.run.side_effect = run
        services = cli.Services(self.root, runner=runner, unit_root=self.unit_root)
        self.assertEqual(services.ensure(manager)["status"], "active")
        manager.recover.assert_called_once_with()
        unit = self.unit_root / "v2ray-agent-port-policy.service"
        content = unit.read_text()
        self.assertIn("AssertPathIsDirectory=" + str(self.root / "port-manager-lib" / "current" / "port_manager"), content)
        self.assertNotIn("ConditionPathIsDirectory=", content)
        self.assertIn("ExecStartPre=/usr/bin/python3 -m port_manager --root " + str(self.root) + " --startup-reconcile", content)
        self.assertIn("ExecStart=/usr/bin/python3 -m port_manager --root " + str(self.root) + " --daemon", content)
        for core in ("xray", "sing-box"):
            dropin = self.unit_root / (core + ".service.d") / "50-v2ray-agent-port-manager.conf"
            self.assertIn("Requires=" + unit.name, dropin.read_text())
            self.assertIn("After=" + unit.name, dropin.read_text())
        mutations = [argv[1] for argv in calls if argv[1] in {"daemon-reload", "enable", "start"}]
        self.assertEqual(mutations, ["daemon-reload", "enable", "start"])
        self.assertTrue(readiness["enabled"])
        self.assertTrue(readiness["active"])
        self.assertFalse(self.lock_is_held())

    def failing_service(self, failure, enabled=False, active=False, stop_error=False):
        state = {"enabled": enabled, "active": active, "cores_active": True}
        calls = []
        runner = mock.Mock()

        def run(argv):
            calls.append(list(argv))
            operation = argv[1]
            code, output = 0, ""
            if operation == "is-enabled":
                code = 0 if state["enabled"] else 1
                output = "enabled" if state["enabled"] else "disabled"
            elif operation == "is-active":
                code = 0 if state["active"] else 3
            elif operation == "show":
                pass
            elif operation in {"daemon-reload", "enable", "disable"}:
                self.assertTrue(self.lock_is_held())
                if operation != "daemon-reload":
                    state["enabled"] = operation == "enable"
            elif operation in {"start", "stop"}:
                self.assertFalse(self.lock_is_held(), "service startup and shutdown must be able to take the writer lock")
                if operation == "start":
                    code = 1 if failure == "nonzero" else 0
                else:
                    # Model systemd's reverse Requires stop propagation.
                    if "--job-mode=ignore-dependencies" not in argv:
                        state["cores_active"] = False
                    self.assertEqual(argv, ["systemctl", "stop", "--job-mode=ignore-dependencies", cli.Services.unit])
                    if stop_error:
                        code = 1
                    else:
                        state["active"] = False
            else:
                self.fail("unexpected systemctl operation: " + operation)
            return subprocess.CompletedProcess(argv, code, output, "")

        runner.run.side_effect = run
        return cli.Services(self.root, runner=runner, unit_root=self.unit_root), state, calls

    def test_cli_first_service_start_failure_removes_new_dependencies_and_enablement(self):
        for command in (["install-service", "--yes"], ["set-policy", "alpha", "--quota", "1", "--yes"]):
            for failure in ("nonzero", "inactive"):
                with self.subTest(command=command[0], failure=failure):
                    services, state, calls = self.failing_service(failure)
                    manager = mock.Mock(root=self.root)
                    manager.list.return_value = [{"port_id": "alpha", "port": 443, "supported": True}]
                    manager.recover.return_value = []
                    policies = mock.Mock()
                    policies.preview.return_value = []
                    policies.status.return_value = []
                    output = io.StringIO()
                    code = cli.main(
                        ["--root", str(self.root), *command],
                        manager_factory=lambda *args, **kwargs: manager,
                        policies_factory=lambda *args, **kwargs: policies,
                        rates_factory=lambda *args, **kwargs: None,
                        services_factory=lambda *args, **kwargs: services,
                        output=output,
                    )
                    self.assertEqual(code, 1, output.getvalue())
                    policies.batch_update.assert_not_called()
                    self.assertFalse(state["enabled"])
                    self.assertFalse(state["active"])
                    self.assertTrue(state["cores_active"], "rollback must not stop live requiring cores")
                    for path in services.templates():
                        self.assertFalse(path.exists(), str(path))
                    mutations = [argv[1] for argv in calls if argv[1] in {"enable", "start", "stop", "disable", "daemon-reload"}]
                    self.assertEqual(mutations, ["daemon-reload", "enable", "start", "stop", "disable", "daemon-reload"])
                    self.assertFalse(self.lock_is_held())

    def test_failed_start_preserves_existing_unit_and_prior_enablement(self):
        for was_enabled in (False, True):
            with self.subTest(was_enabled=was_enabled):
                services, state, calls = self.failing_service("nonzero", enabled=was_enabled)
                unit = self.unit_root / services.unit
                unit.parent.mkdir(parents=True, exist_ok=True)
                original = services.templates()[unit]
                unit.write_text(original)
                manager = mock.Mock(root=self.root)
                manager.recover.return_value = []
                with self.assertRaises(ValueError):
                    services.ensure(manager)
                self.assertEqual(unit.read_text(), original)
                self.assertEqual(state["enabled"], was_enabled)
                self.assertEqual(state["active"], False)
                for path in services.templates():
                    if path != unit:
                        self.assertFalse(path.exists())
                if was_enabled:
                    self.assertFalse(any(argv[1] in {"enable", "disable"} for argv in calls))

    def test_failed_start_does_not_stop_preexisting_active_service(self):
        services, state, calls = self.failing_service("nonzero", active=True)
        for path, content in services.templates().items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        manager = mock.Mock(root=self.root)
        manager.recover.return_value = []
        with self.assertRaises(ValueError):
            services.ensure(manager)
        self.assertTrue(state["active"])
        self.assertFalse(state["enabled"])
        self.assertFalse(any(argv[1] == "stop" for argv in calls))
        self.assertTrue(all(path.read_text() == content for path, content in services.templates().items()))

    def test_cleanup_failure_is_reported_and_other_cleanup_still_runs(self):
        services, state, calls = self.failing_service("nonzero", stop_error=True)
        manager = mock.Mock(root=self.root)
        manager.recover.return_value = []
        with self.assertRaisesRegex(ValueError, "rollback is incomplete.*systemctl stop"):
            services.ensure(manager)
        self.assertFalse(state["enabled"])
        self.assertTrue(all(not path.exists() for path in services.templates()))
        self.assertEqual(calls[-1], ["systemctl", "daemon-reload"])

    def test_inherited_writer_lock_rejects_installation_before_mutation(self):
        services, _, calls = self.failing_service("nonzero")
        manager = mock.Mock(root=self.root)
        with open(self.root / ".write.lock", "a+") as owner:
            fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
            os.environ["PORT_MANAGER_LOCK_FD"] = str(owner.fileno())
            with self.assertRaisesRegex(ValueError, "caller's writer lock"):
                services.ensure(manager)
            self.assertTrue(self.lock_is_held())
            self.assertFalse(calls)
            manager.recover.assert_not_called()

    def test_concurrent_install_waits_for_failed_start_compensation(self):
        first, state, calls = self.failing_service("nonzero")
        second = cli.Services(self.root, runner=first.runner, unit_root=self.unit_root)
        manager = mock.Mock(root=self.root)
        manager.recover.return_value = []
        first_started = threading.Event()
        second_waiting = threading.Event()
        release_first = threading.Event()
        original_run = first.runner.run.side_effect
        original_sleep = cli.time.sleep
        starts = []
        results = {}

        def run(argv):
            if argv[1] == "start":
                starts.append(argv)
                if len(starts) == 1:
                    first_started.set()
                    if not release_first.wait(2):
                        raise AssertionError("second installer did not wait")
                else:
                    self.assertFalse(self.lock_is_held())
                    state["active"] = True
                    return subprocess.CompletedProcess(argv, 0, "", "")
            return original_run(argv)

        def sleep(seconds):
            second_waiting.set()
            original_sleep(seconds)

        def install(name, services):
            try:
                results[name] = services.ensure(manager)
            except BaseException as exc:
                results[name] = exc

        first.runner.run.side_effect = run
        threads = [threading.Thread(target=install, args=("first", first)),
                   threading.Thread(target=install, args=("second", second))]
        with mock.patch.object(cli.time, "sleep", side_effect=sleep):
            threads[0].start()
            self.assertTrue(first_started.wait(2))
            threads[1].start()
            try:
                self.assertTrue(second_waiting.wait(2), "installation lock must span start and rollback")
            finally:
                release_first.set()
                for thread in threads:
                    thread.join(3)
        self.assertIsInstance(results.get("first"), ValueError)
        self.assertEqual(results.get("second"), {"status": "active"})
        self.assertTrue(state["enabled"])
        self.assertTrue(state["active"])
        self.assertTrue(all(path.read_text() == content for path, content in second.templates().items()))

    def test_custom_existing_unit_is_preserved_and_service_is_not_started(self):
        unit = self.unit_root / "v2ray-agent-port-policy.service"
        unit.parent.mkdir(parents=True)
        custom = "[Service]\nExecStart=/usr/local/bin/operator-custom-policy\n"
        unit.write_text(custom)
        manager = mock.Mock(root=self.root)
        manager.recover.return_value = []
        runner = mock.Mock()
        runner.run.return_value = subprocess.CompletedProcess(["systemctl"], 1, "", "")
        services = cli.Services(self.root, runner=runner, unit_root=self.unit_root)
        with self.assertRaisesRegex(ValueError, "人工核对|needs review"):
            services.ensure(manager)
        self.assertEqual(unit.read_text(), custom)
        self.assertEqual([path for path in self.unit_root.rglob("*") if path.is_file()], [unit])
        for call in runner.run.call_args_list:
            self.assertNotIn(call.args[0][1], {"daemon-reload", "enable", "start"})
        self.assertFalse(self.lock_is_held())

    def test_rate_fault_blocks_affected_entry_and_fails_reconciliation(self):
        entries = [{"port_id": "alpha", "port": 443}, {"port_id": "beta", "port": 8443}]
        manager = mock.Mock(root=self.root)
        manager.list.return_value = entries
        manager.recover.return_value = []
        policies = mock.Mock()
        policies.reconcile.return_value = []
        rates = mock.Mock()
        rates.reconcile.return_value = [{"port_id": "alpha", "state": "fault"}, {"port_id": "beta", "state": "unlimited"}]
        app = cli.Application(manager, policies=policies, rates=rates, output=io.StringIO())
        with self.assertRaisesRegex(ValueError, "限速执行|Rate enforcement"):
            cli.reconcile_once(app)
        policies.reconcile.assert_called_once_with(entries, defer_queue_drain=True)
        rates.reconcile.assert_called_once_with(entries)
        policies.block_runtime.assert_called_once_with(entries[0], "rate_enforcement_fault")
        self.assertFalse(self.lock_is_held())

    def test_unlimited_rate_state_is_valid_and_does_not_block_entry(self):
        entries = [{"port_id": "alpha", "port": 443}]
        manager = mock.Mock(root=self.root)
        manager.list.return_value = entries
        manager.recover.return_value = []
        policies = mock.Mock()
        policies.reconcile.return_value = [{"port_id": "alpha", "state": "active"}]
        rates = mock.Mock()
        rates.reconcile.return_value = [{"port_id": "alpha", "state": "unlimited"}]
        app = cli.Application(manager, policies=policies, rates=rates, output=io.StringIO())
        result = cli.reconcile_once(app)
        self.assertEqual(result["rates"], rates.reconcile.return_value)
        self.assertEqual(result["policies"], policies.reconcile.return_value)
        policies.block_runtime.assert_not_called()
        self.assertFalse(self.lock_is_held())

    def test_startup_recovery_defers_core_starts_until_normal_reconciliation(self):
        manager = mock.Mock(root=self.root)
        manager.list.return_value = []
        manager.recover.return_value = []
        app = cli.Application(manager, output=io.StringIO())
        cli.reconcile_once(app, startup=True)
        manager.recover.assert_called_once_with(start_services=False)
        cli.reconcile_once(app)
        self.assertEqual(manager.recover.call_args_list, [mock.call(start_services=False), mock.call()])
        self.assertFalse(self.lock_is_held())

    def test_queue_drain_runs_after_rate_restoration_in_runtime_and_startup(self):
        for startup, expected in ((False, ["policy-defer", "rate", "policy-drain"]), (True, ["rate", "policy-drain"])):
            with self.subTest(startup=startup):
                manager = mock.Mock(root=self.root)
                manager.list.return_value = [{"port_id": "alpha", "port": 443}]
                manager.recover.return_value = []
                calls = []
                policies = mock.Mock()
                policies.reconcile.side_effect = lambda entries, **kwargs: calls.append("policy-defer" if kwargs.get("defer_queue_drain") else "policy-drain") or []
                rates = mock.Mock()
                rates.reconcile.side_effect = lambda entries: calls.append("rate") or []
                app = cli.Application(manager, policies=policies, rates=rates, output=io.StringIO())
                cli.reconcile_once(app, startup=startup)
                self.assertEqual(calls, expected)

    def test_deferred_recovery_starts_service_without_lock_then_recovers_again(self):
        manager = mock.Mock(root=self.root)
        manager.history.return_value = [{"status": "restored"}]
        results = iter(([{"status": "restored_awaiting_start"}], [{"status": "restored"}]))

        def recover():
            self.assertTrue(self.lock_is_held())
            return next(results)

        manager.recover.side_effect = recover
        services = mock.Mock()

        def start(argv):
            self.assertEqual(argv, ["systemctl", "start", "v2ray-agent-port-policy.service"])
            self.assertFalse(self.lock_is_held(), "startup reconciliation must acquire the shared lock")

        services._run.side_effect = start
        app = cli.Application(manager, services=services, output=io.StringIO())
        result = cli.recover_once(app)
        self.assertEqual(manager.recover.call_count, 2)
        manager.history.assert_called_once_with()
        services._run.assert_called_once()
        self.assertEqual(result[-1]["status"], "restored")
        self.assertFalse(self.lock_is_held())

    def test_deferred_reconciliation_retries_only_once_after_unlocked_start(self):
        for final_status in ("restored", "restored_awaiting_start"):
            with self.subTest(final_status=final_status):
                manager = mock.Mock(root=self.root)
                manager.list.return_value = []
                manager.recover.side_effect = [[{"status": "restored_awaiting_start"}], [{"status": final_status}]]
                services = mock.Mock()
                services._run.side_effect = lambda argv: self.assertFalse(self.lock_is_held())
                policies = mock.Mock()
                policies.reconcile.return_value = []
                app = cli.Application(manager, policies=policies, services=services, output=io.StringIO())
                if final_status == "restored":
                    result = cli.reconcile_once(app)
                    self.assertEqual(result["recovery"], [{"status": "restored"}])
                    self.assertEqual(policies.reconcile.call_args_list, [mock.call([], defer_queue_drain=True), mock.call([])])
                else:
                    with self.assertRaisesRegex(ValueError, "恢复等待|Recovery awaits"):
                        cli.reconcile_once(app)
                    policies.reconcile.assert_not_called()
                self.assertEqual(manager.recover.call_count, 2)
                services._run.assert_called_once_with(["systemctl", "start", "v2ray-agent-port-policy.service"])
                self.assertFalse(self.lock_is_held())

    def test_deferred_recovery_preserves_inherited_lock_and_does_not_start_service(self):
        for operation in (cli.recover_once, cli.reconcile_once):
            with self.subTest(operation=operation.__name__):
                manager = mock.Mock(root=self.root)
                manager.recover.return_value = [{"status": "restored_awaiting_start"}]
                services = mock.Mock()
                app = cli.Application(manager, services=services, output=io.StringIO())
                with open(self.root / ".write.lock", "a+") as owner:
                    fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
                    os.environ["PORT_MANAGER_LOCK_FD"] = str(owner.fileno())
                    with self.assertRaisesRegex(ValueError, "调用者写锁|caller's writer lock"):
                        operation(app)
                    self.assertTrue(self.lock_is_held(), "a nested operation must not release the caller's lock")
                    manager.recover.assert_called_once_with()
                    services._run.assert_not_called()
                    fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
                os.environ.pop("PORT_MANAGER_LOCK_FD", None)
                self.assertFalse(self.lock_is_held())


if __name__ == "__main__":
    unittest.main()
