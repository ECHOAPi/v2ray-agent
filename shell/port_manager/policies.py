"""Persistent, fail-closed port quotas. Caller holds the common installer lock.

Accounting point: inet input/output, excluding loopback. A packet which passes
the administrative/time gate is counted before the shared quota test (including
the packet which crosses the quota). Both address families and directions use
one named quota. No proxy credentials are stored here.

Only the v2ray_agent_ports table is owned by this module. Real kernel, firewall
reload and transfer qualification is still required on the deployment host.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

TABLE = "v2ray_agent_ports"
OWNER = "v2ray-agent-port-policy-v1"
SERVICE = "v2ray-agent-port-policy.service"
LEASE_SECONDS = 30
UTC = dt.timezone.utc
FIELDS = {"quota_bytes", "expires_at", "timezone", "paused"}


class PolicyError(ValueError):
    pass


def _now():
    return dt.datetime.now(UTC)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def parse_expiry(value, timezone="Asia/Shanghai"):
    """Date-only values include that complete local date; timestamps need zone."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyError("expires_at must be a date or an ISO timestamp")
    try:
        zone = ZoneInfo(timezone)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parsed = dt.datetime.combine(dt.date.fromisoformat(value) + dt.timedelta(days=1),
                                         dt.time(), zone)
        else:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timestamp needs UTC offset")
        return parsed.astimezone(UTC).isoformat()
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise PolicyError("invalid expiry/timezone: " + str(exc)) from exc


def _cycle(now, timezone):
    local = now.astimezone(ZoneInfo(timezone))
    month = local.month % 12 + 1
    year = local.year + (local.month == 12)
    boundary = dt.datetime(year, month, 1, tzinfo=ZoneInfo(timezone)).astimezone(UTC)
    return local.strftime("%Y-%m"), int(boundary.timestamp())


def _token(port_id):
    return "p" + hashlib.sha256(port_id.encode()).hexdigest()[:20]


def _mapping(entry):
    # Keep only public topology, never credentials/config content.
    return {k: entry[k] for k in ("port_id", "core", "port", "listen", "protocols")}


def _validate_entry(entry, others=()):
    if not entry.get("supported") or entry.get("kind") not in {
            "xray-reality", "xray-xhttp", "xray-reality-forward", "sing-box-reality",
            "sing-box-hysteria2", "sing-box-tuic"}:
        raise PolicyError("entry is not an adapted independent public listener: " + str(entry.get("reason", "")))
    if not isinstance(entry.get("port_id"), str) or not entry["port_id"]:
        raise PolicyError("entry has no stable port_id")
    if type(entry.get("port")) is not int or not 1 <= entry["port"] <= 65535:
        raise PolicyError("invalid listener port")
    if not entry.get("protocols") or not set(entry["protocols"]).issubset({"tcp", "udp"}):
        raise PolicyError("unsupported transport")
    try:
        address = ipaddress.ip_address(entry["listen"] or "0.0.0.0")
    except (KeyError, ValueError) as exc:
        raise PolicyError("listener must use an explicit IP or wildcard address") from exc
    if address.is_loopback or address.is_multicast:
        raise PolicyError("loopback/shared listeners cannot be metered")
    for other in others:
        if other["port_id"] == entry["port_id"]:
            continue
        if other.get("port") == entry["port"] and set(other.get("protocols", [])) & set(entry["protocols"]):
            # Conservatively reject even separate addresses: wildcard dual-stack and
            # externally mapped topology must be qualified explicitly first.
            raise PolicyError("ambiguous port/address/transport mapping")


def _normalise_change(current, changes):
    if not isinstance(changes, dict) or set(changes) - FIELDS:
        raise PolicyError("only quota, expiry, timezone and pause may be changed in a batch")
    result = {key: current[key] for key in FIELDS}
    result.update(changes)
    quota = result["quota_bytes"]
    if quota is not None and (type(quota) is not int or not 0 <= quota <= 2**63 - 1):
        raise PolicyError("quota_bytes must be null or a nonnegative 64-bit integer")
    if type(result["paused"]) is not bool:
        raise PolicyError("paused must be boolean")
    try:
        ZoneInfo(result["timezone"])
    except (TypeError, ValueError, ZoneInfoNotFoundError) as exc:
        raise PolicyError("invalid management timezone") from exc
    if "timezone" in changes and current.get("version", 0) and result["timezone"] != current["timezone"]:
        raise PolicyError("changing an enrolled timezone requires a separate audited cycle migration")
    if "expires_at" in changes:
        result["expires_at"] = parse_expiry(changes["expires_at"], result["timezone"])
    return result


class PolicyManager:
    def __init__(self, root="/etc/v2ray-agent", runner=None, *, clock=None):
        self.root = Path(root).absolute()
        self.state_dir = self.root / "port-manager"
        self.path = self.state_dir / "policies.sqlite3"
        self.runner = runner
        self.clock = clock or _now
        self.db = None

    def _open(self, create=True):
        if self.db is not None:
            return self.db
        if not create and not self.path.exists():
            return None
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_dir.is_symlink() or self.path.is_symlink():
            raise PolicyError("policy state must not be a symlink")
        os.chmod(self.state_dir, 0o700)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS ports (
              port_id TEXT PRIMARY KEY, mapping TEXT NOT NULL,
              quota_bytes INTEGER, expires_at TEXT, timezone TEXT NOT NULL,
              paused INTEGER NOT NULL DEFAULT 0, expired INTEGER NOT NULL DEFAULT 0,
              cycle TEXT NOT NULL, used_up INTEGER NOT NULL DEFAULT 0,
              used_down INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1,
              generation TEXT, last_up INTEGER NOT NULL DEFAULT 0,
              last_down INTEGER NOT NULL DEFAULT 0, fault TEXT,
              migration INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cycles (
              port_id TEXT NOT NULL, cycle TEXT NOT NULL,
              used_up INTEGER NOT NULL, used_down INTEGER NOT NULL,
              closed_at TEXT NOT NULL, PRIMARY KEY(port_id,cycle)
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS journal (
              batch_id TEXT PRIMARY KEY, phase TEXT NOT NULL,
              before_json TEXT NOT NULL, after_json TEXT NOT NULL,
              created_at TEXT NOT NULL, error TEXT
            );
        """)
        return self.db

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def _run(self, args, *, input=None, check=True):
        try:
            if self.runner is None:
                result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=30)
            elif hasattr(self.runner, "run"):
                result = self.runner.run(args, input=input)
            else:
                result = self.runner(args, input=input, text=True, capture_output=True, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise PolicyError("policy backend command failed: " + args[0]) from exc
        if check and result.returncode:
            # Do not expose potentially secret system command output.
            raise PolicyError("policy backend command failed: " + " ".join(args[:4]))
        return result

    def _rows(self):
        if self.db is None and not self.path.exists():
            return []
        if self.db is None:
            with sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True) as db:
                db.row_factory = sqlite3.Row
                rows = [dict(x) for x in db.execute("SELECT * FROM ports ORDER BY port_id")]
        else:
            rows = [dict(x) for x in self.db.execute("SELECT * FROM ports ORDER BY port_id")]
        for row in rows:
            row["paused"] = bool(row["paused"])
            row["expired"] = bool(row["expired"])
            row["mapping"] = json.loads(row["mapping"])
        return rows

    def _meta(self, key, default=None):
        if self.db is None:
            if not self.path.exists():
                return default
            with sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True) as db:
                value = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        else:
            value = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(value[0]) if value else default

    def _set_meta(self, key, value):
        self._open().execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, _json(value)))

    @staticmethod
    def _default(entry, now):
        return {"port_id": entry["port_id"], "mapping": _mapping(entry), "quota_bytes": None,
                "expires_at": None, "timezone": "Asia/Shanghai", "paused": False,
                "expired": False, "cycle": _cycle(now, "Asia/Shanghai")[0],
                "used_up": 0, "used_down": 0, "version": 0, "generation": None,
                "last_up": 0, "last_down": 0, "fault": None, "migration": 0}

    def _save(self, row):
        values = dict(row)
        values["mapping"] = _json(values["mapping"])
        columns = list(values)
        self._open().execute("INSERT OR REPLACE INTO ports (" + ",".join(columns) + ") VALUES (" +
                             ",".join("?" for _ in columns) + ")", [values[k] for k in columns])

    def _reasons(self, row, now=None):
        now = now or self.clock()
        reasons = []
        if row["paused"]:
            reasons.append("paused")
        if row["expired"] or (row["expires_at"] and now >= dt.datetime.fromisoformat(row["expires_at"])):
            reasons.append("expired")
        if row["quota_bytes"] is not None and row["used_up"] + row["used_down"] >= row["quota_bytes"]:
            reasons.append("quota_exhausted")
        if row["fault"]:
            reasons.append("fault:" + row["fault"])
        if row["migration"]:
            reasons.append("port_migration")
        return reasons

    def preview(self, entries, changes):
        if not entries or len({x["port_id"] for x in entries}) != len(entries):
            raise PolicyError("select one or more unique entries")
        by_id = {row["port_id"]: row for row in self._rows()}
        # Selection does not hide collisions with other enrolled listeners.
        existing = [dict(row["mapping"], supported=True, kind="xray-reality") for row in by_id.values()]
        from .core import inventory
        existing += inventory(self.root)
        per_entry = not set(changes).issubset(FIELDS)
        if per_entry and set(changes) != {entry["port_id"] for entry in entries}:
            raise PolicyError("per-entry changes must match the complete selection")
        result = []
        now = self.clock()
        for entry in entries:
            _validate_entry(entry, entries + existing)
            old = by_id.get(entry["port_id"], self._default(entry, now))
            delta = changes[entry["port_id"]] if per_entry else changes
            new = dict(old)
            new.update(_normalise_change(old, delta))
            if "expires_at" in delta:
                new["expired"] = bool(new["expires_at"] and now >= dt.datetime.fromisoformat(new["expires_at"]))
            if old["version"] == 0:
                new["cycle"] = _cycle(now, new["timezone"])[0]
            new["version"] += 1
            result.append({"port_id": entry["port_id"], "old": old, "new": new,
                           "used_bytes": new["used_up"] + new["used_down"],
                           "reasons": self._reasons(new, now),
                           "next_reset": _cycle(now, new["timezone"])[1]})
        return result

    def _nft(self):
        result = self._run(["nft", "-j", "list", "table", "inet", TABLE], check=False)
        if result.returncode:
            return None
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise PolicyError("nft returned invalid JSON") from exc

    @staticmethod
    def _fingerprint(snapshot):
        def stable(obj):
            if isinstance(obj, list):
                return [stable(x) for x in obj if not (isinstance(x, dict) and "metainfo" in x)]
            if isinstance(obj, dict):
                return {k: stable(v) for k, v in obj.items() if k not in {"handle", "packets", "used"}
                        and not (k == "bytes" and ("packets" in obj or "counter" in obj))}
            return obj
        return hashlib.sha256(_json(stable(snapshot)).encode()).hexdigest()

    def _owned(self, snapshot):
        tables = [x["table"] for x in snapshot.get("nftables", []) if "table" in x]
        if len(tables) != 1 or tables[0].get("name") != TABLE or tables[0].get("comment") != OWNER:
            raise PolicyError("refusing to modify an unowned nftables table")

    def _apply(self, script):
        self._run(["nft", "--check", "-f", "-"], input=script)
        self._run(["nft", "-f", "-"], input=script)

    def probe(self, *, enrollment=False):
        if self.runner is None and os.geteuid() != 0:
            raise PolicyError("root privileges are required to enforce policies")
        if self._run(["systemctl", "show", "--property=Version", "--value"], check=False).returncode:
            raise PolicyError("systemd is required")
        if self._run(["systemd-detect-virt", "--container", "--quiet"], check=False).returncode == 0:
            raise PolicyError("container network mappings are not supported")
        if enrollment and self._run(["systemctl", "is-enabled", SERVICE], check=False).returncode:
            raise PolicyError("install and enable the persistent port policy service before enrollment")
        if enrollment and self._run(["systemctl", "is-active", SERVICE], check=False).returncode:
            raise PolicyError("port policy background service is not active")
        if self._run(["timedatectl", "show", "--property=NTPSynchronized", "--value"]).stdout.strip() != "yes":
            raise PolicyError("synchronized system time is required for automatic expiry")
        result = self._run(["nft", "-j", "list", "ruleset"])
        try:
            rules = json.loads(result.stdout).get("nftables", [])
        except ValueError as exc:
            raise PolicyError("cannot inspect active nftables ownership") from exc
        active = []
        for name in ("ufw", "firewalld", "nftables"):
            if self._run(["systemctl", "is-active", name], check=False).returncode == 0:
                active.append(name)
        if len(active) > 1 or active == ["nftables"]:
            raise PolicyError("conflicting or unadapted firewall managers")
        allowed = {TABLE, "v2ray_agent_tc"}
        if active == ["firewalld"]:
            allowed.add("firewalld")
        if active == ["ufw"]:
            # UFW's xtables-nft backend owns these exact filter tables. Legacy
            # iptables is intentionally rejected instead of guessing coexistence.
            if "nf_tables" not in self._run(["iptables", "--version"]).stdout:
                raise PolicyError("UFW requires the nftables backend")
            allowed.add("filter")
        for item in rules:
            if "table" in item and item["table"].get("name") not in allowed:
                raise PolicyError("unadapted nftables table: " + str(item["table"].get("name")))
            if any(word in _json(item) for word in ('"dnat"', '"redirect"', '"flowtable"', '"notrack"')):
                raise PolicyError("NAT, redirect, untracked flows or flow offload makes accounting ambiguous")
            chain = item.get("chain", {})
            if active == ["ufw"] and chain.get("table") == "filter" and not (
                    chain.get("name") in {"INPUT", "OUTPUT", "FORWARD"} or
                    chain.get("name", "").startswith("ufw-")):
                raise PolicyError("custom chains in UFW filter table are not adapted")
        if not active:
            for command in ("iptables-save", "ip6tables-save"):
                legacy = self._run([command], check=False)
                if legacy.returncode == 0 and re.search(r"(?m)^(?:-A |:\S+ DROP\b)", legacy.stdout):
                    raise PolicyError("unmanaged iptables filtering is not adapted")
        # Parser+kernel capability probe, never installs a probe table.
        self._run(["nft", "--check", "-f", "-"], input=(
            'add table inet v2ray_agent_policy_probe\n'
            'add quota inet v2ray_agent_policy_probe q { over 1 bytes used 0 bytes; }\n'
            'add counter inet v2ray_agent_policy_probe c\n'
            'add chain inet v2ray_agent_policy_probe i { type filter hook input priority -10; policy accept; }\n'
            'add rule inet v2ray_agent_policy_probe i meta time >= 1 drop\n'
            'add rule inet v2ray_agent_policy_probe i meta l4proto { tcp, udp } th dport 65535 counter name c quota name q drop\n'
            'delete table inet v2ray_agent_policy_probe\n'))
        return {"supported": True, "firewall": active[0] if active else "none", "table": TABLE}

    def _matches(self, row, direction):
        mapping = row["mapping"]
        address = ipaddress.ip_address(mapping["listen"] or "0.0.0.0")
        interface = 'iifname != "lo"' if direction == "up" else 'oifname != "lo"'
        flow = "ct direction original" if direction == "up" else "ct direction reply"
        field = "daddr" if direction == "up" else "saddr"
        portfield = "dport" if direction == "up" else "sport"
        family = ""
        if not address.is_unspecified:
            family = ("ip" if address.version == 4 else "ip6") + " " + field + " " + str(address)
        elif address.version == 4:
            family = "meta nfproto ipv4"
        # IPv6 wildcard is deliberately one combined v4/v6 entry. Inventory must
        # reject separate listeners at the same transport/port before enrollment.
        return [f"{interface} {family} {flow} {proto} {portfield} {mapping['port']}" for proto in mapping["protocols"]]

    def _rules(self, rows, *, frozen=False):
        now = self.clock()
        lease = int(now.timestamp()) + LEASE_SECONDS
        lines = []
        # Old mappings stay blocked through a port transaction. The next daemon
        # tick (after the shared lock is released) can remove them once inventory
        # agrees with the committed mapping. This closes the pre-restart gap.
        for mapping in self._meta("retired_mappings", []) + self._meta("emergency_mappings", []):
            for direction, chain in (("up", "input"), ("down", "output")):
                for match in self._matches({"mapping": mapping}, direction):
                    lines.append(f"add rule inet {TABLE} {chain} {match} drop")
        for row in rows:
            token = _token(row["port_id"])
            names = token + "_" + row["generation"]
            deadline = min(lease, _cycle(now, row["timezone"])[1])
            if row["expires_at"]:
                deadline = min(deadline, int(dt.datetime.fromisoformat(row["expires_at"]).timestamp()))
            for direction, chain, suffix in (("up", "input", "u"), ("down", "output", "d")):
                for match in self._matches(row, direction):
                    prefix = f"add rule inet {TABLE} {chain} {match}"
                    if frozen or self._reasons(row, now):
                        lines.append(prefix + " drop")
                    else:
                        # Expiry, month boundary and daemon heartbeat fail closed
                        # inside packet processing, including established flows.
                        lines.append(prefix + f" meta time >= {deadline} drop")
                        lines.append(prefix + f" meta time < {int(now.timestamp()) - 5} drop")
                        action = f" counter name {names}_{suffix}"
                        if row["quota_bytes"] is not None:
                            action += f" quota name {names}_q drop"
                        lines.append(prefix + action)
        return "\n".join(lines) + "\n"

    def _remember_kernel(self):
        snapshot = self._nft()
        if snapshot is None:
            raise PolicyError("policy table disappeared after application")
        self._owned(snapshot)
        self._set_meta("fingerprint", self._fingerprint(snapshot))
        self._set_meta("lease_until", int(self.clock().timestamp()) + LEASE_SECONDS)
        self._open().commit()

    def _refresh(self, rows, *, frozen=False):
        if not rows:
            return
        snapshot = self._nft()
        if snapshot is None:
            raise PolicyError("policy table is missing")
        self._owned(snapshot)
        if not frozen:
            # Revoke clean-shutdown trust durably BEFORE permitting any packet.
            self._set_meta("clean_shutdown", False)
            self._open().commit()
        script = f"flush chain inet {TABLE} input\nflush chain inet {TABLE} output\n"
        self._apply(script + self._rules(rows, frozen=frozen))
        self._remember_kernel()

    def _rebuild(self, rows, *, frozen=False):
        snapshot = self._nft()
        script = ""
        if snapshot is not None:
            self._owned(snapshot)
            script += f"delete table inet {TABLE}\n"
        script += f'add table inet {TABLE} {{ comment "{OWNER}"; }}\n'
        for chain in ("input", "output"):
            script += f"add chain inet {TABLE} {chain} {{ type filter hook {chain} priority -10; policy accept; }}\n"
        for row in rows:
            row["generation"] = uuid.uuid4().hex[:12]
            row["last_up"] = row["used_up"]
            row["last_down"] = row["used_down"]
            names = _token(row["port_id"]) + "_" + row["generation"]
            for suffix, field in (("u", "used_up"), ("d", "used_down")):
                script += f"add counter inet {TABLE} {names}_{suffix} {{ packets 0 bytes {row[field]}; }}\n"
            if row["quota_bytes"] is not None:
                limit = max(1, row["quota_bytes"])
                used = row["used_up"] + row["used_down"]
                script += f"add quota inet {TABLE} {names}_q {{ over {limit} bytes used {used} bytes; }}\n"
        if not frozen:
            self._set_meta("clean_shutdown", False)
            self._open().commit()
        self._apply(script + self._rules(rows, frozen=frozen))
        for row in rows:
            self._save(row)
        self._remember_kernel()
        self._set_meta("cycle_transition", False)
        self._open().commit()

    def _fault_all(self, reason):
        db = self._open()
        db.execute("UPDATE ports SET fault=COALESCE(fault,?)", (reason,))
        db.commit()

    def _sample(self, *, expected=True):
        rows = self._rows()
        if not rows:
            return rows
        snapshot = self._nft()
        if snapshot is None:
            self._fault_all("missing_counter_generation")
            return self._rows()
        self._owned(snapshot)
        if expected and self._meta("fingerprint") != self._fingerprint(snapshot):
            self._fault_all("kernel_rules_changed")
        counters = {item["counter"]["name"]: item["counter"] for item in snapshot.get("nftables", []) if "counter" in item}
        for row in self._rows():
            names = _token(row["port_id"]) + "_" + str(row["generation"])
            for suffix, total, last in (("u", "used_up", "last_up"), ("d", "used_down", "last_down")):
                counter = counters.get(names + "_" + suffix)
                if counter is None or type(counter.get("bytes")) is not int or counter["bytes"] < row[last]:
                    row["fault"] = row["fault"] or "missing_or_reset_counter"
                else:
                    row[total] += counter["bytes"] - row[last]
                    row[last] = counter["bytes"]
            self._save(row)
        self._open().commit()
        return self._rows()

    def _freeze_sample(self):
        try:
            return self._freeze_sample_impl()
        except Exception:
            self._stop_cores()
            raise

    def _stop_cores(self):
        """Last resort when owned packet blocking cannot be established."""
        failures = []
        for core in sorted({row["mapping"]["core"] for row in self._rows()} & {"xray", "sing-box"}):
            try:
                self._run(["systemctl", "stop", core + ".service"])
            except PolicyError:
                failures.append(core)
        if failures:
            raise PolicyError("cannot establish port blocking or stop affected cores; manual recovery required")

    def _freeze_sample_impl(self):
        rows = self._rows()
        if not rows:
            return rows
        snapshot = self._nft()
        if snapshot is not None:
            # Keep counters/quota while atomically stopping packets, then settle.
            # Never sample then replace a live counter (that would refund a race).
            self._sample()
            self._refresh(self._rows(), frozen=True)
            return self._sample()
        if not self._meta("clean_shutdown", False):
            self._fault_all("missing_counter_generation")
        self._rebuild(self._rows(), frozen=True)
        self._set_meta("clean_shutdown", False)
        self._open().commit()
        return self._rows()

    def _advance_time(self, rows):
        now = self.clock()
        prior = self._meta("last_wall")
        mono = time.monotonic()
        previous_mono = self._meta("last_mono")
        boot = self._run(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()
        previous_boot = self._meta("boot_id")
        abnormal = prior is not None and now.timestamp() < prior - 5
        if previous_boot == boot and prior is not None and previous_mono is not None:
            abnormal |= abs((now.timestamp() - prior) - (mono - previous_mono)) > 300
        for row in rows:
            if abnormal:
                row["fault"] = row["fault"] or "clock_anomaly"
            if row["expires_at"] and now >= dt.datetime.fromisoformat(row["expires_at"]):
                row["expired"] = True
            current, _ = _cycle(now, row["timezone"])
            if current < row["cycle"]:
                row["fault"] = row["fault"] or "clock_anomaly"
            elif current > row["cycle"] and not row["fault"]:
                db = self._open()
                existing = db.execute("SELECT 1 FROM cycles WHERE port_id=? AND cycle=?", (row["port_id"], row["cycle"])).fetchone()
                if existing:
                    row["fault"] = "duplicate_cycle"
                else:
                    db.execute("INSERT INTO cycles VALUES (?,?,?,?,?)", (row["port_id"], row["cycle"], row["used_up"], row["used_down"], now.isoformat()))
                    # Baselines belong to the still-installed frozen generation.
                    # Preserve them until _rebuild seeds the new generation, so
                    # a crash here cannot import last month's bytes a second time.
                    row.update(cycle=current, used_up=0, used_down=0)
                    self._set_meta("cycle_transition", True)
            self._save(row)
        self._set_meta("last_wall", max(now.timestamp(), prior or 0))
        self._set_meta("last_mono", mono)
        self._set_meta("boot_id", boot)
        self._open().commit()
        return self._rows()

    def _drain_blocked(self, rows):
        try:
            from .rate_limits import RateLimiter
        except ImportError:
            return
        limiter = RateLimiter(self.root, runner=self.runner)
        for row in rows:
            if self._reasons(row):
                try:
                    limiter.on_policy_block(row["mapping"])
                except Exception as exc:
                    self._open().execute("UPDATE ports SET fault=COALESCE(fault,?) WHERE port_id=?",
                                         ("rate_queue_drain_failed", row["port_id"]))
                    self._open().commit()
                    raise PolicyError("entry is blocked; rate queue drain needs recovery") from exc

    def batch_update(self, entries, changes):
        self.preview(entries, changes)  # Entire batch validated before side effects.
        self.probe(enrollment=True)
        self.reconcile(entries, _allow_missing_entries=True)
        old_rows = self._freeze_sample()
        preview = self.preview(entries, changes)  # Fresh usage and versions, under lock.
        batch = uuid.uuid4().hex
        before = {row["port_id"]: {key: row[key] for key in FIELDS | {"expired"}} for row in old_rows}
        after = {item["port_id"]: {key: item["new"][key] for key in FIELDS | {"expired"}} for item in preview}
        db = self._open()
        db.execute("INSERT INTO journal VALUES (?,?,?,?,?,NULL)", (batch, "prepared", _json(before), _json(after), self.clock().isoformat()))
        db.commit()
        try:
            for item in preview:
                self._save(item["new"])
            db.execute("UPDATE journal SET phase='applying' WHERE batch_id=?", (batch,))
            db.commit()
            self._rebuild(self._rows())
            self._drain_blocked(self._rows())
            db.execute("UPDATE journal SET phase='complete' WHERE batch_id=?", (batch,))
            db.commit()
        except Exception as exc:
            try:
                self._recover_batch(batch, before)
            except Exception:
                self._fault_all("batch_recovery_required")
                db.execute("UPDATE journal SET phase='recovery_required',error=? WHERE batch_id=?", (type(exc).__name__, batch))
                db.commit()
                raise PolicyError("batch failed and recovery is required; ports remain conservatively blocked") from exc
            raise PolicyError("batch failed; previous policy restored without refunding usage") from exc
        return {"batch_id": batch, "status": self.status(entries)}

    def _recover_batch(self, batch, before):
        self._freeze_sample()
        for row in self._rows():
            if row["port_id"] in before:
                row.update(before[row["port_id"]])
                # A rollback cannot erase an expiry observed after the snapshot.
                if row["expires_at"] and self.clock() >= dt.datetime.fromisoformat(row["expires_at"]):
                    row["expired"] = True
                row["version"] += 1
                self._save(row)
            else:
                # Newly enrolled rows retain measured usage and a safe paused
                # state after failure; no identity or accounting history is lost.
                row.update(quota_bytes=None, expires_at=None, paused=True)
                self._save(row)
        self._open().commit()
        self._rebuild(self._rows())
        self._open().execute("UPDATE journal SET phase='rolled_back' WHERE batch_id=?", (batch,))
        self._open().commit()

    def reconcile(self, entries, _allow_missing_entries=False, defer_queue_drain=False):
        if not self._rows():
            return []
        db = self._open()
        if self._meta("cycle_transition", False):
            self._fault_all("interrupted_cycle_transition")
        for pending in db.execute("SELECT * FROM journal WHERE phase NOT IN ('complete','rolled_back')").fetchall():
            self._recover_batch(pending["batch_id"], json.loads(pending["before_json"]))
        known = {e["port_id"]: e for e in entries}
        emergency = self._meta("emergency_mappings", [])
        for row in self._rows():
            current = known.get(row["port_id"])
            if current is None and _allow_missing_entries:
                continue
            if current is None or _mapping(current) != row["mapping"]:
                db.execute("UPDATE ports SET fault=COALESCE(fault,?) WHERE port_id=?", ("listener_mapping_changed", row["port_id"]))
                if current is not None:
                    try:
                        _validate_entry(current)
                    except PolicyError:
                        # Cannot classify safely: stop only its affected core,
                        # never reinterpret an unknown shared listener mapping.
                        core = row["mapping"]["core"]
                        if core in {"xray", "sing-box"}:
                            self._run(["systemctl", "stop", core + ".service"])
                    else:
                        mapping = _mapping(current)
                        if mapping not in emergency:
                            emergency.append(mapping)
        self._set_meta("emergency_mappings", emergency)
        if not _allow_missing_entries and all(
                row["port_id"] in known and _mapping(known[row["port_id"]]) == row["mapping"]
                and not row["migration"] for row in self._rows()):
            self._set_meta("retired_mappings", [])
        db.commit()
        old = self._rows()
        try:
            self.probe()
            rows = self._freeze_sample()
            rows = self._advance_time(rows)
            if [(r["cycle"], r["generation"]) for r in rows] != [(r["cycle"], r["generation"]) for r in old]:
                self._rebuild(rows)
            else:
                self._refresh(rows)
            if not defer_queue_drain:
                self._drain_blocked(rows)
        except Exception as exc:
            self._fault_all("reconcile_failed")
            try:
                self._rebuild(self._rows(), frozen=True)
            except Exception:
                # This failure cannot be hidden behind a saved-policy status.
                self._set_meta("enforcement_failed", True)
                db.commit()
                self._stop_cores()
            raise PolicyError("policy reconciliation failed; check actual kernel/service state") from exc
        self._set_meta("enforcement_failed", False)
        db.commit()
        return self.status(entries)

    tick = reconcile

    def block_runtime(self, entry, reason="rate_execution_failed"):
        """Fail closed for a failed speed policy, including rate-only entries."""
        _validate_entry(entry)
        self._freeze_sample()
        row = next((row for row in self._rows() if row["port_id"] == entry["port_id"]),
                   self._default(entry, self.clock()))
        row["fault"] = row["fault"] or str(reason)[:120]
        row["version"] = max(1, row["version"])
        self._save(row)
        self._open().commit()
        try:
            self._rebuild(self._rows())
        except Exception as exc:
            core = entry["core"]
            if core in {"xray", "sing-box"}:
                self._run(["systemctl", "stop", core + ".service"])
            raise PolicyError("rate enforcement failed; affected core stopped because port blocking failed") from exc
        return self.status([entry])[0]

    def prepare_shutdown(self):
        """Call from the daemon's finalizer after exiting its tick loop, locked.

        Freeze before settlement so a clean boot may restore this exact ledger;
        a crash anywhere before the marker instead takes the uncertainty path.
        """
        if not self._rows():
            return
        self._freeze_sample()
        self._set_meta("clean_shutdown", True)
        self._open().commit()

    def before_port_change(self, entry, force=False):
        rows = self._rows()
        if not any(row["port_id"] == entry["port_id"] for row in rows):
            if not force:
                return
            _validate_entry(entry)
            self.probe(enrollment=True)
            self._freeze_sample()
            row = self._default(entry, self.clock())
            row.update(version=1, migration=1)
            self._save(row)
            self._open().commit()
            self._rebuild(self._rows())
            return
        self._freeze_sample()
        self._open().execute("UPDATE ports SET migration=1 WHERE port_id=?", (entry["port_id"],))
        self._open().commit()
        self._refresh(self._rows())

    def after_port_change(self, entry, new_port, defer_queue_drain=False):
        row = next((row for row in self._rows() if row["port_id"] == entry["port_id"]), None)
        if row is None:
            return
        candidate = dict(entry, port=new_port)
        _validate_entry(candidate)
        self._freeze_sample()
        row = next(row for row in self._rows() if row["port_id"] == entry["port_id"])
        retired = self._meta("retired_mappings", [])
        if row["mapping"] != _mapping(candidate):
            retired.append(row["mapping"])
        self._set_meta("retired_mappings", [mapping for mapping in retired if mapping != _mapping(candidate)])
        row["mapping"] = _mapping(candidate)
        row["migration"] = 0
        self._save(row)
        self._open().commit()
        self._rebuild(self._rows())
        if not defer_queue_drain:
            self._drain_blocked(self._rows())

    def status(self, entries):
        by_id = {row["port_id"]: row for row in self._rows()}
        try:
            snapshot = self._nft() if by_id else None
        except PolicyError:
            snapshot = None
        effective = bool(snapshot and self._meta("fingerprint") == self._fingerprint(snapshot)
                         and not self._meta("enforcement_failed", False))
        now = self.clock()
        lease_ok = bool(by_id and self._meta("lease_until", 0) > now.timestamp())
        results = []
        for entry in entries:
            row = by_id.get(entry["port_id"])
            if row is None:
                results.append({"port_id": entry["port_id"], "managed": False, "effective": False,
                                "state": "unmanaged", "reasons": [], "quota_bytes": None,
                                "expires_at": None, "used_bytes": 0, "paused": False})
                continue
            result = dict(row)
            reasons = self._reasons(row, now)
            if not effective:
                reasons.append("execution_unverified")
            if not lease_ok:
                reasons.append("daemon_lease_elapsed")
            used = row["used_up"] + row["used_down"]
            result.update(managed=True, effective=effective, reasons=reasons,
                          available=effective and not reasons, used_bytes=used,
                          remaining_bytes=None if row["quota_bytes"] is None else max(0, row["quota_bytes"] - used),
                          next_reset=_cycle(now, row["timezone"])[1],
                          state="unverified" if not effective else ("blocked" if reasons else "active"))
            results.append(result)
        return results

    def history(self, port_id=None):
        if not self.path.exists():
            return []
        sql = "SELECT * FROM cycles"
        args = ()
        if port_id is not None:
            sql += " WHERE port_id=?"
            args = (port_id,)
        if self.db is not None:
            return [dict(row) for row in self.db.execute(sql + " ORDER BY cycle DESC,port_id", args)]
        with sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(sql + " ORDER BY cycle DESC,port_id", args)]

    def acknowledge_fault(self, entry, *, used_up, used_down, reason):
        """Explicit administrative correction; never lowers a trusted total.

        Deliberately not a batch field. The operator must establish the missing
        accounting window and record a reason before releasing a fault latch.
        """
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise PolicyError("a recorded accounting correction reason is required")
        self.probe(enrollment=True)
        self._freeze_sample()
        row = next((row for row in self._rows() if row["port_id"] == entry["port_id"]), None)
        if row is None:
            raise PolicyError("entry is not managed")
        if _mapping(entry) != row["mapping"]:
            raise PolicyError("repair the changed listener mapping before an accounting correction")
        from .core import inventory
        current = next((item for item in inventory(self.root) if item["port_id"] == entry["port_id"]), None)
        if current is None or _mapping(current) != row["mapping"] or not current.get("supported"):
            raise PolicyError("current listener identity must be verified before an accounting correction")
        if row["fault"] not in {None, "missing_counter_generation", "missing_or_reset_counter", "clock_anomaly",
                                "kernel_rules_changed", "interrupted_cycle_transition"}:
            raise PolicyError("this fault requires topology/backend recovery, not an accounting correction")
        for key, value in (("used_up", used_up), ("used_down", used_down)):
            if type(value) is not int or not row[key] <= value <= 2**63 - 1:
                raise PolicyError("accounting corrections must not reduce trusted usage")
            row[key] = value
        row["fault"] = None
        self._save(row)
        self._set_meta("emergency_mappings", [mapping for mapping in self._meta("emergency_mappings", [])
                                               if mapping["port_id"] != entry["port_id"]])
        self._set_meta("correction:" + uuid.uuid4().hex, {"port_id": entry["port_id"], "reason": reason,
                                                       "used_up": used_up, "used_down": used_down,
                                                       "at": self.clock().isoformat()})
        self._open().commit()
        self._rebuild(self._rows())
        return self.status([entry])[0]
