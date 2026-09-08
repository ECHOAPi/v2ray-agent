"""Bilingual menus and the systemd entry point for port management.

No input prompt runs while the shared writer lock is held. A confirmed preview
is checked against current inventory again after acquiring that lock.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import date, datetime, time as daytime, timedelta, timezone as dt_timezone
from decimal import Decimal
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


KEEP = object()
INVENTORY_FIELDS = ("port_id", "core", "file", "index", "tag", "port", "listen", "protocols", "kind", "supported", "reason")
_UNLIMITED = {"unlimited", "none", "无限额", "不限额"}


def parse_port(value):
    value = str(value).strip()
    if not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= 65535:
        raise ValueError("端口必须是 1–65535 的十进制整数 / Port must be an integer from 1 to 65535")
    return int(value)


def parse_quota(value):
    value = str(value).strip()
    if not value:
        return KEEP
    if value.lower() in _UNLIMITED:
        return None
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?|\.[0-9]+)\s*(GB|GiB)?", value, re.IGNORECASE)
    if not match:
        raise ValueError("额度请输入 GB 数值、显式 GiB 或 unlimited / Use GB, explicit GiB, or unlimited")
    multiplier = 1073741824 if (match.group(2) or "GB").lower() == "gib" else 1000000000
    result = Decimal(match.group(1)) * multiplier
    if result != result.to_integral_value() or result > 9223372036854775807:
        raise ValueError("额度须为有效的整数字节数 / Quota must fit an integer byte count")
    return int(result)


def parse_expiry(value, timezone="Asia/Shanghai"):
    value = str(value).strip()
    if not value:
        return KEEP
    if value.lower() in {"never", "none", "unlimited", "永不到期", "不过期"}:
        return None
    try:
        zone = ZoneInfo(timezone)
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            cutoff = datetime.combine(date.fromisoformat(value) + timedelta(days=1), daytime.min, zone)
        else:
            if not re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}", value):
                raise ValueError("timestamp format")
            cutoff = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=zone)
                # Reject nonexistent or ambiguous local wall times. Supplying an
                # explicit UTC offset makes the intended instant unambiguous.
                back = cutoff.astimezone(dt_timezone.utc).astimezone(zone)
                if back.replace(tzinfo=None) != cutoff.replace(tzinfo=None) or cutoff.utcoffset() != cutoff.replace(fold=1).utcoffset():
                    raise ValueError("ambiguous local time")
        return cutoff.astimezone(dt_timezone.utc).isoformat()
    except (ValueError, OverflowError, ZoneInfoNotFoundError) as exc:
        raise ValueError("到期时间无效；使用 YYYY-MM-DD 或带时区的 ISO 时间 / Invalid expiry date or ISO timestamp") from exc


def select_entries(value, entries, single=False):
    """Resolve IDs, #row indexes, or existing port lists/ranges without guessing."""
    entries = list(entries)
    tokens = [token.strip() for token in str(value).split(",")]
    if not tokens or any(not token for token in tokens):
        raise ValueError("请选择入口 / Select at least one entry")
    selected = []
    for token in tokens:
        match_ids = [entry for entry in entries if entry.get("port_id") == token]
        if match_ids:
            matches = match_ids
        elif token.startswith("#"):
            index = token[1:]
            if not re.fullmatch(r"[0-9]+", index) or not 1 <= int(index) <= len(entries):
                raise ValueError("列表编号不存在 / Unknown row number")
            matches = [entries[int(index) - 1]]
        else:
            explicit_port = token.startswith("port:")
            port_text = token[5:] if explicit_port else token
            if re.fullmatch(r"[0-9]+-[0-9]+", port_text):
                lower, upper = map(parse_port, port_text.split("-"))
                if lower > upper:
                    raise ValueError("端口范围倒置 / Reversed port range")
                matches = [entry for entry in entries if type(entry.get("port")) is int and lower <= entry["port"] <= upper]
                if not matches:
                    raise ValueError("范围内没有已有入口 / No existing entries in this range")
                counts = {}
                for entry in matches:
                    counts[entry["port"]] = counts.get(entry["port"], 0) + 1
                if any(count > 1 for count in counts.values()):
                    raise ValueError("端口号对应多个入口，请用 #编号 或 port_id / Ambiguous port; use #row or port_id")
            elif re.fullmatch(r"[0-9]+", port_text):
                port = parse_port(port_text)
                matches = [entry for entry in entries if entry.get("port") == port]
                row_match = entries[port - 1] if not explicit_port and port <= len(entries) else None
                if row_match is not None and matches and any(entry is not row_match for entry in matches):
                    raise ValueError("数字同时匹配编号和端口，请用 #编号 或 port:端口 / Ambiguous number; use #row or port:number")
                if not matches and row_match is not None:
                    matches = [row_match]
                if not matches:
                    raise ValueError("端口没有已有入口 / No existing entry at this port")
            else:
                raise ValueError("入口标识或选择格式无效 / Invalid entry identifier or selection")
        if len(matches) > 1 and not ("-" in token and not match_ids):
            raise ValueError("端口号对应多个入口，请用 #编号 或 port_id / Ambiguous port; use #row or port_id")
        for entry in matches:
            if any(previous.get("port_id") == entry.get("port_id") for previous in selected):
                raise ValueError("不能重复选择同一入口 / Duplicate entry selection")
            selected.append(entry)
    if single and len(selected) != 1:
        raise ValueError("本操作只允许选择一个入口 / Select exactly one entry")
    return selected


@contextmanager
def shared_lock(root, timeout=30):
    """Use the installer's lock, accepting only a verified inherited descriptor."""
    path = Path(root) / ".write.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    inherited = os.environ.get("PORT_MANAGER_LOCK_FD")
    try:
        own_stat = os.fstat(fd)
        if not stat.S_ISREG(own_stat.st_mode):
            raise ValueError("写锁必须是普通文件 / Writer lock must be a regular file")
        if inherited is not None:
            try:
                if not re.fullmatch(r"[0-9]+", inherited):
                    raise ValueError("invalid descriptor")
                inherited_fd = int(inherited)
                inherited_stat = os.fstat(inherited_fd)
                if (inherited_stat.st_dev, inherited_stat.st_ino) != (own_stat.st_dev, own_stat.st_ino):
                    raise ValueError("wrong inode")
                fcntl.flock(inherited_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, ValueError, OverflowError) as exc:
                raise ValueError("继承写锁校验失败 / Invalid inherited writer lock") from exc
            yield inherited_fd
            return
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("其他写操作正在进行，请稍后重试 / Another writer is active; retry later")
                time.sleep(0.1)
        try:
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def public_entry(entry):
    return {field: entry.get(field) for field in INVENTORY_FIELDS if field in entry}


def _awaiting_start(results):
    return any(row.get("status") == "restored_awaiting_start" for row in results or [])


def _require_recovered(results):
    if _awaiting_start(results):
        raise ValueError("恢复等待后台服务启动，请运行 --recover 后重试 / Recovery awaits the background service; run --recover and retry")


def _start_recovery_service(app):
    if os.environ.get("PORT_MANAGER_LOCK_FD") is not None:
        raise ValueError("恢复等待启动；请在释放调用者写锁后运行 --recover / Recovery awaits startup; release the caller's writer lock and run --recover")
    if app.services:
        app.services._run(["systemctl", "start", Services.unit])
    elif hasattr(app.manager, "runner"):
        result = app.manager.runner.run(["systemctl", "start", Services.unit])
        if result.returncode:
            raise ValueError("后台恢复服务启动失败 / Recovery service failed to start")
    else:
        raise ValueError("后台恢复服务启动器不可用 / Recovery service launcher unavailable")


def recover_once(app):
    with shared_lock(app.root):
        results = app.manager.recover()
    if _awaiting_start(results):
        _start_recovery_service(app)
        with shared_lock(app.root):
            results += app.manager.recover()
            _require_recovered(app.manager.history())
    return results


def _display(value):
    if value is None:
        return "unlimited"
    if isinstance(value, (list, dict, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    # Block terminal control sequences from customized inbound tags.
    return "".join(char if char.isprintable() else " " for char in str(value))


class Services:
    """Install only the module's dedicated unit and two named core drop-ins."""
    unit = "v2ray-agent-port-policy.service"

    def __init__(self, root, runner=None, unit_root="/etc/systemd/system"):
        self.root = Path(root).resolve()
        self.runner = runner
        self.unit_root = Path(unit_root)

    def _run(self, argv, required=True):
        try:
            result = self.runner.run(argv) if self.runner else subprocess.run(argv, text=True, capture_output=True, timeout=150)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("后台服务命令失败 / Background service command failed") from exc
        if required and result.returncode:
            raise ValueError("后台服务操作失败，请检查 systemd / Background service operation failed; inspect systemd")
        return result

    def ready(self):
        for path, content in self.templates().items():
            if path.is_symlink() or not path.is_file() or path.read_text() != content:
                return False
        return (self._run(["systemctl", "is-enabled", "--quiet", self.unit], False).returncode == 0
                and self._run(["systemctl", "is-active", "--quiet", self.unit], False).returncode == 0)

    def templates(self):
        root = str(self.root)
        if not re.fullmatch(r"/[a-zA-Z0-9/_.-]+", root):
            raise ValueError("服务安装路径包含不支持的字符 / Unsupported service installation path")
        library = root + "/port-manager-lib/current"
        unit = ("[Unit]\nDescription=v2ray-agent persistent port quota and rate policy\n"
                "After=local-fs.target network-online.target time-sync.target\n"
                "Wants=network-online.target time-sync.target\nBefore=xray.service sing-box.service\n"
                "AssertPathIsDirectory=" + library + "/port_manager\n\n"
                "[Service]\nType=exec\nEnvironment=PYTHONPATH=" + library + "\n"
                "Environment=PYTHONUNBUFFERED=1\n"
                "ExecStartPre=/usr/bin/python3 -m port_manager --root " + root + " --startup-reconcile\n"
                "ExecStart=/usr/bin/python3 -m port_manager --root " + root + " --daemon\n"
                "Restart=on-failure\nRestartSec=3\nTimeoutStartSec=120\nTimeoutStopSec=45\n"
                "UMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n"
                "ProtectSystem=strict\nReadWritePaths=" + root + "\n"
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\n"
                "[Install]\nWantedBy=multi-user.target\n")
        dropin = "[Unit]\nRequires=" + self.unit + "\nAfter=" + self.unit + "\n"
        return {self.unit_root / self.unit: unit,
                self.unit_root / "xray.service.d" / "50-v2ray-agent-port-manager.conf": dropin,
                self.unit_root / "sing-box.service.d" / "50-v2ray-agent-port-manager.conf": dropin}

    @contextmanager
    def _installation_lock(self):
        # Keep competing installers serialized while ExecStartPre/the daemon
        # acquire the separate common writer lock during start and stop.
        self.root.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self.root / ".port-policy-install.lock", flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("服务安装锁必须是普通文件 / Service installation lock must be a regular file")
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ValueError("后台服务正在安装，请稍后重试 / Background service installation is in progress; retry later")
                    time.sleep(0.1)
            yield
        finally:
            os.close(fd)

    def ensure(self, manager):
        with self._installation_lock():
            if self.ready():
                return {"status": "active"}
            if os.environ.get("PORT_MANAGER_LOCK_FD") is not None:
                raise ValueError("请释放调用者写锁后安装服务 / Release the caller's writer lock before installing the service")
            return self._install(manager)

    def _install(self, manager):
        module = self.root / "port-manager-lib" / "current" / "port_manager" / "__main__.py"
        if not module.is_file():
            raise ValueError("请先通过主脚本安装端口管理模块 / Install the port manager using the main installer first")
        templates = self.templates()
        created = []
        created_directories = []
        enable_attempted = False
        start_attempted = False
        was_active = False
        try:
            with shared_lock(self.root):
                manager.recover()
                existing = self._run(["systemctl", "show", "--property=FragmentPath", "--value", self.unit], False)
                fragment = existing.stdout.strip()
                if existing.returncode == 0 and fragment and fragment != str(self.unit_root / self.unit):
                    raise ValueError("已有同名服务来源未知 / Existing service with this name has unknown ownership")
                # Refuse to replace customized service definitions.
                for path, content in templates.items():
                    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != Path("/")):
                        raise ValueError("拒绝替换符号链接服务文件 / Refusing symlinked service files")
                    if path.exists() and (not path.is_file() or path.read_text() != content):
                        raise ValueError("已有后台服务配置需要人工核对 / Existing background service configuration needs review")
                enabled = self._run(["systemctl", "is-enabled", self.unit], False)
                if enabled.stdout.strip() in {"masked", "masked-runtime"}:
                    raise ValueError("后台服务已屏蔽，请先核对 systemd 设置 / Background service is masked; review systemd settings first")
                was_enabled = enabled.returncode == 0
                was_active = self._run(["systemctl", "is-active", "--quiet", self.unit], False).returncode == 0
                for path, content in templates.items():
                    if path.exists():
                        continue
                    if not path.parent.exists():
                        path.parent.mkdir(parents=True, exist_ok=True)
                        created_directories.append(path.parent)
                    fd, temporary = tempfile.mkstemp(prefix=".port-manager-", dir=path.parent)
                    try:
                        with os.fdopen(fd, "w") as handle:
                            handle.write(content)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.chmod(temporary, 0o644)
                        os.replace(temporary, path)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                    created.append(path)
                self._run(["systemctl", "daemon-reload"])
                if not was_enabled:
                    # enable can fail after adding some links, so compensate
                    # even when the command itself returns an error.
                    enable_attempted = True
                    self._run(["systemctl", "enable", self.unit])
            # ExecStartPre and daemon shutdown both take the common lock.
            start_attempted = True
            self._run(["systemctl", "start", self.unit])
            if not self.ready():
                raise ValueError("后台服务未就绪；策略未提交 / Background service is not ready; policies were not submitted")
        except BaseException as original:
            cleanup_errors = []

            def cleanup_command(argv):
                try:
                    if self._run(argv, False).returncode:
                        cleanup_errors.append(" ".join(argv))
                except Exception:
                    cleanup_errors.append(" ".join(argv))

            if start_attempted and not was_active:
                # Cancel this unit's automatic restart without propagating a
                # stop through newly installed or preexisting Requires edges.
                cleanup_command(["systemctl", "stop", "--job-mode=ignore-dependencies", self.unit])
            if created or created_directories or enable_attempted:
                try:
                    with shared_lock(self.root):
                        if enable_attempted:
                            cleanup_command(["systemctl", "disable", self.unit])
                        for path in reversed(created):
                            try:
                                if (path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != Path("/"))
                                        or path.exists() and (not path.is_file() or path.read_text() != templates[path])):
                                    cleanup_errors.append(str(path))
                                elif path.exists():
                                    path.unlink()
                            except OSError:
                                cleanup_errors.append(str(path))
                        for directory in reversed(created_directories):
                            try:
                                directory.rmdir()
                            except OSError:
                                # Other operator-owned files may now be present.
                                pass
                        cleanup_command(["systemctl", "daemon-reload"])
                except Exception:
                    cleanup_errors.append("writer lock")
            if cleanup_errors:
                raise ValueError("服务安装失败且补偿未完成，请核对 / Service installation failed and rollback is incomplete; inspect: " + ", ".join(cleanup_errors)) from original
            raise
        return {"status": "active"}


class Application:
    def __init__(self, manager, policies=None, rates=None, input_fn=None, output=None, language="zh", timezone="Asia/Shanghai", services=None):
        self.manager = manager
        self.root = Path(manager.root)
        self.policies = policies
        self.rates = rates
        self.input = input_fn or input
        self.output = output or sys.stdout
        self.language = language
        self.timezone = timezone
        self.services = services

    def tr(self, zh, en):
        return zh if self.language == "zh" else en

    def say(self, value=""):
        print(value, file=self.output)

    def prompt(self, zh, en):
        return self.input(self.tr(zh, en)).strip()

    def emit(self, value, as_json=False):
        if as_json:
            self.say(json.dumps(value, ensure_ascii=False, sort_keys=True))
        elif isinstance(value, list):
            for row in value:
                self.say(_display(row))
            if not value:
                self.say(self.tr("暂无记录。", "No records."))
        else:
            self.say(_display(value))

    def policy_rows(self, entries):
        return self.policies.status(entries) if self.policies else []

    def inventory(self, as_json=False):
        entries = self.manager.list()
        rows = {row["port_id"]: row for row in self.policy_rows(entries)}
        result = []
        for index, entry in enumerate(entries, 1):
            row = public_entry(entry)
            row["row"] = index
            row["policy"] = rows.get(entry["port_id"], {})
            row["rate"] = self.rates.status(entry) if self.rates else {"status": "unconfigured"}
            row["runtime_listener"] = self.manager.listener_status(entry) if hasattr(self.manager, "listener_status") else {"status": "unverified"}
            row["local_rules"] = {"policy_effective": row["policy"].get("effective", False), "rate_applied": row["rate"].get("applied", False), "firewall": "unverified"}
            row["public_verification"] = "unverified"
            result.append(row)
        if as_json:
            self.emit(result, True)
        else:
            self.say(self.tr("编号 | 入口标识 | 核心/用途 | 配置端口 | 协议 | 监听地址 | 可修改", "Row | Entry ID | Core/type | Config port | Protocols | Listen | Editable"))
            for row in result:
                self.say(" | ".join(_display(value) for value in ("#" + str(row["row"]), row.get("port_id"), str(row.get("core")) + "/" + str(row.get("kind")), row.get("port"), "/".join(row.get("protocols", [])), row.get("listen"), row.get("supported", False))))
                if row.get("reason"):
                    self.say("  " + _display(row["reason"]))
                self.say(self.tr("  策略: ", "  Policy: ") + _display(row["policy"]))
                self.say(self.tr("  限速: ", "  Rates: ") + _display(row["rate"]))
                self.say(self.tr("  实际监听：", "  Runtime listener: ") + _display(row["runtime_listener"]))
                self.say(self.tr("  本机规则：", "  Local rules: ") + _display(row["local_rules"]) + self.tr("；公网：未验证", "; public access: unverified"))
            if not result:
                self.say(self.tr("未发现入口。", "No entries found."))
        return entries

    def select(self, entries, single=False):
        value = self.prompt("选择 #编号、port_id 或 port:端口（列表用逗号，范围如 port:10001-10003）：", "Select #row, port_id, or port:number (commas/ranges allowed): ")
        return select_entries(value, entries, single)

    def confirm(self, yes=False):
        if yes:
            return True
        accepted = self.prompt("输入 YES 确认，其他输入取消：", "Type YES to confirm; anything else cancels: ").lower() == "yes"
        if not accepted:
            self.say(self.tr("已取消，未提交修改。", "Cancelled; no changes submitted."))
        return accepted

    def _fingerprint(self, entries):
        return json.dumps([public_entry(entry) for entry in entries], sort_keys=True)

    def write(self, entries, action):
        expected = self._fingerprint(entries)
        with shared_lock(self.root):
            _require_recovered(self.manager.recover())
            current = self.manager.list()
            selected = []
            for entry in entries:
                matches = [row for row in current if row["port_id"] == entry["port_id"]]
                if len(matches) != 1:
                    raise ValueError(self.tr("入口已变化，请重新预览。", "Entry changed; preview again."))
                selected.extend(matches)
            if self._fingerprint(selected) != expected:
                raise ValueError(self.tr("配置已变化，请重新预览。", "Configuration changed; preview again."))
            return action(selected)

    def change(self, entry, port, yes=False):
        port = parse_port(port)
        if port == entry["port"]:
            self.say(self.tr("无需变更。", "No change needed."))
            return {"status": "unchanged"}
        if not entry.get("supported", False):
            raise ValueError(_display(entry.get("reason") or "Unsupported entry"))
        related = [public_entry(row) for row in self.manager.list() if row.get("core") == entry.get("core")]
        self.say(self.tr("变更预览：", "Change preview:"))
        self.emit({"entry": public_entry(entry), "old_port": entry["port"], "new_port": port, "affected_core_entries": related})
        self.say(self.tr("仅重启目标核心，期间同核心连接会短暂中断。按实际协议检查并调整本机放行、计量和限速规则；更新全部适用的已初始化订阅，下载地址不变。请核对云安全组和外部端口映射；公网状态未验证。", "The target core restarts briefly, interrupting its connections. Local firewall, metering, and rate rules are checked for the required protocols; all applicable initialized subscriptions are updated with stable download URLs. Check cloud security groups and external port mappings; public access is unverified."))
        if not self.confirm(yes):
            return None
        result = self.write([entry], lambda rows: self.manager.change(rows[0]["port_id"], port))
        if result.get("status") in {"completed", "committed", "success", "changed"}:
            self.say(self.tr("节点端口已修改；目标服务监听检查通过；服务端订阅已更新，请在客户端重新拉取。公网：未验证。", "Port changed; target listener verified; server subscriptions updated. Refresh your clients. Public access: unverified."))
        self.emit(result)
        return result

    def rollback(self, yes=False):
        records = self.manager.history()
        self.emit(records)
        self.say(self.tr("预览：基于当前账户和配置反向修改最近一次端口变更；不恢复旧用量。目标核心会短暂重启，订阅将更新。", "Preview: reverse the latest port change using current accounts and configuration; usage is preserved. The target core briefly restarts and subscriptions are updated."))
        if self.confirm(yes):
            expected = json.dumps(records, sort_keys=True)
            def apply(_):
                if json.dumps(self.manager.history(), sort_keys=True) != expected:
                    raise ValueError(self.tr("变更记录已更新，请重新预览。", "History changed; preview again."))
                return self.manager.rollback()
            self.emit(self.write([], apply))

    def policy_changes(self, quota=None, expiry=None):
        changes = {}
        if quota is not None:
            parsed = parse_quota(quota)
            if parsed is not KEEP:
                changes["quota_bytes"] = parsed
        if expiry is not None:
            parsed = parse_expiry(expiry, self.timezone)
            if parsed is not KEEP:
                changes["expires_at"] = parsed
        if changes:
            changes["timezone"] = self.timezone
        return changes

    def ask_policy(self):
        self.say(self.tr("空白保留原值；GB = 10⁹ 字节；日期表示当天有效，次日 00:00 到期。", "Blank keeps the current value; GB = 10⁹ bytes; a date expires at 00:00 the next day."))
        quota = self.prompt("月额度（GB，或显式 GiB；unlimited 无限额；0 立即限制）：", "Monthly quota (GB, explicit GiB, unlimited; 0 blocks): ")
        expiry = self.prompt("到期日或 ISO 时间（never 永不到期）：", "Expiry date or ISO timestamp (never removes expiry): ")
        return self.policy_changes(quota, expiry)

    def set_policy(self, entries, changes, yes=False):
        if not self.policies:
            raise ValueError(self.tr("额度执行模块不可用。", "Policy backend unavailable."))
        if not changes or all(not row for row in changes.values() if isinstance(row, dict)) and all(isinstance(row, dict) for row in changes.values()):
            self.say(self.tr("无需变更。", "No change needed."))
            return None
        self.say(self.tr("策略预览；管理时区：", "Policy preview; management timezone: ") + self.timezone)
        preview = self.policies.preview(entries, changes)
        self.emit(preview)
        self.say(self.tr("保留当月已用量；人工暂停、超额和到期分别判断，取消某项限制不会绕过其他限制。", "Current-month usage is preserved. Pause, quota, and expiry remain independent restrictions."))
        self.service_preview()
        before_versions = self._policy_versions(entries)
        if not self.confirm(yes):
            return None
        if self.services:
            self.services.ensure(self.manager)
        def apply(rows):
            if self._policy_versions(rows) != before_versions:
                raise ValueError(self.tr("策略已变化，请重新预览。", "Policies changed; preview again."))
            return self.policies.batch_update(rows, changes)
        result = self.write(entries, apply)
        self.emit(result)
        return result

    def _policy_versions(self, entries):
        return {row["port_id"]: (row.get("version"), row.get("policy_version"), row.get("quota_bytes"), row.get("expires_at"), row.get("paused")) for row in self.policy_rows(entries)}

    def service_preview(self):
        if self.services and not self.services.ready():
            self.say(self.tr("此操作将安装并启用本项目的 systemd 后台服务及核心启动依赖，确保退出菜单和重启后继续执行策略。", "This operation installs and enables the project's systemd background service and core startup dependencies so policies continue after menu exit and reboot."))

    def set_rate(self, entry, upload, download, yes=False):
        if not self.rates:
            raise ValueError(self.tr("限速执行模块不可用。", "Rate backend unavailable."))
        from .rate_limits import KEEP as RATE_KEEP, parse_rate
        upload_bps, download_bps = parse_rate(upload), parse_rate(download)
        if upload_bps is RATE_KEEP and download_bps is RATE_KEEP:
            self.say(self.tr("无需变更。", "No change needed."))
            return None
        current = self.rates.status(entry)
        if not current.get("supported", False):
            raise ValueError(_display(current.get("reason") or "Rate shaping unsupported"))
        self.say(self.tr("单入口限速预览（Mbps = 每秒百万比特；所有用户和连接合计）：", "Single-entry rate preview (Mbps = million bits per second, shared by all users and connections):"))
        self.say(self.tr("限速为实验功能，尚未完成真实流量验收；非首个 IP 分片可能绕过端口分类。执行成功仅表示 tc 对象已安装核对，不代表已验证所有流量均受限。", "Rate limiting is experimental and has not passed live-traffic acceptance. Noninitial IP fragments may bypass port classification. Success verifies installed tc objects, not a proven cap for all traffic."))
        self.emit({"entry": public_entry(entry), "current": current, "upload_bps": current.get("upload_bps") if upload_bps is RATE_KEEP else upload_bps, "download_bps": current.get("download_bps") if download_bps is RATE_KEEP else download_bps})
        self.say(self.tr("常规限速调整不重启核心；不改变额度、已用量、到期日或暂停状态。", "Routine rate changes do not restart the core or alter quota, usage, expiry, or pause state."))
        self.service_preview()
        if not self.confirm(yes):
            return None
        if self.services:
            self.services.ensure(self.manager)
        expected = (current.get("upload_bps"), current.get("download_bps"), current.get("version"))
        def apply(rows):
            latest = self.rates.status(rows[0])
            if (latest.get("upload_bps"), latest.get("download_bps"), latest.get("version")) != expected:
                raise ValueError(self.tr("限速策略已变化，请重新预览。", "Rate policy changed; preview again."))
            return self.rates.set(rows[0], upload_bps=upload_bps, download_bps=download_bps)
        result = self.write([entry], apply)
        self.emit(result)
        return result

    def additional_menu(self):
        entries = self.manager.additional_list()
        self.emit([public_entry(row) for row in entries])
        action = self.prompt("附加端口：1 添加，2 删除，0 返回：", "Additional ports: 1 add, 2 delete, 0 return: ")
        if action == "1":
            selected = self.select(self.inventory(), True)[0]
            port = parse_port(self.prompt("新附加端口：", "New additional port: "))
            self.say(self.tr("预览：添加归属明确的 Xray 转发入口；校验、短暂重启目标核心并更新适用订阅。", "Preview: add an identified Xray forwarding entry, validate, briefly restart the target core, and update applicable subscriptions."))
            self.emit({"target": public_entry(selected), "additional_port": port})
            if self.confirm():
                self.emit(self.write([selected], lambda rows: self.manager.additional_add(rows[0]["port_id"], port)))
        elif action == "2":
            selected = self.select(entries, True)[0]
            self.say(self.tr("预览：删除以下已识别的附加入口，保留目标节点账户。", "Preview: delete this identified additional entry, preserving target accounts."))
            self.emit(public_entry(selected))
            if self.confirm():
                self.emit(self.write([selected], lambda rows: self.manager.additional_delete(rows[0]["port_id"])))
        elif action != "0":
            raise ValueError(self.tr("菜单选项无效。", "Invalid menu option."))

    def usage(self, entries, as_json=False):
        rows = self.policy_rows(entries)
        history = self.policies.history() if self.policies else []
        if as_json:
            self.emit({"entries": rows, "history": history}, True)
        else:
            self.say(self.tr("当前周期：", "Current periods:"))
            self.emit(rows)
            self.say(self.tr("历史周期：", "Period history:"))
            self.emit(history)

    def menu(self):
        while True:
            self.say(self.tr("\n端口管理\n1. 查看端口\n2. 修改节点端口\n3. 检查端口占用\n4. 变更记录与回退\n5. 附加端口管理\n6. 批量设置额度与到期日\n7. 查看用量与周期\n8. 批量续期与状态管理\n9. 设置单端口限速\n0. 返回", "\nPort management\n1. List ports\n2. Change node port\n3. Check port conflicts\n4. History and reverse rollback\n5. Additional ports\n6. Batch quota and expiry\n7. Usage and billing periods\n8. Batch renewal and status\n9. Set one port's rate limits\n0. Return"))
            try:
                choice = self.prompt("请选择：", "Select: ")
                if choice == "0":
                    return 0
                if choice == "1":
                    self.inventory()
                elif choice == "2":
                    entry = self.select(self.inventory(), True)[0]
                    self.change(entry, self.prompt("新端口：", "New port: "))
                elif choice == "3":
                    port = parse_port(self.prompt("检查端口：", "Port to check: "))
                    self.emit(self.manager.check_port(port))
                    self.say(self.tr("本机绑定检查不代表公网可达。", "Local binding checks do not verify public reachability."))
                elif choice == "4":
                    self.emit(self.manager.history())
                    if self.prompt("输入 1 预览最近变更回退，其他输入返回：", "Enter 1 to preview the latest reverse rollback; otherwise return: ") == "1":
                        self.rollback()
                elif choice == "5":
                    self.additional_menu()
                elif choice == "6":
                    entries = self.select(self.inventory())
                    mode = self.prompt("1 统一设置，2 逐项填写：", "1 Same values, 2 Per-entry values: ")
                    if mode == "1":
                        changes = self.ask_policy()
                    elif mode == "2":
                        changes = {}
                        for entry in entries:
                            self.emit(public_entry(entry))
                            changes[entry["port_id"]] = self.ask_policy()
                    else:
                        raise ValueError(self.tr("菜单选项无效。", "Invalid menu option."))
                    self.set_policy(entries, changes)
                elif choice == "7":
                    self.usage(self.manager.list())
                elif choice == "8":
                    entries = self.select(self.inventory())
                    action = self.prompt("1 续期/额度，2 人工暂停，3 取消人工暂停：", "1 Renew/quota, 2 Pause, 3 Resume: ")
                    if action == "1":
                        changes = self.ask_policy()
                    elif action in {"2", "3"}:
                        changes = {"paused": action == "2", "timezone": self.timezone}
                    else:
                        raise ValueError(self.tr("菜单选项无效。", "Invalid menu option."))
                    self.set_policy(entries, changes)
                elif choice == "9":
                    entry = self.select(self.inventory(), True)[0]
                    upload = self.prompt("上传 Mbps（空白保留，unlimited 解除，拒绝 0）：", "Upload Mbps (blank keeps, unlimited removes, 0 rejected): ")
                    download = self.prompt("下载 Mbps（空白保留，unlimited 解除，拒绝 0）：", "Download Mbps (blank keeps, unlimited removes, 0 rejected): ")
                    self.set_rate(entry, upload, download)
                else:
                    self.say(self.tr("菜单选项无效。", "Invalid menu option."))
            except (ValueError, RuntimeError, OSError) as exc:
                self.say(self.tr("操作未完成：", "Operation incomplete: ") + _display(str(exc)))
            except (EOFError, KeyboardInterrupt):
                self.say(self.tr("\n已退出。", "\nExited."))
                return 0
            except Exception:
                self.say(self.tr("操作未完成：内部状态或数据格式异常，请核对记录后重试。", "Operation incomplete: unexpected state or data format; review the records before retrying."))


def build_parser():
    parser = argparse.ArgumentParser(description="v2ray-agent port management / 端口管理")
    parser.add_argument("--root", default="/etc/v2ray-agent")
    parser.add_argument("--language", choices=("zh", "en"), default="zh")
    parser.add_argument("--timezone", default="Asia/Shanghai")
    parser.add_argument("--json", action="store_true", help="JSON output for read-only commands")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--daemon", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    mode.add_argument("--startup-reconcile", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--interval", type=int, default=10)
    commands = parser.add_subparsers(dest="command")
    for name in ("list", "history", "usage"):
        commands.add_parser(name)
    service = commands.add_parser("install-service")
    service.add_argument("--yes", action="store_true")
    check = commands.add_parser("check")
    check.add_argument("port", type=parse_port)
    check.add_argument("--protocol", choices=("tcp", "udp"), action="append")
    check.add_argument("--listen", default="::")
    change = commands.add_parser("change")
    change.add_argument("selection")
    change.add_argument("port", type=parse_port)
    change.add_argument("--yes", action="store_true")
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--yes", action="store_true")
    for name in ("set-policy", "pause", "resume"):
        command = commands.add_parser(name)
        command.add_argument("selection")
        command.add_argument("--yes", action="store_true")
        if name == "set-policy":
            command.add_argument("--quota", default="")
            command.add_argument("--expiry", default="")
    rate = commands.add_parser("rate")
    rate.add_argument("selection")
    rate.add_argument("--upload", default="")
    rate.add_argument("--download", default="")
    rate.add_argument("--yes", action="store_true")
    return parser


def reconcile_once(app, startup=False, _retried=False):
    with shared_lock(app.root):
        recovery = app.manager.recover(start_services=False) if startup else app.manager.recover()
        if startup or not _awaiting_start(recovery):
            entries = app.manager.list()
            # Startup cores are stopped. Reconstruct their queues before policy
            # reconciliation verifies/drains queues for blocked entrances.
            if startup:
                rates = app.rates.reconcile(entries) if app.rates else None
                policies = app.policies.reconcile(entries) if app.policies else None
            else:
                policies = app.policies.reconcile(entries, defer_queue_drain=True) if app.policies else None
                rates = app.rates.reconcile(entries) if app.rates else None
            faults = [row for row in rates or [] if row.get("state") == "fault"]
            if faults:
                by_id = {entry["port_id"]: entry for entry in entries}
                for fault in faults:
                    if app.policies and hasattr(app.policies, "block_runtime") and fault.get("port_id") in by_id:
                        app.policies.block_runtime(by_id[fault["port_id"]], "rate_enforcement_fault")
                raise ValueError("限速执行核对失败；受控入口需要恢复 / Rate enforcement failed verification; recovery is required")
            if not startup and app.policies:
                policies = app.policies.reconcile(entries)
            return {"recovery": recovery, "policies": policies, "rates": rates}
    if _retried:
        _require_recovered(recovery)
    # The service's startup reconciliation requires this lock, so release it
    # before start; its daemon or this retry then finishes runtime recovery.
    _start_recovery_service(app)
    return reconcile_once(app, _retried=True)


def run_daemon(app, interval=10):
    import threading
    stopped = threading.Event()
    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, lambda *_: stopped.set())
    try:
        while not stopped.is_set():
            try:
                reconcile_once(app)
            except Exception as exc:
                # This is a service fault, never claim that database policy
                # existence proves kernel enforcement. systemd can restart us.
                app.say(app.tr("后台核对失败：", "Reconciliation failed: ") + _display(str(exc)))
                return 1
            stopped.wait(interval)
        with shared_lock(app.root):
            if app.policies:
                app.policies.prepare_shutdown()
        return 0
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv=None, manager_factory=None, input_fn=None, output=None, policies_factory=None, rates_factory=None, services_factory=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.daemon or args.reconcile or args.startup_reconcile or args.recover) and args.command:
        parser.error("Background and recovery modes cannot be combined with a command")
    if args.json and args.command not in {"list", "check", "history", "usage"}:
        parser.error("--json requires a read-only command: list, check, history, usage")
    if not 1 <= args.interval <= 60:
        parser.error("--interval must be 1–60 seconds")
    try:
        ZoneInfo(args.timezone)
    except ZoneInfoNotFoundError:
        parser.error("Unknown management timezone")
    if manager_factory is None:
        from .core import Manager
        manager_factory = Manager
    if policies_factory is None:
        from .policies import PolicyManager
        policies_factory = PolicyManager
    if rates_factory is None:
        from .rate_limits import RateLimiter
        rates_factory = RateLimiter
    try:
        manager = manager_factory(args.root)
        services = (services_factory or Services)(args.root)
        app = Application(manager, policies_factory(args.root), rates_factory(args.root), input_fn, output, args.language, args.timezone, services)
        if args.daemon:
            return run_daemon(app, args.interval)
        if args.reconcile or args.startup_reconcile:
            app.emit(reconcile_once(app, startup=args.startup_reconcile))
            return 0
        if args.recover:
            app.emit(recover_once(app))
            return 0
        if args.command == "list":
            app.inventory(args.json)
        elif args.command == "check":
            app.emit(manager.check_port(args.port, args.protocol, args.listen), args.json)
        elif args.command == "history":
            app.emit(manager.history(), args.json)
        elif args.command == "usage":
            app.usage(manager.list(), args.json)
        elif args.command == "change":
            app.change(select_entries(args.selection, manager.list(), True)[0], args.port, args.yes)
        elif args.command == "rollback":
            app.rollback(args.yes)
        elif args.command in {"set-policy", "pause", "resume"}:
            entries = select_entries(args.selection, manager.list())
            changes = app.policy_changes(args.quota, args.expiry) if args.command == "set-policy" else {"paused": args.command == "pause", "timezone": args.timezone}
            app.set_policy(entries, changes, args.yes)
        elif args.command == "rate":
            app.set_rate(select_entries(args.selection, manager.list(), True)[0], args.upload, args.download, args.yes)
        elif args.command == "install-service":
            app.say(app.tr("预览：安装并启用后台策略服务及 Xray/sing-box 启动依赖；先恢复未完成操作。", "Preview: install and enable the background policy service and Xray/sing-box startup dependencies; recover pending operations first."))
            if app.confirm(args.yes):
                app.emit(services.ensure(manager))
        else:
            # Interrupted operations are recovered before opening the menu.
            # The lock is released before waiting for any user input.
            recovered = recover_once(app)
            if recovered:
                app.emit(recovered)
            return app.menu()
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print("操作未完成 / Operation incomplete: " + _display(str(exc)), file=output or sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        return 130
    except Exception:
        print("操作未完成：内部状态或数据格式异常 / Operation incomplete: unexpected state or data format", file=output or sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
