"""Owned Linux tc shaping for one independent proxy entrance at a time.

No shell evaluation, core restarts, firewall changes or quota-ledger writes occur
here. All network mutation is behind an injectable command runner. The initial
template requires an empty/noqueue root: an arbitrary existing QoS tree is never
replaced. IPv4/IPv6 and TCP/UDP selectors feed one HTB class per direction.

This implementation requires real-host acceptance testing before production
use; status verifies objects, not measured throughput or kernel compatibility.
"""

from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


KEEP = object()
ROOT = "7a00:"
MAX_RATE = 1_000_000_000_000
QUEUE_PACKETS = 128
VOLATILE = {"stats", "stats2", "xstats", "refcnt", "bindcnt", "used",
            "lastuse", "installed", "expires", "in_hw_count", "hw_stats",
            "bytes", "packets", "drops", "overlimits", "requeues", "backlog",
            "qlen", "last_action", "used_hw_stats", "not_in_hw", "in_hw",
            "direct_packets_stat", "ref", "bind"}
LIMITATIONS = ["实验性限速：尚未通过真实 TCP/UDP、双栈及重启流量验收",
               "非首片 IP 分片缺少端口字段，可能绕过 flower 端口匹配；不能保证任意分片流量的严格合计上限",
               "首次接入仅接受空/noqueue 队列；mq、fq、fq_codel 及其他既有 QoS 不自动替换"]


class RateLimitError(RuntimeError):
    pass


def parse_rate(text):
    """User-facing decimal Mbps; blank retains, unlimited explicitly removes."""
    text = str(text).strip()
    if not text:
        return KEEP
    if text.lower() in {"不限速", "unlimited", "none", "off"}:
        return None
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,6})?", text):
        raise RateLimitError("速度必须是正数 Mbps，空白保留，输入 不限速 解除")
    try:
        value = int(Decimal(text) * 1_000_000)
    except (InvalidOperation, ValueError, OverflowError):
        raise RateLimitError("无效速度")
    _validate_rate(value)
    return value


def _validate_rate(value):
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                              or not 8 <= value <= MAX_RATE):
        raise RateLimitError("速度必须为 8 至 1000000000000 bps；0 不能表示不限速")


def _canonical(value):
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def _object_id(obj):
    return "|".join(str(obj.get(k, "")) for k in
                    ("type", "dev", "parent", "handle", "pref", "protocol"))


class RateLimiter:
    def __init__(self, root="/etc/v2ray-agent", runner=None):
        self.directory = Path(root) / "port-manager"
        self.path = self.directory / "rates.json"
        self.runner = runner

    def _run(self, argv):
        try:
            if self.runner is None:
                result = subprocess.run(argv, text=True, capture_output=True,
                                        timeout=20, check=False)
            elif hasattr(self.runner, "run"):
                result = self.runner.run(argv)
            else:
                result = self.runner(argv)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RateLimitError("无法执行 {}: {}".format(argv[0], exc)) from exc
        if isinstance(result, str):
            return result
        if getattr(result, "returncode", 0):
            raise RateLimitError("{} 失败: {}".format(" ".join(argv),
                str(getattr(result, "stderr", ""))[-1000:]))
        return getattr(result, "stdout", "") or ""

    def _json(self, argv):
        try:
            value = json.loads(self._run(argv))
        except (ValueError, TypeError) as exc:
            raise RateLimitError("{} 不支持预期的 JSON 输出".format(argv[0])) from exc
        if not isinstance(value, list):
            raise RateLimitError("命令输出格式异常")
        return value

    def _load(self):
        self._safe_paths()
        if not self.path.exists():
            return {"version": 1, "entries": {}, "shared": [], "fault": None}
        try:
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise RateLimitError("限速状态不是普通文件")
                state = json.load(source)
            if state.get("version") != 1 or not isinstance(state["entries"], dict):
                raise ValueError("state version")
            return state
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RateLimitError("限速状态文件不可读；停止更改以保护已有规则") from exc

    def _safe_paths(self):
        for path in [self.directory] + list(self.directory.parents):
            if path.is_symlink():
                raise RateLimitError("限速状态目录不能经过符号链接: " + str(path))
        for path in (self.path, self.directory / "rates.lock"):
            if path.is_symlink():
                raise RateLimitError("限速状态/锁文件不能是符号链接")
            if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
                raise RateLimitError("限速状态/锁文件必须是无硬链接的普通文件")

    def _save(self, state):
        self._safe_paths()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".rates-", dir=str(self.directory))
        try:
            with os.fdopen(fd, "w") as output:
                json.dump(state, output, ensure_ascii=False, sort_keys=True, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.chmod(name, 0o600)
            os.replace(name, self.path)
            directory_fd = os.open(str(self.directory), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @contextmanager
    def _lock(self, readonly=False):
        self._safe_paths()
        if readonly:
            lock_path = self.directory / "rates.lock"
            if not lock_path.exists():
                yield
                return
            fd = os.open(str(lock_path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r") as lock:
                fcntl.flock(lock, fcntl.LOCK_SH)
                yield
            return
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(self.directory / "rates.lock"), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _entry(self, entry):
        if not isinstance(entry, dict) or not entry.get("port_id"):
            raise RateLimitError("缺少稳定 port_id")
        if not entry.get("supported", False):
            raise RateLimitError(entry.get("reason") or "入口不支持独立管理")
        protocols = sorted(set(entry.get("protocols", [])))
        if not protocols or any(p not in {"tcp", "udp"} for p in protocols):
            raise RateLimitError("仅支持可独立识别的 TCP/UDP 入口")
        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise RateLimitError("无效监听端口")
        clean = {k: entry.get(k) for k in ("port_id", "core", "file", "index", "tag",
                 "port", "listen", "kind")}
        clean.update(protocols=protocols, supported=True)
        return clean

    def _network(self, entry):
        links = self._json(["ip", "-j", "-d", "address", "show"])
        candidates = []
        for link in links:
            if link.get("ifname") == "lo" or "UP" not in link.get("flags", []):
                continue
            kind = link.get("linkinfo", {}).get("info_kind", "")
            if kind == "ifb":
                continue
            if any(a.get("scope") == "global" for a in link.get("addr_info", [])):
                candidates.append(link)
        if len(candidates) != 1:
            raise RateLimitError("限速首版要求唯一外部接口；检测到 {} 个".format(len(candidates)))
        link = candidates[0]
        dev = link["ifname"]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", dev):
            raise RateLimitError("接口名称不受支持")
        kind = link.get("linkinfo", {}).get("info_kind", "")
        if kind not in {"", "veth", "virtio_net"} or link.get("master"):
            raise RateLimitError("暂不支持桥接、隧道、VLAN、聚合或从属接口")
        addresses = sorted({a["local"] for a in link.get("addr_info", [])
                            if a.get("scope") == "global"
                            and a.get("family") in {"inet", "inet6"}})
        try:
            listen = ipaddress.ip_address(str(entry.get("listen") or "::").strip("[]"))
        except ValueError as exc:
            raise RateLimitError("监听地址不是明确的 IP 地址") from exc
        if listen.is_loopback or listen.is_multicast or listen.is_link_local:
            raise RateLimitError("回环、组播或链路本地入口不支持公网限速")
        if listen.is_unspecified:
            addresses = [a for a in addresses if listen.version == 6
                         or ipaddress.ip_address(a).version == 4]
        else:
            addresses = [str(listen)] if str(listen) in addresses else []
        if not addresses or len(addresses) * len(entry["protocols"]) > 32:
            raise RateLimitError("监听地址未绑定唯一外部接口，或地址数量超过首版支持范围")
        for family in sorted({ipaddress.ip_address(a).version for a in addresses}):
            rules = self._json(["ip", "-j", "-" + str(family), "rule", "show"])
            expected = {(0, "local"), (32766, "main"), (32767, "default")}
            if any((r.get("priority"), str(r.get("table"))) not in expected
                   or r.get("src", "all") != "all" or r.get("dst", "all") != "all"
                   or any(k in r for k in ("fwmark", "iif", "oif", "uidrange"))
                   for r in rules):
                raise RateLimitError("存在策略路由，无法证明单一限速路径")
            routes = self._json(["ip", "-j", "-" + str(family), "route", "show", "table", "all"])
            defaults = [r for r in routes if r.get("dst") == "default"]
            if not defaults or any(r.get("dev") != dev or r.get("nexthops")
                                   for r in defaults):
                raise RateLimitError("IPv{} 默认路由不是唯一外部接口".format(family))
            if any(r.get("dev") not in {None, "lo", dev} for r in routes):
                raise RateLimitError("存在第二条接口路由，无法保证端口合计上限")
        return dev, addresses

    def _listing(self, obj):
        if obj["type"] == "link":
            return self._json(["ip", "-j", "-d", "link", "show"])
        argv = ["tc", "-j", obj["type"], "show", "dev", obj["dev"]]
        if obj["type"] == "filter":
            argv += ["parent", obj["parent"]]
        return self._json(argv)

    def _get(self, obj):
        if obj["type"] != "link" and not any(l.get("ifname") == obj["dev"] for l in
                self._json(["ip", "-j", "-d", "link", "show"])):
            return None
        matches = []
        for live in self._listing(obj):
            if obj["type"] == "link":
                match = live.get("ifname") == obj["dev"]
            elif obj["type"] == "filter":
                match = (str(live.get("pref")) == str(obj["pref"])
                         and live.get("protocol") == obj["protocol"]
                         and str(live.get("options", {}).get("handle", live.get("handle", "")))
                         in {str(obj["handle"]), hex(int(obj["handle"], 0))})
            else:
                match = live.get("handle") == obj["handle"]
            if match:
                matches.append(live)
        if len(matches) > 1:
            raise RateLimitError("执行对象引用不唯一: " + _object_id(obj))
        return matches[0] if matches else None

    def _fingerprint(self, obj, live):
        if obj["type"] == "link":
            return {"ifname": live.get("ifname"), "ifalias": live.get("ifalias"),
                    "kind": live.get("linkinfo", {}).get("info_kind")}
        result = _canonical(live)
        if obj["type"] == "class":
            # Attaching/removing our separately verified leaf changes this
            # pointer; it is not a change to the HTB class rate parameters.
            result.pop("leaf", None)
        return result

    def _verify_spec(self, obj, live):
        if not live:
            raise RateLimitError("限速执行对象缺失: " + _object_id(obj))
        if obj["type"] == "link":
            okay = (live.get("ifalias") == obj["alias"]
                    and live.get("linkinfo", {}).get("info_kind") == "ifb"
                    and "UP" in live.get("flags", []))
        else:
            okay = live.get("kind", live.get("class")) == obj["kind"]
            # iproute2 emits class parameters at top level, whereas qdiscs and
            # filters nest parameters in options (tc_class.c / tc_qdisc.c).
            options = live.get("options", live if obj["type"] == "class" else {})
            if obj["type"] == "class":
                okay = okay and int(options.get("rate", -1)) == obj["bps"] // 8
                okay = okay and int(options.get("ceil", -1)) == obj["bps"] // 8
            elif obj["type"] == "filter":
                keys = options.get("keys", {})
                okay = okay and all(str(keys.get(k)) == str(v) for k, v in obj["keys"].items())
                if obj.get("classid"):
                    okay = okay and options.get("classid") == obj["classid"]
                else:
                    actions = options.get("actions", [])
                    okay = okay and len(actions) == 1 and actions[0].get("kind") == "mirred"
                    okay = okay and actions[0].get("to_dev") == obj["ifb"]
                    okay = okay and actions[0].get("mirred_action") == "redirect"
                    okay = okay and actions[0].get("direction") == "egress"
            elif obj["kind"] == "pfifo":
                okay = okay and options.get("limit") == QUEUE_PACKETS
            elif obj["kind"] == "htb":
                default = options.get("default", "")
                expected_default = obj.get("default", 0)
                okay = okay and str(default) in {str(expected_default), hex(expected_default)}
        if not okay:
            raise RateLimitError("限速对象参数核验失败: " + _object_id(obj))

    def _verify_owned(self, obj, allow_missing=False):
        live = self._get(obj)
        if live is None and allow_missing:
            return None
        if live is None or obj.get("fingerprint") != self._fingerprint(obj, live):
            raise RateLimitError("对象缺失或被外部更改，拒绝覆盖: " + _object_id(obj))
        self._verify_spec(obj, live)
        return live

    def _qdisc(self, dev, kind, handle, parent=None):
        attach = ["root"] if parent is None else ["parent", parent]
        tail = ["default", "0"] if kind == "htb" else (["limit", str(QUEUE_PACKETS)] if kind == "pfifo" else [])
        return {"type": "qdisc", "dev": dev, "kind": kind, "handle": handle,
                "parent": parent or "root",
                "create": ["tc", "qdisc", "add", "dev", dev] + attach + ["handle", handle, kind] + tail,
                "delete": ["tc", "qdisc", "del", "dev", dev] + attach + ["handle", handle]}

    def _class(self, dev, classid, bps):
        burst = max(16384, (bps + 799) // 800)
        args = ["tc", "class", "add", "dev", dev, "parent", ROOT, "classid", classid,
                "htb", "rate", str(bps) + "bit", "ceil", str(bps) + "bit",
                "burst", str(burst), "cburst", str(burst)]
        return {"type": "class", "dev": dev, "parent": ROOT, "handle": classid,
                "kind": "htb", "bps": bps, "burst_bytes": burst,
                "create": args, "delete": ["tc", "class", "del", "dev", dev, "classid", classid]}

    def _filter(self, dev, parent, pref, handle, address, protocol, port, classid=None, ifb=None):
        family = ipaddress.ip_address(address).version
        wire = "ip" if family == 4 else "ipv6"
        side = "src" if classid else "dst"
        keys = {"eth_type": "ipv4" if family == 4 else "ipv6", "ip_proto": protocol,
                side + "_ip": address, side + "_port": port}
        start = ["tc", "filter", "add", "dev", dev, "parent", parent, "protocol", wire,
                 "pref", str(pref), "handle", str(handle), "flower"]
        args = ["skip_hw", "ip_proto", protocol, side + "_ip", address, side + "_port", str(port)]
        args += ["classid", classid] if classid else ["action", "mirred", "egress", "redirect", "dev", ifb]
        return {"type": "filter", "dev": dev, "parent": parent, "pref": pref,
                "handle": str(handle), "protocol": wire, "kind": "flower", "keys": keys,
                "classid": classid, "ifb": ifb, "create": start + args,
                "delete": ["tc", "filter", "del", "dev", dev, "parent", parent,
                           "protocol", wire, "pref", str(pref), "handle", str(handle), "flower"]}

    def _plan(self, entry, record, dev, addresses, state):
        objects = []
        shared = deepcopy(state["shared"])
        slot = record["slot"]
        classid = ROOT + format(slot + 1, "x")
        if record["download_bps"] is not None:
            root = self._qdisc(dev, "htb", ROOT)
            if not any(_object_id(o) == _object_id(root) for o in shared):
                shared.append(root)
            objects += [self._class(dev, classid, record["download_bps"]),
                        self._qdisc(dev, "pfifo", format(0xb000 + slot, "x") + ":", classid)]
            for i, (address, proto) in enumerate((a, p) for a in addresses for p in entry["protocols"]):
                objects.append(self._filter(dev, ROOT, 1000 + slot * 64 + i, str(1 + i),
                                            address, proto, entry["port"], classid=classid))
        if record["upload_bps"] is not None:
            # Dedicated IFB keeps all client upload traffic in one shared budget.
            ifb = "vpm" + hashlib.sha256(entry["port_id"].encode()).hexdigest()[:11]
            alias = "v2ray-agent:port-manager:" + entry["port_id"]
            link = {"type": "link", "dev": ifb, "alias": alias,
                    "create": ["ip", "link", "add", "name", ifb, "type", "ifb"],
                    "delete": ["ip", "link", "del", "dev", ifb]}
            ingress = self._qdisc(dev, "ingress", "ffff:")
            ingress["parent"] = "ingress"
            ingress["create"] = ["tc", "qdisc", "add", "dev", dev, "handle", "ffff:", "ingress"]
            ingress["delete"] = ["tc", "qdisc", "del", "dev", dev, "ingress"]
            if not any(_object_id(o) == _object_id(ingress) for o in shared):
                shared.append(ingress)
            objects += [link, self._qdisc(ifb, "htb", ROOT),
                        self._class(ifb, classid, record["upload_bps"]),
                        self._qdisc(ifb, "pfifo", format(0xb000 + slot, "x") + ":", classid)]
            # Classification happens before IFB reinjection; no port classifier
            # runs on the IFB. The redirect assigns the IFB's HTB class directly
            # through a fixed default, so both families share that class.
            objects[-3]["create"][-1] = format(slot + 1, "x")
            objects[-3]["default"] = slot + 1
            for i, (address, proto) in enumerate((a, p) for a in addresses for p in entry["protocols"]):
                objects.append(self._filter(dev, "ffff:", 1000 + slot * 64 + i, str(1 + i),
                                            address, proto, entry["port"], ifb=ifb))
        return shared, objects

    def _all_owned(self, state):
        return state["shared"] + [o for r in state["entries"].values() for o in r.get("objects", [])]

    def _guard_initial_tree(self, dev, state):
        owned = self._all_owned(state)
        known = {(o["dev"], o.get("handle")) for o in owned if o["type"] == "qdisc"}
        for live in self._json(["tc", "-j", "qdisc", "show", "dev", dev]):
            if (dev, live.get("handle")) in known:
                continue
            if live.get("kind") == "noqueue" and live.get("handle") == "0:":
                continue
            # HTB creates an implicit pfifo leaf before we install our named one.
            if live.get("kind") == "pfifo" and live.get("handle") == "0:" and live.get("parent") in {
                    o["handle"] for o in owned if o["type"] == "class" and o["dev"] == dev}:
                continue
            raise RateLimitError("接口 {} 存在未归属的 {} 队列；不自动替换既有 QoS".format(dev, live.get("kind")))
        classes = self._json(["tc", "-j", "class", "show", "dev", dev])
        known_classes = {o["handle"] for o in owned if o["type"] == "class" and o["dev"] == dev}
        if any(c.get("handle") not in known_classes for c in classes):
            raise RateLimitError("存在未归属的 tc 类，停止更改")
        for parent in (ROOT, "ffff:"):
            live_filters = self._json(["tc", "-j", "filter", "show", "dev", dev, "parent", parent])
            allowed = {(str(o["pref"]), o["protocol"], str(o["handle"])) for o in owned
                       if o["type"] == "filter" and o["dev"] == dev and o["parent"] == parent}
            for filt in live_filters:
                handle = filt.get("options", {}).get("handle", filt.get("handle"))
                if handle is None:  # tc also prints a per-priority header.
                    if not any((str(filt.get("pref")), filt.get("protocol")) == item[:2]
                               for item in allowed):
                        raise RateLimitError("存在未归属的 tc 分类，停止更改")
                    continue
                try:
                    handle = str(int(str(handle), 0))
                except ValueError:
                    raise RateLimitError("无法识别已有分类句柄，停止更改")
                if (str(filt.get("pref")), filt.get("protocol"), handle) not in allowed:
                    raise RateLimitError("存在未归属的 tc 分类，停止更改")

    def _create(self, obj):
        self._run(obj["create"])
        if obj["type"] == "link":
            self._run(["ip", "link", "set", "dev", obj["dev"], "alias", obj["alias"]])
            self._run(["ip", "link", "set", "dev", obj["dev"], "up"])
        live = self._get(obj)
        self._verify_spec(obj, live)
        obj["fingerprint"] = self._fingerprint(obj, live)

    def _replace(self, old, new):
        self._verify_owned(old)
        if old["type"] == "class":
            command = list(new["create"])
            command[2] = "change"
            self._run(command)
        elif old["type"] == "filter":
            command = list(new["create"])
            command[2] = "replace"
            self._run(command)
        else:
            raise RateLimitError("公共调度对象参数变化，需要人工检查")
        live = self._get(new)
        self._verify_spec(new, live)
        new["fingerprint"] = self._fingerprint(new, live)

    def _transaction(self, state, target):
        old_by_id = {_object_id(o): o for o in self._all_owned(state)}
        new_by_id = {_object_id(o): o for o in self._all_owned(target)}
        undo = []
        working = deepcopy(state)
        working["pending"] = {"started": int(time.time()), "old": deepcopy(state), "target": deepcopy(target)}
        self._save(working)
        try:
            for oid, old in old_by_id.items():
                self._verify_owned(old, allow_missing=True)
            # Create parents first. Replace classifications only after queues exist.
            for oid, new in new_by_id.items():
                old = old_by_id.get(oid)
                live = self._get(new)
                if live is None:
                    undo.append(("remove", new, None))
                    self._create(new)
                elif old:
                    self._verify_owned(old)
                    if old["create"] != new["create"]:
                        undo.append(("restore", new, old))
                        self._replace(old, new)
                    else:
                        new["fingerprint"] = deepcopy(old["fingerprint"])
                else:
                    raise RateLimitError("执行对象名称已被占用，拒绝接管: " + oid)
                # Preserve observed ownership after each successful operation.
                # Recovery will never adopt an unverified object merely because
                # its name was planned in a transaction.
                working["pending"]["target"] = deepcopy(target)
                self._save(working)
            # Leaf/filter removal precedes parent/link removal. Shared roots stay.
            for oid, old in reversed(list(old_by_id.items())):
                if oid in new_by_id:
                    continue
                if self._verify_owned(old, allow_missing=True) is not None:
                    undo.append(("recreate", None, old))
                    self._run(old["delete"])
            for obj in self._all_owned(target):
                self._verify_owned(obj)
            target["fault"] = None
            target.pop("pending", None)
            self._save(target)
        except Exception as exc:
            failures = []
            for action, new, old in reversed(undo):
                try:
                    if action == "remove":
                        live = self._get(new)
                        if live:
                            self._verify_spec(new, live)
                            if new.get("fingerprint") and new["fingerprint"] != self._fingerprint(new, live):
                                raise RateLimitError("回退对象在操作期间被外部更改")
                            self._run(new["delete"])
                    elif action == "restore":
                        live = self._get(new)
                        if live and self._fingerprint(old, live) == old.get("fingerprint"):
                            continue
                        self._verify_spec(new, live)
                        new["fingerprint"] = self._fingerprint(new, live)
                        self._replace(new, old)
                    elif action == "recreate":
                        if self._get(old) is not None:
                            raise RateLimitError("回退对象名称被占用")
                        self._create(old)
                except Exception as rollback_exc:
                    failures.append(str(rollback_exc))
            state["fault"] = str(exc) + ("；回退不完整: " + "; ".join(failures) if failures else "；已回退本次更改")
            if failures:
                state["pending"] = working["pending"]
            self._save(state)
            raise RateLimitError(state["fault"]) from exc

    def _recover_locked(self):
        state = self._load()
        pending = state.get("pending")
        if not pending:
            return False
        old = deepcopy(pending["old"])
        target = deepcopy(pending["target"])
        old_objects = {_object_id(o): o for o in self._all_owned(old)}
        target_objects = {_object_id(o): o for o in self._all_owned(target)}
        union = dict(old_objects)
        union.update(target_objects)
        actual = {}
        try:
            # Validate the entire namespace before the first recovery mutation.
            for oid, obj in union.items():
                live = self._get(obj)
                if live is None:
                    continue
                original = old_objects.get(oid)
                proposed = target_objects.get(oid)
                if original and original.get("fingerprint") == self._fingerprint(original, live):
                    actual[oid] = deepcopy(original)
                elif proposed and proposed.get("fingerprint") == self._fingerprint(proposed, live):
                    actual[oid] = deepcopy(proposed)
                elif original and proposed:
                    # The old ownership record reserves this exact class/filter;
                    # a crash between mutation and its checkpoint is recoverable
                    # only if parameters match our proposed change exactly.
                    self._verify_spec(proposed, live)
                    actual[oid] = deepcopy(proposed)
                    actual[oid]["fingerprint"] = self._fingerprint(proposed, live)
                else:
                    raise RateLimitError("未完成事务包含无法验证归属的新对象: " + oid)
            observed = {"shared": list(actual.values()), "entries": {}}
            devices = {o["dev"] for o in actual.values()}
            for dev in devices:
                self._guard_initial_tree(dev, observed)
            # Remove only verified objects that did not exist before the change.
            for oid, obj in reversed(list(actual.items())):
                if oid not in old_objects:
                    self._verify_owned(obj)
                    self._run(obj["delete"])
            for oid, obj in old_objects.items():
                current = actual.get(oid)
                if current is None:
                    self._create(obj)
                elif current["create"] != obj["create"]:
                    self._replace(current, obj)
                else:
                    self._verify_owned(obj)
                # Recreated action indices can differ; retain the new evidence.
                state["pending"]["old"] = deepcopy(old)
                self._save(state)
            for obj in self._all_owned(old):
                self._verify_owned(obj)
            old.pop("pending", None)
            old["fault"] = None
            old["last_recovery"] = int(time.time())
            self._save(old)
            return True
        except Exception as exc:
            state["fault"] = "限速事务恢复未完成；保留现场: " + str(exc)
            self._save(state)
            raise RateLimitError(state["fault"]) from exc

    def recover(self):
        with self._lock():
            return self._recover_locked()

    def _set_locked(self, entry, upload_bps=KEEP, download_bps=KEEP):
        entry = self._entry(entry)
        self._recover_locked()
        state = self._load()
        if state.get("pending"):
            raise RateLimitError("存在未完成的限速事务，请检查 rates.json 中 pending 与实际对象后再操作")
        old = state["entries"].get(entry["port_id"])
        rates = {"upload_bps": None, "download_bps": None} if old is None else deepcopy(old)
        for key, value in (("upload_bps", upload_bps), ("download_bps", download_bps)):
            if value is not KEEP:
                _validate_rate(value)
                rates[key] = value
        active = rates["upload_bps"] is not None or rates["download_bps"] is not None
        if not old and not active:
            return {"port_id": entry["port_id"], "upload_bps": None, "download_bps": None,
                    "applied": False, "state": "unlimited", "supported": True, "reason": "",
                    "experimental": True, "throughput_verified": False,
                    "limitations": list(LIMITATIONS)}
        dev, addresses = self._network(entry)
        if old and old.get("interface") != dev:
            raise RateLimitError("外部接口变化，需人工检查旧接口对象后迁移")
        for device in {dev} | {o["dev"] for o in self._all_owned(state) if o["type"] == "link"}:
            # The IFB can disappear on reboot; it will be recreated after checking
            # that its name is free. Never query nonexistent device tc trees.
            if device == dev or any(l.get("ifname") == device for l in
                    self._json(["ip", "-j", "-d", "link", "show"])):
                self._guard_initial_tree(device, state)
        for pid, record in state["entries"].items():
            if pid != entry["port_id"] and record.get("entry", {}).get("port") == entry["port"]:
                if set(record.get("addresses", [])) & set(addresses) and set(record["entry"]["protocols"]) & set(entry["protocols"]):
                    raise RateLimitError("相同地址/协议/端口已有其他限速入口，无法独立归属")
        occupied = {r["slot"] for r in state["entries"].values()}
        if old is None:
            slots = [s for s in range(1, 1000) if s not in occupied]
            if not slots:
                raise RateLimitError("达到首版限速入口数量上限")
            rates["slot"] = slots[0]
        rates.update(entry=entry, interface=dev, addresses=addresses)
        shared, objects = self._plan(entry, rates, dev, addresses, state)
        rates["objects"] = objects
        target = deepcopy(state)
        target["shared"] = shared
        changed = old is None or any(rates.get(k) != old.get(k) for k in
            ("entry", "interface", "addresses", "upload_bps", "download_bps"))
        if changed:
            rates["revision"] = (old or {}).get("revision", 0) + 1
            rates["updated_at"] = int(time.time())
            event = {"time": rates["updated_at"], "port_id": entry["port_id"],
                     "port": entry["port"], "interface": dev,
                     "old_upload_bps": (old or {}).get("upload_bps"),
                     "old_download_bps": (old or {}).get("download_bps"),
                     "upload_bps": rates["upload_bps"], "download_bps": rates["download_bps"],
                     "revision": rates["revision"]}
            target["history"] = (target.get("history", []) + [event])[-100:]
        target["entries"][entry["port_id"]] = rates
        self._transaction(state, target)
        return self._status_locked(entry)

    def set(self, entry, upload_bps=KEEP, download_bps=KEEP):
        with self._lock():
            return self._set_locked(entry, upload_bps, download_bps)

    def _status_locked(self, entry):
        state = self._load()
        record = state["entries"].get(entry.get("port_id"), {})
        result = {"port_id": entry.get("port_id"), "upload_bps": record.get("upload_bps"),
                  "download_bps": record.get("download_bps"), "applied": False,
                  "supported": False, "state": "unlimited", "reason": "",
                  "interface": record.get("interface"), "fault": state.get("fault"),
                  "throughput_verified": False, "experimental": True,
                  "limitations": list(LIMITATIONS), "queue_packets": QUEUE_PACKETS}
        result["revision"] = record.get("revision", 0)
        for direction in ("upload", "download"):
            result[direction + "_burst_bytes"] = next((o["burst_bytes"] for o in
                record.get("objects", []) if o["type"] == "class" and
                (o["dev"] == record.get("interface")) == (direction == "download")), None)
        try:
            clean = self._entry(entry)
            dev, addresses = self._network(clean)
            self._guard_initial_tree(dev, state)
            result["supported"] = True
            if state.get("pending"):
                raise RateLimitError("存在未完成的限速事务，执行状态未知")
            if record.get("upload_bps") is not None or record.get("download_bps") is not None:
                if record.get("entry") != clean or record.get("addresses") != addresses or record.get("interface") != dev:
                    raise RateLimitError("监听或接口映射变化，限速分类尚未同步")
                for obj in state["shared"] + record.get("objects", []):
                    self._verify_owned(obj)
                result.update(applied=True, state="applied")
        except RateLimitError as exc:
            result["reason"] = str(exc)
            result["state"] = "fault" if record else "unsupported"
        return result

    def status(self, entry):
        with self._lock(readonly=True):
            return self._status_locked(entry)

    def migrate(self, entry, new_port):
        with self._lock():
            self._recover_locked()
            state = self._load()
            if entry.get("port_id") not in state["entries"]:
                return {"changed": False}
            updated = deepcopy(entry)
            updated["port"] = new_port
            return self._set_locked(updated)

    def reconcile(self, entries):
        results = []
        by_id = {e["port_id"]: e for e in entries}
        with self._lock():
            self._recover_locked()
            for pid, record in list(self._load()["entries"].items()):
                entry = by_id.get(pid)
                if entry is None:
                    results.append({"port_id": pid, "applied": False, "state": "fault",
                                    "reason": "限速入口已消失，保留对象等待人工核对"})
                    continue
                try:
                    results.append(self._set_locked(entry))
                except RateLimitError as exc:
                    results.append({"port_id": pid, "applied": False, "state": "fault", "reason": str(exc)})
        return results

    def on_policy_block(self, entry):
        """Drain this entrance after policy's input/output block is installed.

        Existing link/NIC packets are outside this boundary. Other classes and
        quotas are untouched. A failure leaves policy blocking in place.
        """
        with self._lock():
            state = self._load()
            record = state["entries"].get(entry.get("port_id"))
            if not record:
                return {"drained": True, "queues": 0}
            queues = [o for o in record.get("objects", []) if o.get("kind") == "pfifo"]
            for obj in state["shared"] + record.get("objects", []):
                # At boot a vanished queue contains no old buffered packets.
                # Permit the policy block to settle before rate reconciliation
                # recreates objects. Existing mismatched objects still fail.
                self._verify_owned(obj, allow_missing=True)
            drained = 0
            for obj in queues:
                if self._verify_owned(obj, allow_missing=True) is None:
                    continue
                self._run(obj["delete"])
                try:
                    self._create(obj)
                except RateLimitError as exc:
                    state["fault"] = "入口已阻断；目标队列清理后恢复失败: " + str(exc)
                    self._save(state)
                    raise RateLimitError(state["fault"]) from exc
                drained += 1
            self._save(state)
            return {"drained": True, "queues": drained, "missing_queues": len(queues) - drained}
