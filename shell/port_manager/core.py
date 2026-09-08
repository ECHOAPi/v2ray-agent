"""Conservative port inventory and recoverable, targeted host transactions.

All mutating entry points require the caller to hold the installer's common
``root/.write.lock`` flock. No installer or subscription generator is invoked.
External commands are argv lists, and command stderr (which can contain keys)
is deliberately not copied into exceptions, journals or menus.
"""
from __future__ import annotations

import copy
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
import uuid


class PortError(ValueError):
    pass


class Runner:
    def run(self, args, input=None):
        try:
            return subprocess.run(args, input=input, text=True, capture_output=True,
                                  check=False, timeout=90,
                                  env={**os.environ, "LC_ALL": "C"})
        except FileNotFoundError:
            return subprocess.CompletedProcess(args, 127, "", "")
        except subprocess.TimeoutExpired:
            raise PortError("Command timed out: " + Path(args[0]).name) from None


def port_input(value):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,5}", str(value)):
        raise PortError("Port must be one decimal integer from 1 to 65535")
    number = int(value)
    if not 1 <= number <= 65535:
        raise PortError("Port must be one decimal integer from 1 to 65535")
    return number


def _json(path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(Path(path).read_text(), object_pairs_hook=unique_pairs)
    except (ValueError, OSError):
        raise PortError("Invalid or unreadable JSON: " + Path(path).name) from None


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else None


def _atomic_bytes(path, data, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".pm-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner is not None and os.geteuid() == 0:
            os.fchown(fd, *owner)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        parent = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _write_json(path, value):
    _atomic_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())


def _ip(address):
    address = str(address).strip("[]").split("%", 1)[0]
    if address in ("*", "", "::"):
        return None
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        raise PortError("Unrecognized listen address") from None


def addresses_overlap(first, second):
    """Treat IPv6 wildcard as dual stack; never assume v6only is enabled."""
    a, b = _ip(first), _ip(second)
    if a is None or b is None:
        return True
    if a.version != b.version:
        return False
    return a.is_unspecified or b.is_unspecified or a == b


def _loopback(address):
    try:
        value = _ip(address)
        return bool(value and value.is_loopback)
    except PortError:
        return False


def _deny(entry, reason):
    entry["supported"] = False
    entry["reason"] = reason


def _config_files(root):
    for core, folder in (("xray", "xray/conf"), ("sing-box", "sing-box/conf/config")):
        directory = root / folder
        if directory.exists():
            for path in sorted(directory.glob("*.json")):
                yield core, path


def _inbound_shape(inbound):
    if not isinstance(inbound, dict):
        return False
    for key in ("tag", "listen", "protocol", "type"):
        if key in inbound and not isinstance(inbound[key], str):
            return False
    for key in ("settings", "streamSettings", "tls"):
        if key in inbound and not isinstance(inbound[key], dict):
            return False
    for key in ("clients", "fallbacks"):
        value = inbound.get("settings", {}).get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            return False
    stream = inbound.get("streamSettings", {})
    for key in ("sockopt", "realitySettings", "xhttpSettings"):
        if key in stream and not isinstance(stream[key], dict):
            return False
    if "network" in stream and not isinstance(stream["network"], str):
        return False
    tls = inbound.get("tls", {})
    if "reality" in tls and not isinstance(tls["reality"], dict):
        return False
    return isinstance(inbound.get("users", []), list)


def inventory(root=Path("/etc/v2ray-agent")):
    root = Path(root)
    records, objects = [], []
    malformed = False
    for core, path in _config_files(root):
        relative = str(path.relative_to(root))
        try:
            if path.is_symlink():
                raise PortError("Symlinked configuration")
            doc = _json(path)
            inbounds = doc.get("inbounds", [])
            if not isinstance(inbounds, list) or not all(_inbound_shape(inbound) for inbound in inbounds):
                raise PortError("Invalid inbound list")
        except (PortError, AttributeError):
            malformed = True
            records.append(dict(port_id=hashlib.sha256((core+relative).encode()).hexdigest()[:24],
                                core=core, file=relative, index=None, tag=path.stem,
                                port=None, listen="?", protocols=[], kind="unreadable",
                                supported=False, reason="Malformed, symlinked or unreadable configuration"))
            continue
        for index, inbound in enumerate(inbounds):
            if not isinstance(inbound, dict):
                malformed = True
                continue
            tag = inbound.get("tag") or "@index:" + str(index)
            raw_port = inbound.get("port" if core == "xray" else "listen_port")
            listen = inbound.get("listen", "::")
            protocol = inbound.get("protocol" if core == "xray" else "type", "unknown")
            network = inbound.get("settings", {}).get("network", "tcp")
            protocols = ["udp"] if protocol in ("hysteria2", "tuic") else ["tcp"]
            if protocol == "dokodemo-door":
                protocols = sorted(set(network.split(","))) if isinstance(network, str) else []
            entry = dict(port_id=hashlib.sha256((core+"\0"+relative+"\0"+str(tag)).encode()).hexdigest()[:24],
                         core=core, file=relative, index=index, source_index=index,
                         tag=tag, port=raw_port, listen=listen, protocols=protocols,
                         kind="unknown", supported=False, reason="Unknown/custom configuration")
            records.append(entry)
            objects.append((entry, inbound, inbounds))
            try:
                entry["port"] = port_input(raw_port)
                _ip(listen)
            except PortError:
                _deny(entry, "Port range or listen address is not adapted")
                continue
            if _loopback(listen):
                entry["kind"] = "internal"
                _deny(entry, "Internal loopback/fallback listener")
                continue
            if core == "xray":
                stream = inbound.get("streamSettings", {})
                security = stream.get("security")
                transport = stream.get("network", "tcp")
                if protocol == "vless" and security == "reality" and transport in ("tcp", "raw", "xhttp"):
                    entry.update(kind="xray-xhttp" if transport == "xhttp" else "xray-reality",
                                 supported=True, reason="")
                elif (protocol == "dokodemo-door" and path.name == "07_VLESS_vision_reality_inbounds.json"
                      and index == 0 and len(inbounds) == 2
                      and inbound.get("tag") == "dokodemo-in-VLESSReality"
                      and inbound.get("settings", {}).get("address") == "127.0.0.1"
                      and inbound.get("settings", {}).get("port") == 45987
                      and network == "tcp"
                      and inbounds[1].get("listen") == "127.0.0.1"
                      and inbounds[1].get("port") == 45987
                      and inbounds[1].get("protocol") == "vless"
                      and inbounds[1].get("streamSettings", {}).get("security") == "reality"
                      and not inbounds[1].get("settings", {}).get("fallbacks")):
                    entry.update(kind="xray-reality-forward", supported=True, reason="", source_index=1)
                elif (protocol == "dokodemo-door"
                      and re.fullmatch(r"02_dokodemodoor_inbounds_(?:hysteria_)?[0-9]+(?:_default)?\.json", path.name)
                      and len(inbounds) == 1
                      and inbound.get("settings", {}).get("address") == "127.0.0.1"
                      and inbound.get("settings", {}).get("followRedirect") is False
                      and network in ("tcp", "udp")):
                    entry["kind"] = "additional"
                    entry["target_port"] = inbound["settings"].get("port")
                    entry["default"] = "_default" in path.name
                    _deny(entry, "Additional forward; use the additional-port submenu")
                elif security == "tls":
                    entry["kind"] = "shared-tls"
                    _deny(entry, "TLS/Nginx/shared entry is read-only in v1")
                if inbound.get("settings", {}).get("fallbacks"):
                    _deny(entry, "Fallback/shared routing dependency")
                if stream.get("sockopt", {}).get("acceptProxyProtocol") or stream.get("externalProxy"):
                    _deny(entry, "External proxy dependency")
                if transport == "xhttp":
                    xhttp = stream.get("xhttpSettings", {})
                    if xhttp.get("extra") or xhttp.get("downloadSettings") or security != "reality":
                        _deny(entry, "XHTTP CDN/split transport is not adapted")
                if entry["supported"] and path.name not in (
                        "07_VLESS_vision_reality_inbounds.json", "12_VLESS_XHTTP_inbounds.json"):
                    _deny(entry, "Custom Xray fragment is not adapted")
            else:
                tls = inbound.get("tls", {})
                if protocol in ("hysteria2", "tuic"):
                    entry.update(kind="sing-box-" + protocol, supported=True, reason="")
                elif (protocol == "vless" and tls.get("reality", {}).get("enabled")
                      and not inbound.get("transport")):
                    entry.update(kind="sing-box-reality", supported=True, reason="")
                elif tls.get("enabled"):
                    entry["kind"] = "shared-tls"
                    _deny(entry, "Non-Reality TLS entry is read-only in v1")
                if any(inbound.get(key) for key in ("listen_ports", "port_hopping", "detour", "proxy_protocol")):
                    _deny(entry, "Port hopping/detour/proxy dependency")
                if entry["supported"] and path.name not in (
                        "07_VLESS_vision_reality_inbounds.json", "06_hysteria2_inbounds.json", "09_tuic_inbounds.json"):
                    _deny(entry, "Custom sing-box fragment is not adapted")
            if not inbound.get("tag") and entry["kind"] != "xray-reality-forward":
                _deny(entry, "Missing stable inbound tag")
            if not set(protocols).issubset({"tcp", "udp"}) or not protocols:
                _deny(entry, "Unknown transport protocols")
    for entry, inbound, _ in objects:
        for other, other_inbound, _ in objects:
            if entry is other:
                continue
            if entry["port_id"] == other["port_id"] or (entry["core"] == other["core"] and entry["tag"] == other["tag"] and not str(entry["tag"]).startswith("@index:")):
                _deny(entry, "Duplicate inbound tag/identity")
            if (isinstance(entry["port"], int) and entry["port"] == other["port"]
                    and set(entry["protocols"]) & set(other["protocols"])):
                try:
                    if addresses_overlap(entry["listen"], other["listen"]):
                        _deny(entry, "Shared/conflicting configured listener")
                except PortError:
                    _deny(entry, "Unrecognized peer listen address")
            settings = other_inbound.get("settings", {})
            if (other_inbound.get("protocol") == "dokodemo-door"
                    and settings.get("port") == entry["port"]
                    and entry["kind"] != "internal"):
                _deny(entry, "An additional forwarding entry depends on this port")
        if malformed and entry["supported"]:
            _deny(entry, "Another core fragment is malformed; dependency analysis incomplete")
    # nginx is never changed. Scan supplied installation-local mirrors for read-only inventory.
    nginx_dirs = [root / "nginx"]
    if root == Path("/etc/v2ray-agent"):
        nginx_dirs += [Path("/etc/nginx/conf.d"), Path("/etc/nginx/http.d")]
    for directory in nginx_dirs:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.conf")):
            try:
                data = path.read_text()
            except OSError:
                continue
            for i, match in enumerate(re.finditer(r"(?m)^\s*listen\s+(?:\[([^]]+)\]:|([0-9.]+):)?([0-9]+)\b", data)):
                port = int(match.group(3))
                listen = match.group(1) or match.group(2) or "0.0.0.0"
                records.append(dict(port_id=hashlib.sha256((str(path)+str(i)).encode()).hexdigest()[:24],
                                    core="nginx", file=str(path), index=i, tag=path.stem,
                                    port=port, listen=listen, protocols=["tcp"], kind="subscription" if "subscribe" in path.name else "nginx",
                                    supported=False, reason="Nginx/subscription service is read-only"))
                for entry in records:
                    if entry["core"] != "nginx" and entry["port"] == port and "tcp" in entry["protocols"]:
                        _deny(entry, "Shared Nginx/subscription listener")
            for entry in records:
                if entry["supported"] and re.search(r"(?:proxy_pass|grpc_pass)\s+[^;\n]*:"+str(entry["port"])+r"\b", data):
                    _deny(entry, "Nginx reverse proxy depends on this port")
    return records


def _ss_records(output):
    records = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        address, sep, port = fields[4].rpartition(":")
        if not sep or not port.isdigit():
            continue
        records.append(dict(protocol=fields[0], listen=address.strip("[]"),
                            port=int(port), pids=[int(x) for x in re.findall(r"pid=(\d+)", line)]))
    return records


class Manager:
    def __init__(self, root=Path("/etc/v2ray-agent"), runner=None,
                 subscription_stager=None, policies=None, rate_limiter=None):
        self.root = Path(root).resolve()
        self.state = self.root / "port-manager"
        self.runner = runner or Runner()
        self.subscription_stager = subscription_stager
        self.policies = policies
        self.rate_limiter = rate_limiter

    def _run(self, args, input=None, required=True):
        result = self.runner.run([str(x) for x in args], input=input)
        if required and result.returncode:
            raise PortError("Command failed: " + Path(str(args[0])).name + " " + str(args[1] if len(args)>1 else ""))
        return result

    def list(self):
        return inventory(self.root)

    def _entry(self, port_id):
        matches = [e for e in self.list() if e["port_id"] == port_id]
        if len(matches) != 1:
            raise PortError("Entry not found or identity is ambiguous; refresh the list")
        return matches[0]

    def _mkdir(self):
        if self.state.is_symlink() or (self.state / "transactions").is_symlink():
            raise PortError("Symlinked state directory is not supported")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        (self.state / "transactions").mkdir(exist_ok=True, mode=0o700)

    def history(self):
        items = []
        for path in sorted((self.state / "transactions").glob("*/journal.json")):
            journal = _json(path)
            items.append({key: journal.get(key) for key in
                          ("id", "status", "operation", "entry", "old_port", "new_port", "created", "reverses")})
        return sorted(items, key=lambda item: (item.get("created", 0), item["id"]))

    def _save(self, journal):
        _write_json(self.state / "transactions" / journal["id"] / "journal.json", journal)

    def _path(self, relative):
        path = self.root / relative
        if not path.resolve().is_relative_to(self.root) or path.is_symlink():
            raise PortError("Unsafe path in transaction")
        # Refuse symlinked parent paths as well, even when pointing inside root.
        if any(p.is_symlink() for p in path.parents if p != self.root and p.is_relative_to(self.root)):
            raise PortError("Symlinked configuration directory is not supported")
        return path

    def check_port(self, port, protocols=None, listen="::", exclude=None):
        port = port_input(port)
        protocols = protocols or ["tcp", "udp"]
        _ip(listen)
        conflicts = []
        for e in self.list():
            if e["port_id"] != exclude and e["port"] == port and set(e["protocols"]) & set(protocols):
                if addresses_overlap(e["listen"], listen):
                    conflicts.append(dict(source="configuration", core=e["core"], tag=e["tag"],
                                          port=port, listen=e["listen"], protocols=e["protocols"]))
        for item in _ss_records(self._run(["ss", "-H", "-lntup"]).stdout):
            if item["port"] == port and item["protocol"] in protocols and addresses_overlap(item["listen"], listen):
                conflicts.append(dict(source="listener", **item))
        return conflicts

    def _service(self, entry):
        # systemctl fails on OpenRC/container installations instead of falling back.
        unit = entry["core"] + ".service"
        info = self._run(["systemctl", "show", unit, "--property=ActiveState,MainPID,ExecStart,FragmentPath"]).stdout
        values = dict(line.split("=", 1) for line in info.splitlines() if "=" in line)
        binary = self.root / entry["core"] / entry["core"]
        if values.get("ActiveState") != "active" or not values.get("MainPID", "").isdigit() or int(values["MainPID"]) <= 0:
            raise PortError("Target core is not healthy/active; restore it before changing ports")
        if str(binary) not in values.get("ExecStart", ""):
            raise PortError("Unknown/custom systemd core command")
        expected = str(self.root / ("xray/conf" if entry["core"] == "xray" else "sing-box/conf/config.json"))
        if expected not in values.get("ExecStart", "") or not values.get("FragmentPath"):
            raise PortError("Core service does not use the adapted configuration layout")
        argv_match = re.search(r"argv\[\]=(.*?)(?:\s*;|$)", values["ExecStart"])
        expected_argv = [str(binary), "run", "-confdir" if entry["core"] == "xray" else "-c", expected]
        try:
            actual_argv = shlex.split(argv_match.group(1)) if argv_match else []
        except ValueError:
            actual_argv = []
        if actual_argv != expected_argv:
            raise PortError("Custom core service arguments are not adapted")
        return unit, int(values["MainPID"])

    def _verify_listener(self, entry, port):
        error = None
        for attempt in range(4):
            try:
                return self._verify_listener_once(entry, port)
            except PortError as exc:
                error = exc
                if attempt < 3:
                    time.sleep(0.25)
        raise error

    def _verify_listener_once(self, entry, port):
        _, pid = self._service(entry)
        listeners = _ss_records(self._run(["ss", "-H", "-lntup"]).stdout)
        for proto in entry["protocols"]:
            found = [x for x in listeners if x["port"] == port and x["protocol"] == proto
                     and addresses_overlap(entry["listen"], x["listen"]) and pid in x["pids"]]
            if not found:
                raise PortError("Target service listener/address/process verification failed")
            expected_ip = _ip(entry["listen"])
            if expected_ip is None:
                if not any(x["listen"] in ("*", "::", "") for x in found):
                    raise PortError("IPv6/dual-stack wildcard listener is missing")
            elif expected_ip.is_unspecified:
                if not any(x["listen"] == "0.0.0.0" for x in found):
                    raise PortError("IPv4 wildcard listener is missing")
            else:
                if not any(_ip(x["listen"]) == expected_ip for x in found):
                    raise PortError("Target service listen address does not match configuration")

    def listener_status(self, entry):
        if entry["core"] not in ("xray", "sing-box") or not isinstance(entry["port"], int):
            return {"status": "unverified", "public_verification": "unverified"}
        try:
            self._verify_listener_once(entry, entry["port"])
            return {"status": "verified", "public_verification": "unverified"}
        except PortError:
            return {"status": "unverified", "public_verification": "unverified"}

    def _firewall(self, entry):
        ufw = self._run(["ufw", "status"], required=False)
        firewalld = self._run(["firewall-cmd", "--state"], required=False)
        active_ufw = ufw.returncode == 0 and "Status: active" in ufw.stdout
        active_firewalld = firewalld.returncode == 0 and firewalld.stdout.strip() == "running"
        if active_ufw and active_firewalld:
            raise PortError("Multiple active firewall managers; automatic changes blocked")
        nft = self._run(["nft", "-j", "list", "ruleset"], required=False)
        iptables = self._run(["iptables-save"], required=False)
        ip6tables = self._run(["ip6tables-save"], required=False)
        raw = iptables.stdout + "\n" + ip6tables.stdout
        if re.search(r"\b(?:DNAT|REDIRECT|TPROXY)\b", raw):
            raise PortError("NAT/port-hopping/transparent forwarding dependencies require manual review")
        nft_rules = []
        if nft.returncode == 0:
            try:
                nft_rules = json.loads(nft.stdout).get("nftables", [])
            except (ValueError, AttributeError):
                raise PortError("Cannot inspect native firewall rules") from None
            if any(re.search(r'"(?:dnat|redirect|tproxy)"', json.dumps(x)) for x in nft_rules):
                raise PortError("Native NAT/forwarding dependencies require manual review")
        elif not active_ufw and not active_firewalld:
            raise PortError("nftables inspection unavailable; cannot establish firewall state")
        owned = {"v2ray_agent_ports"}
        if active_firewalld or active_ufw:
            allowed_tables = owned | ({"firewalld"} if active_firewalld else {"filter", "nat", "mangle", "raw"})
            for item in nft_rules:
                rule = item.get("rule") or item.get("chain")
                if rule and rule.get("table") not in allowed_tables:
                    raise PortError("Additional native firewall manager detected")
        if active_firewalld:
            zones = self._run(["firewall-cmd", "--get-active-zones"]).stdout.splitlines()
            names = [line.strip() for line in zones if line and not line[0].isspace()]
            if len(names) != 1:
                raise PortError("Only one active firewalld zone is adapted")
            return {"backend": "firewalld", "zone": names[0]}
        if active_ufw:
            return {"backend": "ufw"}
        for item in nft_rules:
            rule = item.get("rule") or item.get("chain")
            if rule and rule.get("table") not in owned:
                if "expr" in rule or rule.get("policy") == "drop":
                    raise PortError("Unadapted native nftables filtering; automatic changes blocked")
        if re.search(r"^-A |^:[^ ]+ (?:DROP|REJECT)\b", raw, re.MULTILINE):
            raise PortError("Unadapted iptables filtering; automatic changes blocked")
        return {"backend": "none", "note": "No active local filtering detected"}

    def _rule_plan(self, entry, port, firewall, txid):
        rules = []
        for proto in entry["protocols"]:
            if firewall["backend"] == "ufw":
                # UFW deduplicates matching rules and can replace the original comment.
                # Never tag/remove a rule that predates this transaction.
                status = self._run(["ufw", "status"]).stdout
                rows = [line for line in status.splitlines()
                        if re.search(r"(?<![0-9])"+str(port)+r"(?:/"+proto+r")?(?![0-9])", line)]
                if rows:
                    if all("ALLOW" in row and re.search(r"(?<![0-9])"+str(port)+r"/"+proto+r"\b", row) for row in rows):
                        if entry["listen"] in ("::", "*") and not (
                                any("(v6)" in row for row in rows) and any("(v6)" not in row for row in rows)):
                            raise PortError("Existing UFW rule does not establish both address families")
                        rules.append({"add": [], "remove": [], "owned": False, "applied": False})
                        continue
                    raise PortError("Existing ambiguous UFW rule for requested port; review it first")
                comment = "v2ray-pm-" + txid[-12:] + "-" + proto
                destination = "any" if entry["listen"] in ("::", "0.0.0.0", "*") else entry["listen"]
                args = ["ufw", "allow", "proto", proto, "from", "any", "to", destination,
                        "port", str(port), "comment", comment]
                delete = ["ufw", "--force", "delete"] + args[1:]
                rules.append({"add": args, "remove": delete, "owned": True, "applied": False})
            elif firewall["backend"] == "firewalld":
                for permanent in (False, True):
                    prefix = ["firewall-cmd", "--zone=" + firewall["zone"]]
                    if permanent:
                        prefix.append("--permanent")
                    spec = str(port) + "/" + proto
                    existing = self._run(prefix + ["--query-port=" + spec], required=False)
                    if existing.returncode not in (0, 1):
                        raise PortError("Cannot query firewalld rule")
                    rules.append({"add": prefix + ["--add-port=" + spec],
                                  "remove": prefix + ["--remove-port=" + spec],
                                  "owned": existing.returncode == 1, "applied": False})
        return rules

    def _validate(self, entry, stage, changes):
        core = entry["core"]
        folder = "xray/conf" if core == "xray" else "sing-box/conf/config"
        candidate = stage / "core"
        shutil.copytree(self.root / folder, candidate)
        for original, prepared in changes:
            try:
                rel = Path(original).relative_to(self.root / folder)
            except ValueError:
                continue
            destination = candidate / rel
            if prepared is None:
                destination.unlink()
            else:
                shutil.copyfile(prepared, destination)
        binary = self.root / core / core
        if core == "xray":
            self._run([binary, "run", "-test", "-confdir", candidate])
            return []
        merged = stage / "merged.json"
        self._run([binary, "merge", merged, "-C", candidate])
        _json(merged)
        self._run([binary, "check", "-c", merged])
        return [(self.root / "sing-box/conf/config.json", merged)]

    def _policy_managers(self):
        if self.policies is None and (self.state / "policies.sqlite3").exists():
            from .policies import PolicyManager
            self.policies = PolicyManager(self.root, runner=lambda args, input=None, **kw: self.runner.run(args, input=input))
        if self.rate_limiter is None and (self.state / "rates.json").exists():
            from .rate_limits import RateLimiter
            self.rate_limiter = RateLimiter(self.root, runner=self.runner)
        return self.policies, self.rate_limiter

    def _policy_before(self, entry):
        policies, _ = self._policy_managers()
        if policies:
            policies.before_port_change(entry)

    def _subscription_endpoint(self, entry):
        candidates = list((self.root / "nginx").rglob("subscribe.conf"))
        if self.root == Path("/etc/v2ray-agent"):
            candidates += [path for path in (Path("/etc/nginx/conf.d/subscribe.conf"),
                                            Path("/etc/nginx/http.d/subscribe.conf")) if path.exists()]
        if len(candidates) != 1 or candidates[0].is_symlink():
            raise PortError("An unambiguous initialized Nginx subscription configuration is required")
        try:
            config = candidates[0].read_text()
        except OSError:
            raise PortError("Cannot read subscription service configuration") from None
        config = re.sub(r"(?m)#.*$", "", config)
        alias = "alias " + str(self.root / "subscribe") + "/$1/$2;"
        if alias not in re.sub(r"[ \t]+", " ", config) or "^/s/(" not in config:
            raise PortError("Subscription service alias/URL layout is not adapted")
        if not all(name in config for name in ("clashMeta", "default", "clashMetaProfiles", "sing-box", "sing-box_profiles")):
            raise PortError("Subscription service does not expose every expected format")
        listeners = re.findall(r"\blisten\s+([^;]+);", config)
        if not listeners:
            raise PortError("Subscription listener cannot be identified")
        selected = None
        for declaration in listeners:
            tokens = declaration.split()
            address, sep, number = tokens[0].rpartition(":")
            if not sep:
                address, number = "0.0.0.0", tokens[0]
            address = address.strip("[]")
            number = port_input(number)
            _ip(address)
            if number == entry["port"]:
                raise PortError("Target shares the subscription service port")
            if selected is None:
                selected = {"address": address, "port": number, "scheme": "https" if "ssl" in tokens else "http"}
        hostname_match = re.search(r"\bserver_name\s+([^;\s]+)", config)
        hostname = hostname_match.group(1) if hostname_match else "localhost"
        if hostname == "_" and selected["scheme"] == "http":
            hostname = "localhost"
        if not re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
            raise PortError("Custom subscription virtual host is not adapted")
        selected["hostname"] = hostname
        self._run(["systemctl", "is-active", "nginx.service"])
        return selected

    def _verify_subscription_files(self, endpoint, paths):
        public = []
        for path in paths:
            try:
                relative = Path(path).relative_to(self.root / "subscribe")
            except ValueError:
                continue
            if len(relative.parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", piece) for piece in relative.parts):
                raise PortError("Published subscription path is not adapted")
            public.append((Path(path), relative))
        if not public:
            raise PortError("No published subscription files to verify")
        address = endpoint["address"]
        address = "127.0.0.1" if address == "0.0.0.0" else "::1" if address == "::" else address
        if ":" in address:
            address = "[" + address + "]"
        authority = endpoint["hostname"] + ":" + str(endpoint["port"])
        connection = authority + ":" + address + ":" + str(endpoint["port"])
        for path, relative in public:
            url = endpoint["scheme"] + "://" + authority + "/s/" + relative.as_posix()
            result = self._run(["curl", "--silent", "--show-error", "--fail", "--max-time", "8",
                                "--connect-timeout", "3", "--noproxy", "*", "--connect-to", connection,
                                "--url", url])
            if hashlib.sha256(result.stdout.encode()).hexdigest() != _digest(path):
                raise PortError("Subscription download endpoint does not serve the verified published file")

    def _policy_after(self, entry, port, startup=False):
        policies, rates = self._policy_managers()
        if policies:
            if startup:
                policies.after_port_change(entry, port, defer_queue_drain=True)
            else:
                policies.after_port_change(entry, port)
        if rates:
            rates.migrate(entry, port)

    def _stop_before_mapping(self, journal):
        policies, rates = self._policy_managers()
        if policies or rates:
            journal["restart_intent"] = True
            self._save(journal)
            self._run(["systemctl", "stop", journal["entry"]["core"] + ".service"])

    def _read_dependencies(self):
        paths = {path for _, path in _config_files(self.root)}
        merged = self.root / "sing-box/conf/config.json"
        if merged.exists():
            paths.add(merged)
        for name in ("subscribe", "subscribe_local", "subscribe_remote"):
            directory = self.root / name
            if directory.exists():
                paths.update(path for path in directory.rglob("*") if path.is_file())
        paths.update(path for path in self.root.glob("*Salt*") if path.is_file())
        paths.update(path for path in self.root.glob("*salt*") if path.is_file())
        nginx = self.root / "nginx"
        if nginx.exists():
            paths.update(path for path in nginx.rglob("*.conf") if path.is_file())
        result = {}
        for path in paths:
            relative = str(path.relative_to(self.root))
            self._path(relative)
            result[relative] = _digest(path)
        if self.root == Path("/etc/v2ray-agent"):
            for folder in (Path("/etc/nginx/conf.d"), Path("/etc/nginx/http.d")):
                if folder.exists():
                    for path in folder.rglob("*.conf"):
                        result["external:" + str(path)] = _digest(path)
        return result

    def _snapshot(self, original, candidate, txdir):
        original = Path(original)
        relative = str(original.relative_to(self.root))
        self._path(relative)
        item = {"path": relative, "before": _digest(original), "after": _digest(candidate) if candidate else None,
                "candidate": str(Path(candidate).relative_to(txdir)) if candidate else None,
                "mode": 0o600, "uid": os.geteuid(), "gid": os.getegid(), "intent": False}
        if original.exists():
            meta = original.stat()
            item.update(mode=stat.S_IMODE(meta.st_mode), uid=meta.st_uid, gid=meta.st_gid)
            backup = txdir / "backup" / relative
            backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _atomic_bytes(backup, original.read_bytes())
        return item

    def _restore(self, journal, start_services=True):
        txdir = self.state / "transactions" / journal["id"]
        journal["status"] = "recovering"
        self._save(journal)
        try:
            if start_services and (journal.get("restart_intent") or journal.get("policy_intent")):
                # Never synchronously start a required policy unit while holding the
                # common lock: its ExecStartPre also requires that same lock.
                requires = self._run(["systemctl", "show", journal["entry"]["core"] + ".service",
                                      "--property=Requires", "--value"], required=False)
                if "v2ray-agent-port-policy.service" in requires.stdout:
                    active = self._run(["systemctl", "is-active", "v2ray-agent-port-policy.service"], required=False)
                    if active.returncode:
                        start_services = False
            if not start_services and journal.get("policy_intent"):
                active = self._run(["systemctl", "is-active", journal["entry"]["core"] + ".service"], required=False)
                if active.returncode == 0:
                    raise PortError("Deferred startup recovery requires a stopped target core")
            # Old rules are deliberately retained, including all unknown/unowned rules.
            for item in journal["files"]:
                if not item["intent"]:
                    continue
                path = self._path(item["path"])
                current = _digest(path)
                if current not in (item["before"], item["after"]):
                    raise PortError("External edit found during recovery; backup retained")
                if item["before"] is None:
                    if path.exists():
                        path.unlink()
                else:
                    backup = txdir / "backup" / item["path"]
                    if _digest(backup) != item["before"]:
                        raise PortError("Backup verification failed")
                    _atomic_bytes(path, backup.read_bytes(), item["mode"], (item["uid"], item["gid"]))
            if journal.get("policy_intent"):
                if start_services:
                    self._stop_before_mapping(journal)
                self._policy_after(journal["entry"], journal["old_port"], startup=not start_services)
            if journal.get("restart_intent") and start_services:
                self._run(["systemctl", "restart", journal["entry"]["core"] + ".service"])
                # A removed/added forward may not have existed before; verify target instead.
                verify_entry = journal.get("verify_before", journal["entry"])
                self._verify_listener(verify_entry, verify_entry["port"])
            if not start_services and (journal.get("restart_intent") or journal.get("policy_intent")):
                # Unit startup cannot restart a core that Requires this very unit.
                # Keep all rules until the running daemon completes runtime recovery.
                journal["status"] = "restored_awaiting_start"
                self._save(journal)
                return
            for rule in reversed(journal["rules"]):
                if rule["owned"] and rule.get("intent"):
                    result = self._run(rule["remove"], required=False)
                    if result.returncode:
                        # A killed process may not have completed its recorded add intent.
                        if Path(rule["remove"][0]).name == "ufw":
                            status = self._run(["ufw", "status"]).stdout
                            if rule["add"][-1] in status:
                                raise PortError("Owned firewall rule recovery failed")
                        else:
                            query = [x.replace("--remove-port=", "--query-port=") for x in rule["remove"]]
                            if self._run(query, required=False).returncode != 1:
                                raise PortError("Owned firewall rule recovery failed")
            journal["status"] = "rolled_back"
            self._save(journal)
        except Exception as exc:
            journal["status"] = "needs_recovery"
            journal["error"] = type(exc).__name__
            self._save(journal)
            raise PortError("Recovery incomplete; further writes blocked. Backup: " + str(txdir)) from None

    def recover(self, start_services=True):
        results = []
        for path in sorted((self.state / "transactions").glob("*/journal.json")):
            journal = _json(path)
            if journal["status"] not in ("committed", "rolled_back", "aborted"):
                if not journal.get("apply_intent"):
                    journal["status"] = "aborted"
                    self._save(journal)
                else:
                    self._restore(journal, start_services=start_services)
                results.append({"id": journal["id"], "status": journal["status"]})
        return results

    def _transact(self, entry, new_port, operation="change", changes=None, verify_before=None,
                  reverses=None):
        self._mkdir()
        recovery = self.recover()
        if any(item["status"] not in ("committed", "rolled_back", "aborted") for item in recovery):
            raise PortError("Pending runtime recovery must complete before any further port changes")
        if any(item["status"] not in ("committed", "rolled_back", "aborted") for item in self.history()):
            raise PortError("An incomplete transaction blocks further port changes")
        self._service(entry)
        firewall = self._firewall(entry)
        if operation != "additional-delete" and self.check_port(new_port, entry["protocols"], entry["listen"]):
            raise PortError("Requested port conflicts with a configured or running listener")
        self._verify_listener(verify_before or entry, (verify_before or entry)["port"])
        if shutil.disk_usage(self.root).free < 8 * 1024 * 1024:
            raise PortError("Insufficient free disk space for recoverable transaction")
        txid = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:16]
        txdir = self.state / "transactions" / txid
        stage = txdir / "stage"
        stage.mkdir(parents=True, mode=0o700)
        journal = dict(id=txid, created=time.time(), status="preparing", operation=operation,
                       entry=copy.deepcopy(entry), old_port=entry["port"], new_port=new_port,
                       firewall=firewall, files=[], rules=[], restart_intent=False,
                       apply_intent=False, policy_intent=False, reverses=reverses)
        if verify_before:
            journal["verify_before"] = verify_before
        self._save(journal)
        # All fragments are read dependencies, including unchanged users/routing files.
        reads = self._read_dependencies()
        try:
            endpoint = self._subscription_endpoint(entry) if operation == "change" else None
            if changes is None:
                original = self._path(entry["file"])
                doc = _json(original)
                patched = copy.deepcopy(doc)
                field = "port" if entry["core"] == "xray" else "listen_port"
                patched["inbounds"][entry["index"]][field] = new_port
                check = copy.deepcopy(patched)
                check["inbounds"][entry["index"]][field] = doc["inbounds"][entry["index"]][field]
                if check != doc:
                    raise PortError("Candidate changed fields beyond the target listener port")
                candidate = stage / "inbound.json"
                _write_json(candidate, patched)
                config_changes = [(original, candidate)]
            else:
                config_changes = []
                for number, (original, value) in enumerate(changes):
                    prepared = stage / ("additional-" + str(number) + ".json") if value is not None else None
                    if prepared:
                        _write_json(prepared, value)
                    config_changes.append((original, prepared))
            config_changes += self._validate(entry, stage, config_changes)
            subscription_changes = []
            if operation == "change":
                stager = self.subscription_stager
                if stager is None:
                    from .subscriptions import stage_subscriptions
                    stager = stage_subscriptions
                subscription_changes = stager(self.root, entry, new_port, stage / "subscriptions")
                if not subscription_changes:
                    raise PortError("No verified subscription output; initialize local subscriptions first")
                self._verify_subscription_files(endpoint, [path for path, _ in subscription_changes])
            changes_all = config_changes + subscription_changes
            paths = [str(Path(path)) for path, _ in changes_all]
            if len(set(paths)) != len(paths):
                raise PortError("Duplicate candidate output path")
            journal["config_count"] = len(config_changes)
            journal["files"] = [self._snapshot(a, b, txdir) for a, b in changes_all]
            journal["rules"] = [] if operation == "additional-delete" else self._rule_plan(entry, new_port, firewall, txid)
            journal["status"] = "validated"
            self._save(journal)
            current_reads = self._read_dependencies()
            if reads != current_reads or any(_digest(self._path(x["path"])) != x["before"] for x in journal["files"]):
                raise PortError("Files changed after preview; refresh and retry")
            if operation != "additional-delete" and self.check_port(new_port, entry["protocols"], entry["listen"]):
                raise PortError("Port became occupied before commit")
            journal["apply_intent"] = True
            journal["status"] = "applying"
            self._save(journal)
            if operation == "change":
                journal["policy_intent"] = True
                self._save(journal)
                self._policy_before(entry)
            for rule in journal["rules"]:
                if rule["owned"]:
                    rule["intent"] = True
                    self._save(journal)
                    self._run(rule["add"])
                    rule["applied"] = True
                    self._save(journal)
            for index, item in enumerate(journal["files"]):
                if index == journal["config_count"]:
                    self._activate(journal)
                item["intent"] = True
                self._save(journal)
                destination = self._path(item["path"])
                if _digest(destination) != item["before"]:
                    raise PortError("External edit detected during publication")
                if item["candidate"] is None:
                    destination.unlink()
                else:
                    candidate = txdir / item["candidate"]
                    if _digest(candidate) != item["after"]:
                        raise PortError("Candidate changed after validation")
                    _atomic_bytes(destination, candidate.read_bytes(), item["mode"], (item["uid"], item["gid"]))
            if not subscription_changes:
                self._activate(journal)
            if any(_digest(self._path(x["path"])) != x["after"] for x in journal["files"]):
                raise PortError("Published file digest verification failed")
            if endpoint:
                self._verify_subscription_files(endpoint, [path for path, _ in subscription_changes])
            journal["status"] = "committed"
            journal["note"] = "Unknown/preexisting old firewall rules retained; public reachability unverified"
            self._save(journal)
            return {"status": "committed", "transaction_id": txid, "old_port": entry["port"],
                    "new_port": new_port, "firewall": firewall,
                    "public_verification": "unverified"}
        except Exception as exc:
            if journal["apply_intent"]:
                self._restore(journal)
            else:
                journal["status"] = "aborted"
                journal["error"] = type(exc).__name__
                self._save(journal)
            if isinstance(exc, PortError):
                raise
            outcome = "was recovered" if journal["status"] in ("rolled_back", "aborted") else "requires runtime recovery"
            raise PortError("Transaction failed and " + outcome + ": " + type(exc).__name__) from None

    def _activate(self, journal):
        if journal["policy_intent"]:
            self._stop_before_mapping(journal)
            self._policy_after(journal["entry"], journal["new_port"])
        journal["restart_intent"] = True
        self._save(journal)
        self._run(["systemctl", "restart", journal["entry"]["core"] + ".service"])
        if journal["operation"] == "additional-delete":
            self._verify_listener(journal["verify_before"], journal["verify_before"]["port"])
            for item in _ss_records(self._run(["ss", "-H", "-lntup"]).stdout):
                if item["port"] == journal["old_port"] and item["protocol"] in journal["entry"]["protocols"]:
                    raise PortError("Deleted additional listener is still active")
        else:
            self._verify_listener(journal["entry"], journal["new_port"])
        journal["status"] = "service_verified"
        self._save(journal)

    def change(self, port_id, new_port):
        new_port = port_input(new_port)
        self.recover()
        entry = self._entry(port_id)
        if not entry["supported"]:
            raise PortError(entry["reason"])
        if new_port == entry["port"]:
            return {"status": "unchanged", "old_port": new_port, "new_port": new_port}
        return self._transact(entry, new_port)

    def rollback(self):
        self.recover()
        committed = [x for x in self.history() if x["status"] == "committed" and x["operation"] == "change"]
        if not committed:
            raise PortError("No committed port change to roll back")
        last = committed[-1]
        if last.get("reverses"):
            raise PortError("Latest port change is already a rollback")
        entry = self._entry(last["entry"]["port_id"])
        if not entry["supported"] or entry["port"] != last["new_port"]:
            raise PortError("Current entry no longer matches the last change")
        # Rebase the reverse change onto current accounts, subscriptions and current ledger.
        return self._transact(entry, last["old_port"], reverses=last["id"])

    def additional_list(self):
        return [x for x in self.list() if x["kind"] == "additional"]

    def _unmanaged_forward(self, target):
        policies, rates = self._policy_managers()
        if policies:
            for item in policies.status([target]):
                if item.get("port_id") == target["port_id"] and item.get("managed", True):
                    raise PortError("Forwarding a policy-managed entry would bypass accounting")
        if rates and (self.state / "rates.json").exists():
            data = _json(self.state / "rates.json")
            if target["port_id"] in json.dumps(data):
                raise PortError("Forwarding a rate-managed entry is not supported")

    def additional_add(self, target_id, new_port):
        new_port = port_input(new_port)
        self.recover()
        target = self._entry(target_id)
        if target["core"] != "xray" or target["kind"] not in ("shared-tls", "xray-reality", "xray-xhttp") or target["protocols"] != ["tcp"]:
            raise PortError("Only an existing direct Xray TCP entry supports an additional forward")
        if Path(target["file"]).name not in ("02_VLESS_TCP_inbounds.json", "02_trojan_TCP_inbounds.json", "07_VLESS_vision_reality_inbounds.json", "12_VLESS_XHTTP_inbounds.json"):
            raise PortError("Custom forwarding target is not adapted")
        if target["listen"] not in ("::", "0.0.0.0", "*"):
            raise PortError("Additional forward requires a wildcard target listener")
        self._unmanaged_forward(target)
        path = self.root / "xray/conf" / ("02_dokodemodoor_inbounds_" + str(new_port) + ".json")
        if path.exists():
            raise PortError("Additional configuration already exists")
        tag = "dokodemo-door-newPort-" + str(new_port)
        doc = {"inbounds": [{"listen": "0.0.0.0", "port": new_port, "protocol": "dokodemo-door",
                              "settings": {"address": "127.0.0.1", "port": target["port"],
                                           "network": "tcp", "followRedirect": False}, "tag": tag}]}
        entry = {**target, "listen": "0.0.0.0", "kind": "additional"}
        changes = [(path, doc)]
        hy2 = [x for x in self.list() if x["kind"] == "sing-box-hysteria2"]
        if len(hy2) > 1 or (hy2 and not hy2[0]["supported"]):
            raise PortError("Hysteria companion target is ambiguous or has forwarding dependencies")
        if hy2:
            companion = hy2[0]
            self._unmanaged_forward(companion)
            if companion["listen"] not in ("::", "0.0.0.0", "*"):
                raise PortError("Hysteria companion must have a wildcard listener")
            self._verify_listener(companion, companion["port"])
            udp_path = path.with_name("02_dokodemodoor_inbounds_hysteria_" + str(new_port) + ".json")
            if udp_path.exists():
                raise PortError("Additional UDP companion already exists")
            udp_doc = copy.deepcopy(doc)
            udp_doc["inbounds"][0]["settings"].update(port=companion["port"], network="udp")
            udp_doc["inbounds"][0]["tag"] = "dokodemo-door-newPort-hysteria-" + str(new_port)
            entry["protocols"] = ["tcp", "udp"]
            changes.append((udp_path, udp_doc))
        return self._transact(entry, new_port, operation="additional-add", changes=changes, verify_before=target)

    def additional_delete(self, port_id):
        self.recover()
        entry = self._entry(port_id)
        if entry["kind"] != "additional" or entry.get("default"):
            raise PortError("Default or unrecognized forward cannot be deleted")
        targets = [x for x in self.list() if x["core"] == "xray" and x["port"] == entry.get("target_port") and x["kind"] != "additional"]
        if len(targets) != 1:
            raise PortError("Forward target is missing or ambiguous")
        # Existing published references to extra ports must not be left dangling.
        for directory in (self.root / "subscribe_local", self.root / "subscribe"):
            if directory.exists():
                for path in directory.rglob("*"):
                    if path.is_file():
                        try:
                            text = path.read_text()
                        except (UnicodeError, OSError):
                            raise PortError("Cannot inspect existing subscription references") from None
                        compact = "".join(text.split())
                        if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
                            try:
                                text += "\n" + base64.b64decode(compact + "="*((-len(compact)) % 4), validate=True).decode()
                            except (ValueError, UnicodeError):
                                pass
                        if re.search(r"(?<!\d)"+str(entry["port"])+r"(?!\d)", text):
                            raise PortError("Subscription may reference this additional port; deletion blocked")
        changes = [(self._path(entry["file"]), None)]
        # Preserve the legacy paired TCP + Hysteria UDP deletion behavior.
        if entry["protocols"] == ["tcp"]:
            companions = [x for x in self.additional_list() if x["port"] == entry["port"]
                          and x["protocols"] == ["udp"]
                          and Path(x["file"]).name == "02_dokodemodoor_inbounds_hysteria_"+str(entry["port"])+".json"]
            if len(companions) > 1:
                raise PortError("Ambiguous additional UDP companion")
            if companions:
                changes.append((self._path(companions[0]["file"]), None))
                entry = {**entry, "protocols": ["tcp", "udp"]}
        return self._transact(entry, entry["port"], operation="additional-delete",
                              changes=changes, verify_before=targets[0])
