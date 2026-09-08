"""Stage existing subscription outputs without reinitialising accounts or URLs.

The installed script owns the subscription templates.  We deliberately adapt its
already-published generation, retaining cached remote nodes and provider URLs.
Every affected account must be present in all applicable formats before any
candidate is written.  This module never writes to an installed source file.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


class SubscriptionError(ValueError):
    """A subscription cannot safely be associated with the selected entry."""


def _fail(message):
    raise SubscriptionError(message)


def _json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("JSON 订阅含重复字段")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (ValueError, TypeError):
        _fail("JSON 配置或订阅格式无效")


def _yaml_module():
    try:
        import yaml
    except ImportError:
        _fail("缺少 python3-yaml；请先安装后重试")
    return yaml


def _yaml(text):
    yaml = _yaml_module()

    class Loader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, int, float, bool)) or key in result:
                _fail("YAML 订阅含重复或未知字段")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result
    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return yaml.load(text, Loader=Loader)
    except (yaml.YAMLError, TypeError, RecursionError):
        _fail("YAML 订阅格式无效")


def _read(root, relative):
    relative = Path(relative)
    path = root / relative
    if relative.is_absolute() or not path.resolve().is_relative_to(root.resolve()):
        _fail("订阅或配置路径越界")
    if path.is_symlink() or not path.is_file():
        _fail("订阅尚未完整初始化或文件缺失；请先重新生成全部订阅")
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _fail("无法读取订阅或配置文件")
    if not value.strip():
        _fail("订阅或配置为空；请先重新生成全部订阅")
    return path, value


def _accounts(root, entry):
    _, text = _read(root, entry.get("source_file", entry["file"]))
    data = _json(text)
    try:
        inbound = data["inbounds"][entry.get("source_index", entry["index"])]
        kind = inbound.get("protocol", inbound.get("type"))
        if kind not in ("vless", "hysteria2", "tuic"):
            _fail("目标协议未适配订阅同步")
        users = inbound["settings"]["clients"] if entry["core"] == "xray" else inbound["users"]
        transport = (inbound.get("streamSettings", {}).get("network", "tcp")
                     if entry["core"] == "xray" else inbound.get("transport", {}).get("type", "tcp"))
        if transport == "raw":
            transport = "tcp"
        accounts = []
        labels = set()
        for user in users:
            label = user.get("email", user.get("name"))
            if not isinstance(label, str) or not label or label in labels:
                _fail("目标账户名称缺失或重复，无法核对完整订阅")
            bundle = label.split("-", 1)[0]
            if bundle in ("", ".", "..") or "/" in bundle or "\\" in bundle:
                _fail("目标账户订阅文件名无法安全识别")
            credentials = ((user.get("id", user.get("uuid")),) if kind == "vless" else
                           (user.get("password"),) if kind == "hysteria2" else
                           (user.get("uuid"), user.get("password")))
            if any(not isinstance(v, str) or not v for v in credentials):
                _fail("目标账户凭据字段缺失，无法验证订阅")
            accounts.append({"label": label, "bundle": bundle, "type": kind,
                             "credentials": credentials, "transport": transport})
            labels.add(label)
    except (KeyError, IndexError, TypeError, AttributeError):
        _fail("无法读取目标入口的完整账户集合")
    if not accounts:
        _fail("目标入口没有可验证的账户")
    return accounts


def _b64decode(text):
    try:
        stripped = re.sub(r"\s+", "", text)
        return base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        _fail("默认订阅 Base64 格式无效")


def _uri(line):
    try:
        parsed = urlsplit(line)
        if parsed.scheme == "vmess":
            node = _json(_b64decode(line.split("://", 1)[1]))
            if not isinstance(node, dict) or not all(key in node for key in ("id", "port", "add")):
                _fail("VMess 订阅格式无效")
            return None
        if (parsed.scheme not in ("vless", "trojan", "hysteria2", "hy2", "tuic", "naive+https", "anytls", "ss")
                or not parsed.hostname or parsed.port is None):
            _fail("默认订阅含未适配或无效的节点链接")
        if not 1 <= parsed.port <= 65535:
            _fail("默认订阅节点端口无效")
        scheme = "hysteria2" if parsed.scheme == "hy2" else parsed.scheme
        credentials = ((unquote(parsed.username or ""), unquote(parsed.password or ""))
                       if scheme == "tuic" else (unquote(parsed.username or ""),))
        return {"label": unquote(parsed.fragment), "type": scheme,
                "server": parsed.hostname.lower(), "credentials": credentials,
                "port": parsed.port, "query": parse_qs(parsed.query), "parsed": parsed}
    except (ValueError, TypeError, AttributeError):
        _fail("默认订阅节点链接格式无效")


def _identity(node):
    return (node["label"], node["type"], node["server"], node["credentials"])


def _account_for(node, accounts):
    if node is None:
        return None
    found = []
    for account in accounts:
        label_matches = node["label"] == account["label"]
        if account["transport"] == "xhttp":
            label_matches = bool(re.fullmatch(re.escape(account["label"]) + r"[0-9]*", node["label"]))
        if label_matches and node["type"] == account["type"]:
            found.append(account)
    if len(found) > 1:
        _fail("订阅节点与多个账户关联，无法安全迁移")
    if not found:
        return None
    if node["credentials"] != found[0]["credentials"]:
        _fail("订阅凭据与服务端账户不一致；请先重新生成全部订阅")
    return found[0]


def _rewrite_uri(line, new_port):
    # Edit only the numeric authority port, retaining URL escaping and query order.
    authority_start = line.index("://") + 3
    authority_end = min((i for i in (line.find(c, authority_start) for c in "/?#") if i >= 0), default=len(line))
    authority = line[authority_start:authority_end]
    prefix, separator, old_port = authority.rpartition(":")
    if not separator or not old_port.isdecimal():
        _fail("节点端口位置无法安全识别")
    return line[:authority_start] + prefix + ":" + str(new_port) + line[authority_end:]


def _stage_uris(text, accounts, old_port, new_port, expected=None):
    identities, seen_accounts, selected = set(), set(), {}
    lines = text.splitlines(keepends=True)
    for index, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        node = _uri(line)
        account = _account_for(node, accounts)
        if account is None:
            continue
        identity = _identity(node)
        if expected is not None and identity not in expected:
            _fail("公开订阅出现不属于当前本地节点的目标账户条目")
        if identity in identities or node["port"] != old_port:
            _fail("默认订阅目标节点缺失、重复或端口不一致")
        if node["type"] == "vless":
            query = node["query"]
            if (query.get("security") != ["reality"] or
                    query.get("type", ["tcp"]) != [account["transport"]]):
                _fail("默认订阅目标传输方式与配置不一致")
        if node["type"] == "hysteria2" and "mport" in node["query"]:
            _fail("目标订阅包含端口跳跃，不能直接修改")
        if expected is not None and line != expected[identity]:
            _fail("公开订阅目标节点与本地输入不一致")
        identities.add(identity)
        seen_accounts.add(account["label"])
        selected[identity] = line
        lines[index] = raw.replace(line, _rewrite_uri(line, new_port), 1)
    if seen_accounts != {a["label"] for a in accounts} or (expected is not None and identities != set(expected)):
        _fail("默认订阅未覆盖目标入口的全部账户")
    return "".join(lines), selected


def _structured_node(node, fmt):
    if not isinstance(node, dict):
        _fail("订阅节点结构无效")
    kind = node.get("type")
    if kind not in ("vless", "hysteria2", "tuic"):
        return None
    credentials = ((node.get("uuid"),) if kind == "vless" else
                   (node.get("password"),) if kind == "hysteria2" else
                   (node.get("uuid"), node.get("password")))
    server, label = node.get("server"), node.get("name" if fmt == "clash" else "tag")
    if not isinstance(server, str) or not isinstance(label, str):
        _fail("订阅节点缺少名称或服务器字段")
    return {"type": kind, "label": label, "server": server.lower().strip("[]"),
            "credentials": credentials, "port": node.get("port" if fmt == "clash" else "server_port")}


def _stage_nodes(nodes, fmt, accounts, old_port, new_port, expected_ids, expected_nodes=None):
    if not isinstance(nodes, list):
        _fail("订阅节点列表缺失")
    selected = {}
    result = copy.deepcopy(nodes)
    port_field = "port" if fmt == "clash" else "server_port"
    for index, original in enumerate(nodes):
        node = _structured_node(original, fmt)
        account = _account_for(node, accounts)
        if account is None:
            continue
        identity = _identity(node)
        if identity not in expected_ids or identity in selected or type(node["port"]) is not int or node["port"] != old_port:
            _fail("订阅目标节点集合、端口或账户归属不一致")
        if "ports" in original or "server_ports" in original:
            _fail("目标订阅包含端口跳跃，不能直接修改")
        if node["type"] == "vless":
            if fmt == "clash":
                transport = original.get("network", "tcp")
                reality = isinstance(original.get("reality-opts"), dict)
            else:
                transport = original.get("transport", {}).get("type", "tcp")
                reality = original.get("tls", {}).get("reality", {}).get("enabled") is True
            if transport != account["transport"] or not reality:
                _fail("订阅目标传输方式与服务端不一致")
        if expected_nodes is not None and original != expected_nodes[identity]:
            _fail("公开订阅目标节点与本地输入不一致")
        selected[identity] = original
        result[index][port_field] = new_port
    if set(selected) != set(expected_ids):
        _fail("订阅格式未覆盖目标入口的全部账户和节点")
    return result, selected


def stage_subscriptions(root: Path, entry: dict, new_port: int, stage_dir: Path) -> list[tuple[Path, Path]]:
    """Validate/stage local and public outputs; return (original, candidate) pairs.

    ``root`` is the installed /etc/v2ray-agent directory. The caller owns locking,
    backups, source digest validation, publication and rollback. Missing files
    abort instead of silently publishing a subset or downloading new templates.
    """
    root, stage_dir = Path(root), Path(stage_dir)
    if type(new_port) is not int or not 1 <= new_port <= 65535:
        _fail("新端口必须为 1–65535 的整数")
    if new_port == entry["port"]:
        return []
    _yaml_module()
    accounts = _accounts(root, entry)
    _, salt_text = _read(root, "subscribe_local/subscribeSalt")
    salt = salt_text.rstrip("\n")  # Match Bash command substitution and legacy MD5 input.
    if not salt or "\n" in salt or "\r" in salt:
        _fail("已有订阅 Salt 格式无效")
    planned = []
    for bundle in sorted({a["bundle"] for a in accounts}):
        group = [a for a in accounts if a["bundle"] == bundle]
        digest = hashlib.md5((bundle + salt + "\n").encode()).hexdigest()
        paths = {
            "local_uri": f"subscribe_local/default/{bundle}",
            "public_uri": f"subscribe/default/{digest}",
            "local_clash": f"subscribe_local/clashMeta/{bundle}",
            "public_clash": f"subscribe/clashMeta/{digest}",
            "full_clash": f"subscribe/clashMetaProfiles/{digest}",
            "local_sing": f"subscribe_local/sing-box/{bundle}",
            "nodes_sing": f"subscribe/sing-box_profiles/{digest}",
            "full_sing": f"subscribe/sing-box/{digest}",
        }
        # XHTTP has no upstream sing-box output. Older installations can have
        # none of these files; a partial existing generation still must abort.
        sing_keys = ("local_sing", "nodes_sing", "full_sing")
        omit_sing = all(a["transport"] == "xhttp" for a in group) and not any(
            (root / paths[key]).exists() or (root / paths[key]).is_symlink() for key in sing_keys)
        if omit_sing:
            for key in sing_keys:
                del paths[key]
        sources = {key: _read(root, value) for key, value in paths.items()}
        outputs = {key: value[1] for key, value in sources.items()}
        outputs["local_uri"], uri_nodes = _stage_uris(outputs["local_uri"], group, entry["port"], new_port)
        public_uri, _ = _stage_uris(_b64decode(outputs["public_uri"]), group, entry["port"], new_port, uri_nodes)
        outputs["public_uri"] = base64.b64encode(public_uri.encode()).decode() + "\n"
        local_clash = _yaml(outputs["local_clash"])
        local_clash, clash_nodes = _stage_nodes(local_clash, "clash", group, entry["port"], new_port, uri_nodes)
        outputs["local_clash"] = _yaml_module().safe_dump(local_clash, allow_unicode=True, sort_keys=False)
        public_clash = _yaml(outputs["public_clash"])
        if not isinstance(public_clash, dict):
            _fail("Clash provider 结构无效")
        public_clash["proxies"], _ = _stage_nodes(public_clash.get("proxies"), "clash", group, entry["port"], new_port, uri_nodes, clash_nodes)
        outputs["public_clash"] = _yaml_module().safe_dump(public_clash, allow_unicode=True, sort_keys=False)
        full_clash = _yaml(outputs["full_clash"])
        if not isinstance(full_clash, dict):
            _fail("Clash 完整配置结构无效")
        providers = full_clash.get("proxy-providers", {})
        if not isinstance(providers, dict):
            _fail("Clash provider 引用结构无效")
        expected_path = "/s/clashMeta/" + digest
        references = []
        for name, provider in providers.items():
            if isinstance(provider, dict) and isinstance(provider.get("url"), str):
                parsed = urlsplit(provider["url"])
                if parsed.path == expected_path and parsed.scheme in ("http", "https") and parsed.hostname:
                    references.append(name)
        has_inline = "proxies" in full_clash
        if has_inline:
            inline = full_clash["proxies"]
            inline_ids = {_identity(n) for n in (_structured_node(v, "clash") for v in inline)
                          if n is not None and _account_for(n, group) is not None}
            if inline_ids:
                full_clash["proxies"], _ = _stage_nodes(inline, "clash", group, entry["port"], new_port, uri_nodes, clash_nodes)
                outputs["full_clash"] = _yaml_module().safe_dump(full_clash, allow_unicode=True, sort_keys=False)
        else:
            inline_ids = set()
        if not references and not inline_ids:
            _fail("Clash 完整配置缺少已有本地 provider 引用或目标节点")
        if references:
            groups = full_clash.get("proxy-groups", [])
            if not isinstance(groups, list) or not any(isinstance(g, dict) and any(ref in g.get("use", []) for ref in references) for g in groups):
                _fail("Clash 完整配置未使用已有本地 provider")
        # The upstream generator intentionally has no sing-box XHTTP outbound.
        sing_group = [a for a in group if a["transport"] != "xhttp"]
        sing_ids = {identity for identity in uri_nodes if any(identity[0] == a["label"] for a in sing_group)}
        if not omit_sing:
            local_sing = _json(outputs["local_sing"])
            changed_sing, sing_nodes = _stage_nodes(local_sing, "sing", group, entry["port"], new_port, sing_ids)
            if sing_ids:
                outputs["local_sing"] = json.dumps(changed_sing, ensure_ascii=False, indent=2) + "\n"
            for key in ("nodes_sing", "full_sing"):
                data = _json(outputs[key])
                if key == "full_sing" and not isinstance(data, dict):
                    _fail("sing-box 完整配置结构无效")
                nodes = data.get("outbounds") if key == "full_sing" else data
                changed, _ = _stage_nodes(nodes, "sing", group, entry["port"], new_port, sing_ids, sing_nodes)
                if sing_ids:
                    if key == "full_sing":
                        data["outbounds"] = changed
                    else:
                        data = changed
                    outputs[key] = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        planned.extend((sources[key][0], outputs[key]) for key in paths)
    # Finish all validation before writing even the first candidate.
    destination = stage_dir / "subscriptions"
    for forbidden in (root / "subscribe", root / "subscribe_local", root / "xray" / "conf", root / "sing-box" / "conf"):
        if destination.resolve().is_relative_to(forbidden.resolve()):
            _fail("订阅候选目录不能位于正式服务目录")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    pairs = []
    for index, (original, content) in enumerate(planned):
        candidate = destination / str(index)
        if candidate.exists() or candidate.is_symlink():
            _fail("订阅候选目录非空，请使用新的事务目录")
        with candidate.open("x", encoding="utf-8") as handle:
            handle.write(content)
        candidate.chmod(0o600)
        pairs.append((original, candidate))
    return pairs
