"""Actual installer core workflows; archives/locks are real, cores and services inert."""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
import zipfile

from test_port_installer import function
from test_port_policies import FakeRunner
from port_manager import __main__ as cli
from port_manager.core import Manager
from port_manager.policies import PolicyManager

REPO = Path(__file__).resolve().parents[1]
INSTALLERS = ("install.sh", "shell/install_en.sh")
HELPERS = ("agentWriteLock", "agentWriteUnlock", "agentConfigDigest", "read", "agentPreparationDigest",
           "agentPrepare", "agentManagedRecoveryClear", "agentRecoverBeforeLegacy", "readInstallType",
           "agentCoreDirectory", "agentCoreDigest", "agentCoreServiceState", "agentFetchCoreReleases",
           "agentChooseCoreVersion", "agentExtractCore", "agentPrepareCore", "agentPublishCore",
           "agentInstallCore", "installSingBox", "updateSingBox", "installXray", "updateXray",
           "agentGeoDigest", "agentGeoRecoveryClear", "agentDownloadGeo", "agentPublishGeo", "updateGeoSite",
           "initSingBoxLocalDNSConfig", "migrateSingBoxLegacyOutboundConfig", "initSingBoxHTTPClientConfig",
           "agentBuildSingBoxCandidate", "singBoxMergeConfig")
TAGS = {"xray": ("v26.3.27", "v26.3.28-pre.1", "v26.3.1"),
        "sing-box": ("v1.14.0", "v1.14.1-alpha.1", "v1.13.0")}

# This executable is packaged in actual ZIP/tar.gz fixtures and also used as the old core.
BINARY = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
CORE = @CORE@
VERSION = @VERSION@
root = Path(os.environ["CORE_TEST_ROOT"])
args = sys.argv[1:]
stage = "version" if args == ["version"] else ("merge" if args[0] == "merge" else
        ("asset-check" if CORE == "xray" and "-config" in args else "config-check"))
try:
    os.fstat(9)
    closed = False
except OSError:
    closed = True
with (root / "binary.calls").open("a") as log:
    log.write(json.dumps({"core": CORE, "stage": stage, "args": args, "closed": closed}) + "\n")
assert closed, "candidate inherited shared lock descriptor"
if stage == os.environ.get("CORE_PAUSE"):
    (root / "paused").write_text(stage)
    if not sys.stdin.readline():
        sys.exit(92)
if stage == os.environ.get("CORE_INVALID"):
    sys.exit(23)
if stage == "version":
    version = "0.0.0" if os.environ.get("CORE_VERSION_MISMATCH") else VERSION[1:]
    print(("Xray " if CORE == "xray" else "sing-box version ") + version)
elif CORE == "xray":
    assets = Path(os.environ["xray.location.asset"])
    assert str(assets) == os.environ["XRAY_LOCATION_ASSET"]
    assert assets.name == "candidate" or assets.name.startswith(".geo-update.")
    assert (assets / "geosite.dat").read_text() == "new-geosite.dat"
    assert (assets / "geoip.dat").read_text() == "new-geoip.dat"
    if stage == "asset-check":
        assert len(json.loads(Path(args[-1]).read_text())["routing"]["rules"]) == 2
    else:
        assert args[-1] == str(root / "xray/conf")
elif stage == "merge":
    fragments = Path(args[args.index("-C") + 1])
    assert ".core-update." in str(fragments) or ".merged-stage." in str(fragments)
    assert fragments != root / "sing-box/conf/config"
    def merge(left, right):
        for key, value in right.items():
            if key in left and isinstance(value, list) and isinstance(left[key], list):
                left[key] += value
            elif key in left and isinstance(value, dict) and isinstance(left[key], dict):
                merge(left[key], value)
            else:
                left[key] = value
    output = {}
    for path in sorted(fragments.glob("*.json")):
        merge(output, json.loads(path.read_text()))
    Path(args[1]).write_text(json.dumps(output))
else:
    document = json.loads(Path(args[args.index("-c") + 1]).read_text())
    assert isinstance(document, dict)
'''

CURL = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
from pathlib import Path
root = Path(os.environ["CORE_TEST_ROOT"])
args = sys.argv[1:]
url = next(value for value in args if value.startswith("https://"))
destination = Path(args[args.index("-o") + 1])
if "Loyalsoldier" in url:
    stage = "geo-metadata" if url.endswith("/latest") else url.rsplit("/", 1)[1]
    data = json.dumps({"tag_name":"202609080001"}).encode()
    if stage.endswith(".sha256sum"):
        name = stage.removesuffix(".sha256sum")
        data = (hashlib.sha256(("new-" + name).encode()).hexdigest() + "  " + name + "\n").encode()
    elif stage != "geo-metadata":
        data = ("new-" + stage).encode()
else:
    core = "xray" if "XTLS" in url else "sing-box"
    releases = json.loads((root / ("releases-" + core)).read_text())
    if "/releases/download/" in url:
        stage = "archive"
        tag = url.split("/releases/download/")[1].split("/")[0]
        data = (root / ("archive-" + core + "-" + tag)).read_bytes()
    else:
        stage = "metadata"
        if "per_page" in url:
            selected = releases
        elif "/tags/" in url:
            selected = next(item for item in releases if item["tag_name"] == url.rsplit("/", 1)[1])
        else:
            selected = releases[0]
        data = json.dumps(selected).encode()
        if os.environ.get("CORE_BAD_METADATA"):
            data = os.environ["CORE_BAD_METADATA"].encode()
try:
    os.fstat(9)
    closed = False
except OSError:
    closed = True
with (root / "downloads.jsonl").open("a") as out:
    out.write(json.dumps({"stage":stage, "url":url, "closed":closed,
                         "private":destination.parent.stat().st_mode & 0o777}) + "\n")
assert closed
if stage == os.environ.get("CORE_PAUSE"):
    (root / "paused").write_text(stage)
    if not sys.stdin.readline():
        sys.exit(92)
if stage == os.environ.get("CORE_FAIL"):
    destination.write_text("incomplete")
    sys.exit(22)
destination.write_bytes(data)
'''

SYSTEMCTL = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ["CORE_TEST_ROOT"])
args = sys.argv[1:]
try:
    os.fstat(9)
    sys.exit(91)
except OSError:
    pass
with (root / "service.calls").open("a") as out:
    out.write(json.dumps(args) + "\n")
core = args[-1].removesuffix(".service")
if args[0] == "show":
    print("User=" + os.environ.get("CORE_SERVICE_USER", "root"))
    print("DynamicUser=" + os.environ.get("CORE_DYNAMIC_USER", "no"))
    print("FragmentPath=" + os.environ.get("CORE_FRAGMENT_PATH", str(root / "systemd" / (core + ".service"))))
    binary = str(root / core / core)
    command = binary + (" run -confdir " + str(root / "xray/conf") if core == "xray" else
                        " run -c " + str(root / "sing-box/conf/config.json"))
    print("ExecStart={ path=" + binary + " ; argv[]=" + os.environ.get("CORE_COMMAND", command) +
          " ; ignore_errors=no ; start_time=[] ; stop_time=[] ; pid=1 ; code=(null) ; status=0 }")
    sys.exit(0)
if args[0] == "is-active":
    state = (root / ("state-" + core)).read_text()
    if os.environ.get("CORE_SERVICE_FAIL") == "inactive" and (root / "restarted").exists():
        state = "inactive"
    if "--quiet" not in args:
        print(state)
    sys.exit(0 if state == "active" else 3)
if args[:2] == ["--no-block", "restart"]:
    sys.exit(0)
if args[0] == "restart":
    (root / "restarted").touch()
    if os.environ.get("CORE_SERVICE_FAIL") == "timeout":
        time.sleep(60)
    sys.exit(1 if os.environ.get("CORE_SERVICE_FAIL") == "restart" else 0)
sys.exit(92)
'''

MOVE = r'''#!/usr/bin/env python3
import os, signal, sys
from pathlib import Path
source, destination = map(Path, sys.argv[-2:])
publishing = source.parent.name == "candidate" or (source.name == "config.json" and source.parent.name == "conf")
if publishing and source.name == os.environ.get("CORE_FAIL_MOVE"):
    if os.environ.get("CORE_SIGNAL"):
        os.kill(os.getppid(), int(os.environ["CORE_SIGNAL"]))
    sys.exit(1)
if source.name.endswith(".restore") and os.environ.get("CORE_FAIL_RESTORE"):
    sys.exit(1)
os.execv("/bin/mv", ["mv"] + sys.argv[1:])
'''

TOUCH = r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
if Path(sys.argv[-1]).name == "COMPLETE" and os.environ.get("CORE_FAIL_COMPLETE"):
    sys.exit(1)
os.execv("/bin/touch", ["touch"] + sys.argv[1:])
'''


class CoreFixture:
    def __init__(self, case):
        self.case = case
        self.temp = tempfile.TemporaryDirectory(prefix="port-core-")
        case.addCleanup(self.temp.cleanup)
        self.count = 0

    def archive(self, core, tag, *, duplicate=False, symlink=False, empty=False, extras=False):
        source = BINARY.replace("@CORE@", repr(core)).replace("@VERSION@", repr(tag)).encode()
        if empty:
            source = b""
        buffer = io.BytesIO()
        if core == "xray":
            asset, member = "Xray-linux-64.zip", "xray"
            with zipfile.ZipFile(buffer, "w") as archive:
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o755) << 16
                archive.writestr(info, source)
                if duplicate:
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        archive.writestr(info, source)
                if extras:
                    archive.writestr("../../should-not-extract", "unrelated")
                    archive.writestr("geo-custom.dat", "wrong")
        else:
            folder = "sing-box-" + tag[1:] + "-linux-amd64"
            asset, member = folder + ".tar.gz", folder + "/sing-box"
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                info = tarfile.TarInfo(member)
                info.mode = 0o755
                info.type = tarfile.SYMTYPE if symlink else tarfile.REGTYPE
                info.linkname = "/should-not-follow" if symlink else ""
                info.size = 0 if symlink else len(source)
                archive.addfile(info, None if symlink else io.BytesIO(source))
                if duplicate:
                    archive.addfile(info, None if symlink else io.BytesIO(source))
                if extras:
                    extra = tarfile.TarInfo("../../should-not-extract")
                    extra.size = 9
                    archive.addfile(extra, io.BytesIO(b"unrelated"))
        return asset, buffer.getvalue()

    def replace_archive(self, root, core, tag, **options):
        asset, content = self.archive(core, tag, **options)
        (root / ("archive-" + core + "-" + tag)).write_bytes(content)
        path = root / ("releases-" + core)
        releases = json.loads(path.read_text())
        for release in releases:
            if release["tag_name"] == tag:
                release["assets"] = [{"name":asset, "digest":"sha256:" + hashlib.sha256(content).hexdigest()}]
        path.write_text(json.dumps(releases))

    def make(self, rel, core, installed=True, state="active"):
        self.count += 1
        root = Path(self.temp.name) / str(self.count)
        (root / "bin").mkdir(parents=True)
        (root / "systemd").mkdir()
        for kind in ("xray", "sing-box"):
            directory = root / kind
            config = directory / ("conf" if kind == "xray" else "conf/config")
            config.mkdir(parents=True)
            if installed or core != kind:
                (directory / kind).write_text(BINARY.replace("@CORE@", repr(kind)).replace("@VERSION@", repr(TAGS[kind][2])))
                (directory / kind).chmod(0o755)
                (root / "systemd" / (kind + ".service")).write_text("User=root\nExecStart=" + str(directory / kind) + " run\n")
                (root / ("state-" + kind)).write_text(state if core == kind else "active")
                if kind == "xray":
                    node = {"inbounds":[{"tag":"reality", "protocol":"vless", "listen":"::", "port":443,
                        "settings":{"clients":[{"id":"user-one", "email":"alice"}]},
                        "streamSettings":{"network":"tcp", "security":"reality",
                                          "realitySettings":{"privateKey":"private", "shortIds":["abcd"]}}}]}
                    (config / "07_VLESS_vision_reality_inbounds.json").write_text(json.dumps(node))
                else:
                    node = {"inbounds":[{"type":"hysteria2", "tag":"hy2", "listen":"::", "listen_port":8443,
                        "users":[{"name":"alice", "password":"private"}],
                        "tls":{"enabled":True, "certificate_path":str(root / "tls/test.crt"),
                               "key_path":str(root / "tls/test.key")}}]}
                    (config / "06_hysteria2_inbounds.json").write_text(json.dumps(node))
                    (config / "IPv4_out.json").write_text(json.dumps({"outbounds":[
                        {"type":"direct", "tag":"IPv4_out", "domain_strategy":"prefer_ipv4"}]}))
                    (directory / "conf/config.json").write_text(json.dumps(node))
                    (directory / "conf/config.json").chmod(0o600)
            if kind == "xray":
                for name in ("geosite.dat", "geoip.dat", "geo-custom.dat"):
                    (directory / name).write_text("old-" + name)
                    (directory / name).chmod(0o640)
            releases = []
            for index, tag in enumerate(TAGS[kind]):
                asset, content = self.archive(kind, tag)
                (root / ("archive-" + kind + "-" + tag)).write_bytes(content)
                releases.append({"tag_name":tag, "draft":False, "prerelease":index == 1,
                                 "assets":[{"name":asset, "digest":"sha256:" + hashlib.sha256(content).hexdigest()}]})
            (root / ("releases-" + kind)).write_text(json.dumps(releases))
        (root / "tls").mkdir()
        (root / "tls/test.crt").write_text("synthetic cert")
        (root / "tls/test.key").write_text("synthetic key")
        (root / "install.sh").write_text("# installed installer\n")
        source = (REPO / rel).read_text()
        body = "\n".join(function(source, name) for name in HELPERS)
        body = body.replace("/etc/v2ray-agent", str(root)).replace("/etc/nginx/conf.d", str(root / "nginx"))
        body = body.replace("/etc/systemd/system", str(root / "systemd"))
        (root / "helpers.sh").write_text(body)
        for name, body in (("curl", CURL), ("systemctl", SYSTEMCTL), ("mv", MOVE), ("touch", TOUCH)):
            (root / "bin" / name).write_text(body)
            (root / "bin" / name).chmod(0o700)
        return root

    def start(self, root, core, *, operation=None, pause="", fail="", setup="", answers="", **variables):
        environment = dict(os.environ, CORE_TEST_ROOT=str(root), CORE_PAUSE=pause, CORE_FAIL=fail,
                           PATH=str(root / "bin") + os.pathsep + os.environ["PATH"], **{k:str(v) for k,v in variables.items()})
        script = 'echoContent() { printf "%s\\n" "$2"; }\n. ' + shlex.quote(str(root / "helpers.sh"))
        script += "\nrelease=ubuntu\nxrayCoreCPUVendor=Xray-linux-64\nsingBoxCoreCPUVendor=-linux-amd64\n"
        script += setup + "\nagentWriteLock || exit 1\n" + (operation or f"agentInstallCore {core}")
        proc = subprocess.Popen(["bash", "-c", script], env=environment, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
        self.case.addCleanup(cleanup)
        if answers:
            proc.stdin.write(answers)
            proc.stdin.flush()
        if pause:
            deadline = time.monotonic() + 8
            while not (root / "paused").exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not (root / "paused").exists():
                out, err = proc.communicate(timeout=5)
                self.case.fail(f"Did not reach pause {pause}: {out} {err}")
        return proc

    def finish(self, proc, expected):
        out, err = proc.communicate("continue\n", timeout=12)
        self.case.assertEqual(proc.returncode, expected, out + err)
        return out, err

    @staticmethod
    def snapshot(root, core):
        paths = [root / core / core]
        paths += list((root / core / "conf").rglob("*.json"))
        if core == "xray":
            paths += [root / core / name for name in ("geosite.dat", "geoip.dat", "geo-custom.dat")]
        return {str(path.relative_to(root)):(path.read_bytes(), path.stat().st_mode & 0o777)
                for path in paths if path.is_file() and not any(part.startswith(".merged-stage.") for part in path.parts)}

    @staticmethod
    def services(root):
        path = root / "service.calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class CoreUpdateTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("installer explicitly requires root")
        self.fx = CoreFixture(self)

    def unchanged(self, root, core, before):
        self.assertEqual(self.fx.snapshot(root, core), before)
        self.assertEqual(list((root / core).glob(".core-update.*")), [])

    def test_success_keeps_private_previous_version_and_only_restarts_target(self):
        for rel in INSTALLERS:
            for core in TAGS:
                with self.subTest(rel=rel, core=core):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    self.fx.finish(self.fx.start(root, core), 0)
                    self.assertIn(repr(TAGS[core][0]), (root / core / core).read_text())
                    backups = list((root / core).glob(".core-backup.*"))
                    self.assertEqual(len(backups), 1)
                    self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
                    self.assertEqual((backups[0] / "previous" / core).read_bytes(), before[core + "/" + core][0])
                    self.assertFalse((backups[0] / "KEEP_RECOVERY").exists())
                    self.assertEqual([c for c in self.fx.services(root) if "restart" in c], [["restart",core + ".service"]])
                    if core == "xray":
                        self.assertEqual((root / core / "geo-custom.dat").read_text(), "old-geo-custom.dat")
                        self.assertEqual((root / core / "geosite.dat").read_text(), "new-geosite.dat")
                    else:
                        self.assertEqual((root / core / "conf/config/IPv4_out.json").read_bytes(),
                                         before[core + "/conf/config/IPv4_out.json"][0])
                        out = json.loads((root / core / "conf/config.json").read_text())["outbounds"][0]
                        self.assertEqual(out["domain_resolver"], {"server":"local","strategy":"prefer_ipv4"})
                        self.assertNotIn("domain_strategy", out)

    def test_fresh_install_prepares_files_without_starting_unconfigured_service(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core, installed=False)
                operation = "installXray 1 false" if core == "xray" else "installSingBox 1"
                self.fx.finish(self.fx.start(root, core, operation=operation), 0)
                self.assertTrue((root / core / core).is_file())
                self.assertEqual(self.fx.services(root), [])
                self.assertFalse((root / core / "conf/config.json").exists())

    def test_network_failures_preserve_existing_installation_and_do_not_restart(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for stage in (("metadata","archive","geo-metadata","geosite.dat","geoip.dat") if core == "xray" else ("metadata","archive")):
                    with self.subTest(rel=rel, core=core, stage=stage):
                        root = self.fx.make(rel, core)
                        before = self.fx.snapshot(root, core)
                        self.fx.finish(self.fx.start(root, core, fail=stage), 1)
                        self.unchanged(root, core, before)
                        self.assertFalse(any("restart" in call for call in self.fx.services(root)))

    def test_fresh_xray_embedded_geo_failure_preserves_every_old_geo_file(self):
        for rel in INSTALLERS:
            root = self.fx.make(rel, "xray", installed=False)
            before = self.fx.snapshot(root, "xray")
            self.fx.finish(self.fx.start(root, "xray", operation="installXray 1 false", fail="geoip.dat"), 1)
            self.unchanged(root, "xray", before)
            self.assertFalse((root / "xray/xray").exists())

    def test_actual_update_wrappers_fail_without_deleting_or_stopping_old_core(self):
        for rel in INSTALLERS:
            for core, operation in (("xray","updateXray"), ("xray","updateXray v26.3.1"),
                                    ("xray","installXray 1 true"), ("sing-box","updateSingBox"),
                                    ("sing-box","installSingBox 1")):
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                self.fx.finish(self.fx.start(root, core, operation=operation, answers="y\n", fail="archive"), 1)
                self.unchanged(root, core, before)
                self.assertFalse(any("restart" in call for call in self.fx.services(root)))

    def test_declining_update_does_not_download_or_restart(self):
        for rel in INSTALLERS:
            for core, operation in (("xray","updateXray"), ("sing-box","updateSingBox"),
                                    ("xray","installXray 1 false"), ("sing-box","installSingBox 1")):
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                self.fx.finish(self.fx.start(root, core, operation=operation, answers="n\n"), 0)
                self.unchanged(root, core, before)
                self.assertFalse((root / "downloads.jsonl").exists())
                self.assertEqual(self.fx.services(root), [])

    def test_metadata_and_digest_errors_do_not_execute_candidate(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for mode in ("invalid-json", "tag", "missing-digest", "duplicate-asset", "wrong-digest"):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    document = json.loads((root / ("releases-" + core)).read_text())[0]
                    if mode == "tag":
                        document["tag_name"] = "../../escape"
                    elif mode == "missing-digest":
                        document["assets"][0]["digest"] = None
                    elif mode == "duplicate-asset":
                        document["assets"] *= 2
                    elif mode == "wrong-digest":
                        document["assets"][0]["digest"] = "sha256:" + "0" * 64
                    metadata = "not JSON" if mode == "invalid-json" else json.dumps(document)
                    self.fx.finish(self.fx.start(root, core, CORE_BAD_METADATA=metadata), 1)
                    self.unchanged(root, core, before)
                    self.assertFalse((root / "binary.calls").exists())

    def test_archive_member_type_duplicates_and_empty_files_are_rejected(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for option in ("duplicate", "symlink", "empty"):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    self.fx.replace_archive(root, core, TAGS[core][0], **{option:True})
                    self.fx.finish(self.fx.start(root, core), 1)
                    self.unchanged(root, core, before)
                    self.assertFalse((root / "binary.calls").exists())

    def test_unselected_archive_entries_are_never_extracted(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core)
                self.fx.replace_archive(root, core, TAGS[core][0], extras=True)
                self.fx.finish(self.fx.start(root, core), 0)
                self.assertFalse(list(root.rglob("should-not-extract")))
                if core == "xray":
                    self.assertEqual((root / core / "geo-custom.dat").read_text(), "old-geo-custom.dat")

    def test_bad_archive_bytes_with_matching_digest_fail_closed(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                (root / ("archive-" + core + "-" + TAGS[core][0])).write_bytes(b"broken archive")
                path = root / ("releases-" + core)
                data = json.loads(path.read_text())
                data[0]["assets"][0]["digest"] = "sha256:" + hashlib.sha256(b"broken archive").hexdigest()
                path.write_text(json.dumps(data))
                self.fx.finish(self.fx.start(root, core), 1)
                self.unchanged(root, core, before)

    def test_version_or_native_config_rejection_preserves_old_files(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for stage in (("version","asset-check","config-check") if core == "xray" else ("version","merge","config-check")):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    self.fx.finish(self.fx.start(root, core, CORE_INVALID=stage), 1)
                    self.unchanged(root, core, before)
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                self.fx.finish(self.fx.start(root, core, CORE_VERSION_MISMATCH=1), 1)
                self.unchanged(root, core, before)

    def test_real_policy_renewal_survives_slow_core_geo_and_config_preparation(self):
        for rel in INSTALLERS:
            for core, installed, stage in (("xray",True,"archive"),("xray",False,"geoip.dat"),
                                           ("sing-box",True,"archive"),("sing-box",True,"config-check")):
                with self.subTest(rel=rel, core=core, installed=installed, stage=stage):
                    root = self.fx.make(rel, core, installed=installed)
                    before = self.fx.snapshot(root, core)
                    runner = FakeRunner()
                    now = [dt.datetime(2026,9,8,1,tzinfo=dt.timezone.utc)]
                    policies = PolicyManager(root, runner, clock=lambda:now[0])
                    self.addCleanup(policies.close)
                    manager = Manager(root, runner=runner, policies=policies)
                    entries = manager.list()
                    self.assertTrue(entries)
                    with cli.shared_lock(root, timeout=1):
                        policies.batch_update(entries, {"quota_bytes":1000})
                    app = cli.Application(manager, policies=policies, output=io.StringIO())
                    original_lease = policies._meta("lease_until")
                    proc = self.fx.start(root, core, pause=stage)
                    self.assertEqual(self.fx.snapshot(root, core), before)
                    for second in (11,22,33):
                        with cli.shared_lock(root, timeout=1):
                            pass
                        now[0] = dt.datetime(2026,9,8,1,tzinfo=dt.timezone.utc) + dt.timedelta(seconds=second)
                        for entry in entries:
                            runner.add_usage(entry["port_id"],10,15)
                        self.assertEqual(cli.reconcile_once(app)["recovery"], [])
                        for row in policies.status(entries):
                            self.assertTrue(row["available"], row)
                            self.assertNotIn("daemon_lease_elapsed", row["reasons"])
                    self.assertLess(original_lease, now[0].timestamp())
                    self.assertGreater(policies._meta("lease_until"), now[0].timestamp())
                    self.assertTrue(all(row["used_bytes"] == 75 for row in policies.status(entries)))
                    self.fx.finish(proc, 0)
                    records = [json.loads(line) for line in (root / "downloads.jsonl").read_text().splitlines()]
                    self.assertTrue(all(item["closed"] for item in records))

    def test_concurrent_config_binary_geo_unit_tls_or_script_change_rejects_candidate(self):
        for rel in INSTALLERS:
            for core in TAGS:
                paths = [core + "/" + core, core + ("/conf/added.json" if core == "xray" else "/conf/config/added.json"), "systemd/" + core + ".service",
                         "tls/test.key", "install.sh"]
                if core == "xray":
                    paths += ["xray/geosite.dat"]
                for path in paths:
                    root = self.fx.make(rel, core)
                    proc = self.fx.start(root, core, pause="archive")
                    with cli.shared_lock(root, timeout=1):
                        target = root / path
                        target.write_text(target.read_text() + "\n# concurrent\n" if target.exists() else "{}")
                        changed = target.read_bytes()
                    self.fx.finish(proc, 1)
                    self.assertEqual(target.read_bytes(), changed)
                    self.assertFalse(any("restart" in call for call in self.fx.services(root)))

    def test_concurrent_service_state_change_rejects_preparation(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                proc = self.fx.start(root, core, pause="archive")
                (root / ("state-" + core)).write_text("inactive")
                self.fx.finish(proc, 1)
                self.unchanged(root, core, before)

    def test_existing_inactive_service_remains_inactive(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core, state="inactive")
                self.fx.finish(self.fx.start(root, core), 0)
                self.assertFalse(any("restart" in call for call in self.fx.services(root)))
                self.assertEqual((root / ("state-" + core)).read_text(), "inactive")

    def test_partial_file_publication_and_service_failure_restore_previous_files(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for variables in ({"CORE_FAIL_MOVE":"geoip.dat" if core == "xray" else "config.json"},
                                  {"CORE_SERVICE_FAIL":"restart"}, {"CORE_SERVICE_FAIL":"inactive"},
                                  {"CORE_FAIL_COMPLETE":1}):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    out, _ = self.fx.finish(self.fx.start(root, core, **variables), 1)
                    self.unchanged(root, core, before)
                    self.assertNotIn("files verified and installed", out)

    def test_failed_restore_blocks_both_core_update_and_legacy_entry(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core)
                self.fx.finish(self.fx.start(root, core, CORE_FAIL_MOVE="geoip.dat" if core == "xray" else "config.json",
                                             CORE_FAIL_RESTORE=1), 1)
                stages = list((root / core).glob(".core-update.*"))
                self.assertEqual(len(stages),1)
                self.assertTrue((stages[0] / "KEEP_RECOVERY").is_file())
                self.assertEqual(stages[0].stat().st_mode & 0o777, 0o700)
                downloads = (root / "downloads.jsonl").read_bytes()
                self.fx.finish(self.fx.start(root, core), 1)
                self.assertEqual((root / "downloads.jsonl").read_bytes(), downloads)
                self.fx.finish(self.fx.start(root, core, operation="agentRecoverBeforeLegacy"), 1)
                other = "sing-box" if core == "xray" else "xray"
                self.fx.finish(self.fx.start(root, other), 1)
                self.fx.finish(self.fx.start(root, "xray", operation="updateGeoSite"), 1)
                self.assertEqual((root / "downloads.jsonl").read_bytes(), downloads)

    def test_candidate_only_merge_retains_all_source_bytes_and_modes(self):
        for rel in INSTALLERS:
            root = self.fx.make(rel, "sing-box")
            before = self.fx.snapshot(root, "sing-box")
            proc = self.fx.start(root, "sing-box", operation="singBoxMergeConfig", pause="config-check")
            self.assertEqual(self.fx.snapshot(root, "sing-box"), before)
            with cli.shared_lock(root, timeout=1):
                pass
            self.fx.finish(proc, 0)
            after = self.fx.snapshot(root, "sing-box")
            for path, contents in before.items():
                if path != "sing-box/conf/config.json":
                    self.assertEqual(after[path], contents)
            self.assertFalse((root / "sing-box/conf/config/dns.json").exists())
            self.assertFalse((root / "sing-box/conf/config/00_http_clients.json").exists())
            candidate = json.loads((root / "sing-box/conf/config.json").read_text())
            self.assertEqual(candidate["dns"]["servers"], [{"tag":"local", "type":"local"}])
            self.assertIn("domain_resolver", candidate["outbounds"][0])
            self.assertEqual(list((root / "sing-box/conf").glob(".merged-stage.*")), [])

    def test_merge_or_check_failure_keeps_fragments_and_active_merged_config(self):
        for rel in INSTALLERS:
            for stage in ("merge", "config-check"):
                root = self.fx.make(rel, "sing-box")
                before = self.fx.snapshot(root, "sing-box")
                self.fx.finish(self.fx.start(root, "sing-box", operation="singBoxMergeConfig",
                                             CORE_INVALID=stage), 1)
                self.unchanged(root, "sing-box", before)
                self.assertEqual(list((root / "sing-box/conf").glob(".merged-stage.*")), [])

    def test_malformed_or_ambiguous_legacy_fragments_fail_without_rewriting_sources(self):
        cases = (("dns.json", "not JSON"), ("dns.json", '{"dns":{"servers":"bad"}}'),
                 ("extra.json", '{}\n{}'), ("extra.json", '[]'),
                 ("IPv4_out.json", '{"outbounds":[{"type":"direct","domain_strategy":"prefer_ipv4",'
                                  '"domain_resolver":{"server":"custom"}}]}'))
        for rel in INSTALLERS:
            for name, document in cases:
                root = self.fx.make(rel, "sing-box")
                (root / "sing-box/conf/config" / name).write_text(document)
                before = self.fx.snapshot(root, "sing-box")
                self.fx.finish(self.fx.start(root, "sing-box", operation="singBoxMergeConfig"), 1)
                self.unchanged(root, "sing-box", before)

    def test_merge_preserves_explicit_modern_dns_and_http_client_settings(self):
        for rel in INSTALLERS:
            root = self.fx.make(rel, "sing-box")
            dns = {"dns":{"servers":[{"type":"https","tag":"custom","server":"dns.example"}]}}
            clients = {"http_clients":[{"tag":"custom-http","detour":"custom-out"}],
                       "route":{"default_http_client":"custom-http"}}
            (root / "sing-box/conf/config/dns.json").write_text(json.dumps(dns))
            (root / "sing-box/conf/config/00_http_clients.json").write_text(json.dumps(clients))
            self.fx.finish(self.fx.start(root, "sing-box", operation="singBoxMergeConfig"), 0)
            document = json.loads((root / "sing-box/conf/config.json").read_text())
            self.assertEqual(document["http_clients"], clients["http_clients"])
            self.assertEqual(document["route"], clients["route"])
            self.assertEqual(document["dns"]["servers"][0], dns["dns"]["servers"][0])
            self.assertEqual(json.loads((root / "sing-box/conf/config/dns.json").read_text()), dns)

    def test_merge_detects_concurrent_source_or_binary_change(self):
        for rel in INSTALLERS:
            for path in ("sing-box/conf/config/added.json", "sing-box/sing-box"):
                root = self.fx.make(rel, "sing-box")
                merged = (root / "sing-box/conf/config.json").read_bytes()
                proc = self.fx.start(root, "sing-box", operation="singBoxMergeConfig", pause="config-check")
                with cli.shared_lock(root, timeout=1):
                    target = root / path
                    target.write_text(target.read_text() + "\n# concurrent\n" if target.exists() else "{}")
                    changed = target.read_bytes()
                self.fx.finish(proc, 1)
                self.assertEqual((root / "sing-box/conf/config.json").read_bytes(), merged)
                self.assertEqual(target.read_bytes(), changed)

    def test_existing_merged_only_installation_is_checked_without_fabricated_fragments(self):
        for rel in INSTALLERS:
            root = self.fx.make(rel, "sing-box")
            for path in (root / "sing-box/conf/config").glob("*.json"):
                path.unlink()
            before = (root / "sing-box/conf/config.json").read_bytes()
            self.fx.finish(self.fx.start(root, "sing-box"), 0)
            self.assertEqual((root / "sing-box/conf/config.json").read_bytes(), before)
            self.assertEqual(list((root / "sing-box/conf/config").iterdir()), [])

    def test_new_recovery_marker_during_preparation_prevents_publication(self):
        for rel in INSTALLERS:
            for core in TAGS:
                root = self.fx.make(rel, core)
                before = self.fx.snapshot(root, core)
                proc = self.fx.start(root, core, pause="archive")
                with cli.shared_lock(root, timeout=1):
                    marker = root / "xray/.geo-update.synthetic/KEEP_RECOVERY"
                    marker.parent.mkdir(mode=0o700)
                    marker.write_text("synthetic interrupted Geo publication")
                self.fx.finish(proc, 1)
                self.unchanged(root, core, before)
                self.assertTrue(marker.is_file())

    def test_untrusted_core_directories_and_linked_inputs_fail_closed(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for scenario in ("writable", "binary-link", "fragment-link"):
                    root = self.fx.make(rel, core)
                    if scenario == "writable":
                        (root / core).chmod(0o777)
                    elif scenario == "binary-link":
                        binary = root / core / core
                        saved = root / "saved-binary"
                        binary.rename(saved)
                        binary.symlink_to(saved)
                    else:
                        config = root / core / ("conf" if core == "xray" else "conf/config")
                        (root / "linked-fragment").write_text("{}")
                        (config / "linked.json").symlink_to(root / "linked-fragment")
                    before = self.fx.snapshot(root, core)
                    self.fx.finish(self.fx.start(root, core), 1)
                    self.unchanged(root, core, before)

    def test_publish_signals_compensate_and_sigkill_preserves_recovery(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGKILL):
                    root = self.fx.make(rel, core)
                    before = self.fx.snapshot(root, core)
                    self.fx.finish(self.fx.start(root, core, CORE_FAIL_MOVE="geoip.dat" if core == "xray" else "config.json",
                                                 CORE_SIGNAL=int(signum)), 1)
                    if signum == signal.SIGKILL:
                        self.assertTrue(list((root / core).glob(".core-update.*/KEEP_RECOVERY")))
                        self.fx.finish(self.fx.start(root, core), 1)
                    else:
                        self.unchanged(root, core, before)

    def test_restart_timeout_compensates_without_waiting_indefinitely(self):
        for rel in INSTALLERS:
            root = self.fx.make(rel, "xray")
            before = self.fx.snapshot(root, "xray")
            self.fx.finish(self.fx.start(root, "xray", CORE_SERVICE_FAIL="timeout"), 1)
            self.unchanged(root, "xray", before)

    def test_nonroot_unmanaged_transitional_or_openrc_service_is_refused(self):
        for rel in INSTALLERS:
            for scenario in ("nonroot","missing-unit","activating","failed","alpine","dynamic","custom-unit","custom-command"):
                root = self.fx.make(rel, "xray", state=scenario if scenario in ("activating","failed") else "active")
                before = self.fx.snapshot(root, "xray")
                if scenario == "missing-unit":
                    (root / "systemd/xray.service").unlink()
                variables = {"nonroot":{"CORE_SERVICE_USER":"nobody"}, "dynamic":{"CORE_DYNAMIC_USER":"yes"},
                             "custom-unit":{"CORE_FRAGMENT_PATH":"/custom/xray.service"},
                             "custom-command":{"CORE_COMMAND":"/custom/xray run -c /custom/config.json"}}.get(scenario,{})
                self.fx.finish(self.fx.start(root, "xray", setup="release=alpine" if scenario == "alpine" else "",
                                             **variables),1)
                self.unchanged(root, "xray", before)
                self.assertFalse((root / "downloads.jsonl").exists())

    def test_explicit_rollback_and_preview_keep_the_selected_version(self):
        for rel in INSTALLERS:
            for core in TAGS:
                for tag, preview in ((TAGS[core][2],"false"), ("","true")):
                    root = self.fx.make(rel,core)
                    self.fx.finish(self.fx.start(root,core,operation=f"agentInstallCore {core} {shlex.quote(tag)} {preview}"),0)
                    expected = tag or TAGS[core][1]
                    self.assertIn(repr(expected),(root / core / core).read_text())

    def test_release_picker_fetches_once_outside_lock_and_rejects_bad_selection(self):
        for rel in INSTALLERS:
            for answer, result in (("2\n",0), ("99\n",1), ("$(echo nope)\n",1)):
                root = self.fx.make(rel,"xray")
                proc = self.fx.start(root,"xray",operation="agentChooseCoreVersion xray",pause="metadata")
                with cli.shared_lock(root,timeout=1):
                    pass
                proc.stdin.write("continue\n")
                proc.stdin.flush()
                deadline = time.monotonic() + 5
                while not list((root / "xray").glob(".core-versions.*/versions")) and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                out, err = proc.communicate(answer, timeout=12)
                self.assertEqual(proc.returncode, result, out + err)
                self.assertEqual(len((root / "downloads.jsonl").read_text().splitlines()),1)

    def test_old_installation_callers_propagate_failure_and_upgrade_menu_does_not_double_restart(self):
        for rel in INSTALLERS:
            text = (REPO / rel).read_text()
            for line in text.splitlines():
                if line.strip().startswith(("installXray ", "installSingBox ")):
                    self.assertIn("|| return 1",line)
            menu = function(text,"singBoxVersionManageMenu")
            branch = menu.split('if [[ "${selectSingBoxType}" == "1" ]]; then',1)[1].split("elif",1)[0]
            self.assertIn("updateSingBox || return 1",branch)
            self.assertNotIn("handleSingBox",branch)
            for name in ("installXray","updateXray","installSingBox"):
                body = function(text,name)
                self.assertNotIn("rm ",body)
                self.assertNotIn("wget",body)
