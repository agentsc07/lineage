"""Python-AST capability extractor incl. install-time and start-up hooks (setup.py, .pth, sitecustomize) (Track C)."""
from __future__ import annotations

import ast
import json
import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._pycode import Names, PyFile, _walk, iter_python, line_text
from lineage.schemas.finding import Finding

CAPABILITIES = ("network", "filesystem", "subprocess", "env_secrets", "dynamic_exec", "encoded_blob", "obfuscation")
# Derived keys that `extract` adds; they match the banned_capabilities names in the policy pack.
DERIVED = ("startup_hook", "network_at_install", "install_exec", "dynamic_exec_of_remote_code")

NETWORK = (
    "socket", "requests", "urllib.request", "urllib3", "http.client", "httpx", "aiohttp", "ftplib", "smtplib",
    "telnetlib", "websockets", "websocket", "paramiko", "xmlrpc.client", "poplib", "imaplib", "grpc",
)
NETWORK_IMPORT_ONLY = {"socket", "ftplib", "smtplib", "telnetlib", "paramiko"}
FS_OS = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "replace", "makedirs", "mkdir", "listdir", "scandir",
    "walk", "chmod", "chown", "symlink", "link", "truncate", "utime",
}
FS_PATH = {
    "read_text", "write_text", "read_bytes", "write_bytes", "open", "unlink", "mkdir", "iterdir", "rglob", "glob",
    "rmdir", "rename", "touch",
}
SUBPROCESS = ("subprocess", "os.system", "os.popen", "os.exec", "os.spawn", "os.posix_spawn", "pty.spawn",
              "commands.getoutput", "asyncio.create_subprocess")
DYN_EXEC = {"exec", "eval", "compile", "__import__", "marshal.loads", "pickle.loads", "pickle.load", "dill.loads",
            "cloudpickle.loads", "runpy.run_path", "runpy.run_module", "importlib.import_module"}
ENCODED = {
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.urlsafe_b64decode", "base64.standard_b64decode", "base64.decodebytes", "binascii.unhexlify",
    "binascii.a2b_base64", "binascii.a2b_hex", "bytes.fromhex", "zlib.decompress", "gzip.decompress",
    "bz2.decompress", "lzma.decompress", "codecs.decode",
}
SENSITIVE_PATH = re.compile(
    r"(\.ssh\b|id_rsa|id_ed25519|\.aws/|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker/config|\.kube/config"
    r"|/etc/passwd|/etc/shadow|\.config/gcloud|\.env\b|Login Data|wallet\.dat)"
)
SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSW|CRED|AUTH)", re.I)
B64_LIKE = re.compile(r"^[A-Za-z0-9+/=_-]{200,}$")
INSTALL_FILES = {"setup.py", "hatch_build.py", "_custom_build.py", "custom_build.py", "build_backend.py"}
STARTUP_FILES = {"sitecustomize.py", "usercustomize.py"}
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
NPM_NET = re.compile(r"(curl|wget|https?://|node\s+-e|base64|nc\s|powershell|bash\s+-c|eval)", re.I)


@dataclass(frozen=True)
class Hit:
    cap: str
    file: str
    line: int
    api: str
    snippet: str = ""
    flags: frozenset[str] = field(default_factory=frozenset)

    @property
    def ref(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class Hook:
    kind: str  # startup_hook | network_at_install | install_exec
    file: str
    line: int
    detail: str


@dataclass
class Analysis:
    hits: list[Hit] = field(default_factory=list)
    hooks: list[Hook] = field(default_factory=list)


def _matches(dotted: str, prefixes) -> bool:
    return any(dotted == p or dotted.startswith(p + ".") or dotted.startswith(p + "()") for p in prefixes)


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


class _Visitor(ast.NodeVisitor):
    def __init__(self, pf: PyFile):
        assert pf.tree is not None
        self.pf = pf
        self.lines = pf.text.splitlines()
        self.names = Names(pf.tree)
        self.hits: list[Hit] = []
        self.parents: dict[ast.AST, ast.AST] = {}
        for p in ast.walk(pf.tree):
            for c in ast.iter_child_nodes(p):
                self.parents[c] = p
        self.docstrings = {
            n.body[0].value
            for n in ast.walk(pf.tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)
        }

    def add(self, cap: str, node: ast.AST, api: str, flags: tuple[str, ...] = ()) -> None:
        line = getattr(node, "lineno", 1)
        self.hits.append(Hit(cap, self.pf.rel, line, api, line_text(self.lines, line), frozenset(flags)))

    # --- imports (only modules that are a capability by themselves)
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.name in NETWORK_IMPORT_ONLY:
                self.add("network", node, f"import {a.name}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in NETWORK_IMPORT_ONLY:
            self.add("network", node, f"from {node.module} import ...")

    # --- calls
    def visit_Call(self, node: ast.Call) -> None:
        d = self.names.dotted(node.func) or ""
        if _matches(d, NETWORK):
            self.add("network", node, d)
        if d == "open" or (d.startswith("os.") and d[3:] in FS_OS) or d.startswith("shutil.") or d == "glob.glob":
            self.add("filesystem", node, d)
        elif d.startswith("pathlib.Path") and d.rsplit(".", 1)[-1] in FS_PATH:
            self.add("filesystem", node, d)
        if _matches(d, SUBPROCESS):
            self.add("subprocess", node, d)
        if d in ("os.getenv", "os.getenvb", "getpass.getpass", "keyring.get_password", "dotenv.load_dotenv"):
            self.add("env_secrets", node, d)
        if d in DYN_EXEC:
            if d == "importlib.import_module" and node.args and isinstance(node.args[0], ast.Constant):
                pass  # a literal module name is ordinary plugin loading
            else:
                decoded = d in ("exec", "eval") and self._contains_decode(node)
                self.add("dynamic_exec", node, d, ("decoded_exec",) if decoded else ())
        if d in ENCODED or d.endswith(".decode") and d.startswith(("base64.", "codecs.")):
            if d == "codecs.decode" and not (len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                                             and str(node.args[1].value).lower().replace("-", "_") in
                                             {"hex", "base64", "base_64", "rot13", "rot_13", "zlib", "bz2", "uu"}):
                pass
            else:
                self.add("encoded_blob", node, d)
        # obfuscation
        if d in ("getattr", "setattr", "delattr") and len(node.args) > 1 and not isinstance(node.args[1], ast.Constant):
            self.add("obfuscation", node, f"{d}(<computed name>)")
        if d == "getattr" and node.args and (self.names.dotted(node.args[0]) or "") in ("builtins", "__builtins__"):
            self.add("obfuscation", node, "getattr(builtins, ...)")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and any(
            isinstance(n, ast.Call) and self.names.dotted(n.func) == "chr" for a in node.args for n in ast.walk(a)
        ):
            self.add("obfuscation", node, "''.join(chr(...))")
        self.generic_visit(node)

    def _contains_decode(self, call: ast.Call) -> bool:
        for sub in ast.walk(ast.Tuple(elts=call.args + [k.value for k in call.keywords], ctx=ast.Load())):
            if isinstance(sub, ast.Call):
                dd = self.names.dotted(sub.func) or ""
                if dd in ENCODED or dd.endswith((".decode", ".decompress")) or dd.startswith(("base64.", "codecs.")):
                    return True
        return False

    # --- os.environ access
    def visit_Attribute(self, node: ast.Attribute) -> None:
        d = self.names.dotted(node)
        if d in ("os.environ", "os.environb"):
            par = self.parents.get(node)
            targeted = isinstance(par, ast.Subscript) or (
                isinstance(par, ast.Attribute) and par.attr in ("get", "setdefault", "pop")
            )
            key = ""
            if isinstance(par, ast.Subscript) and isinstance(par.slice, ast.Constant):
                key = str(par.slice.value)
            elif isinstance(par, ast.Attribute):
                gp = self.parents.get(par)
                if isinstance(gp, ast.Call) and gp.args and isinstance(gp.args[0], ast.Constant):
                    key = str(gp.args[0].value)
            flags = ("bulk",) if not targeted else (("secret_key",) if SECRET_KEY.search(key) else ())
            self.add("env_secrets", node, f"{d}[{key}]" if key else d, flags)
        self.generic_visit(node)

    # --- string literals
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node not in self.docstrings:
            s = node.value
            if len(s) < 200 and SENSITIVE_PATH.search(s):
                self.add("env_secrets", node, f"path literal {s[:60]!r}", ("sensitive_path",))
            elif len(s) >= 200 and B64_LIKE.match(s) and _entropy(s) > 4.0:
                self.add("encoded_blob", node, f"base64-like literal ({len(s)} chars)", ("literal",))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        sl = node.slice
        if (isinstance(sl, ast.Slice) and isinstance(sl.step, ast.UnaryOp) and isinstance(sl.step.op, ast.USub)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                and len(node.value.value) >= 8):
            self.add("obfuscation", node, "reversed string literal")
        if (self.names.dotted(node.value) or "") in ("__builtins__", "builtins"):
            self.add("obfuscation", node, "__builtins__[...]")
        self.generic_visit(node)


_OBFUSCATED_NAME = re.compile(r"^_?0x[0-9a-f]+$|^[Il1O0_]{8,}$")
_HEX_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}")
_REGEX_FALLBACK = (
    ("dynamic_exec", re.compile(r"\b(exec|eval)\s*\(")),
    ("encoded_blob", re.compile(r"b64decode|unhexlify|zlib\.decompress")),
    ("subprocess", re.compile(r"subprocess\.|os\.system|os\.popen")),
    ("network", re.compile(r"\b(socket|urlopen|requests\.(get|post))\b")),
)


def _file_hits(pf: PyFile) -> list[Hit]:
    lines = pf.text.splitlines()
    if pf.tree is None:  # unparseable (e.g. Python 2): coarse line-based fallback
        hits = []
        for n, line in enumerate(lines, 1):
            for cap, rx in _REGEX_FALLBACK:
                if rx.search(line):
                    hits.append(Hit(cap, pf.rel, n, rx.pattern, line.strip()[:160], frozenset({"regex"})))
        return hits
    v = _Visitor(pf)
    v.visit(pf.tree)
    names = [n.id for n in ast.walk(pf.tree) if isinstance(n, ast.Name)]
    if sum(1 for n in names if _OBFUSCATED_NAME.match(n)) >= 5:
        v.hits.append(Hit("obfuscation", pf.rel, 1, "obfuscated identifiers", line_text(lines, 1)))
    if len(_HEX_ESCAPES.findall(pf.text)) >= 20:
        first = next((i for i, ln in enumerate(lines, 1) if _HEX_ESCAPES.search(ln)), 1)
        v.hits.append(Hit("obfuscation", pf.rel, first, "dense \\x escapes", line_text(lines, first)))
    return v.hits


def _install_files(root: Path) -> set[str]:
    base = root.parent if root.is_file() else root
    files = set(INSTALL_FILES)
    for pp in _walk(root):
        if pp.name == "pyproject.toml":
            try:
                data = tomllib.loads(pp.read_text())
            except tomllib.TOMLDecodeError:
                continue
            for b in data.get("build-system", {}).get("backend-path", []):
                bp = (pp.parent / b)
                if bp.is_dir():
                    files.update(x.relative_to(base).as_posix() for x in bp.rglob("*.py"))
    return files


def analyse(package_dir: Path) -> Analysis:
    """All capability hits plus the install-time and start-up hooks, with no LLM involved."""
    root = Path(package_dir)
    a = Analysis()
    install = _install_files(root)
    for pf in iter_python(root):
        hits = _file_hits(pf)
        a.hits.extend(hits)
        _derive_hooks(a, pf, hits, install)
    _npm_hooks(a, root)
    a.hits.sort(key=lambda h: (h.file, h.line, h.cap))
    return a


def analyse_files(files: list[Path], root: Path) -> Analysis:
    """Same analysis for an explicit file list (e.g. the custom code a model's auto_map points at)."""
    a = Analysis()
    for f in files:
        for pf in iter_python(f):
            pf.rel = f.relative_to(root).as_posix()
            hits = _file_hits(pf)
            a.hits.extend(hits)
    return a


def _derive_hooks(a: Analysis, pf: PyFile, hits: list[Hit], install: set[str]) -> None:
    name = Path(pf.rel).name
    if pf.kind == "pth":
        for n, line in enumerate(pf.text.splitlines(), 1):
            if line.startswith(("import ", "import\t")):
                a.hooks.append(Hook("startup_hook", pf.rel, n, line.strip()[:160]))
    elif name in STARTUP_FILES:
        a.hooks.append(Hook("startup_hook", pf.rel, 1, f"{name} runs on every interpreter start"))
    if pf.rel in install or name in INSTALL_FILES:
        for h in hits:
            if h.cap == "network":
                a.hooks.append(Hook("network_at_install", h.file, h.line, h.snippet))
            elif h.cap in ("subprocess", "dynamic_exec", "encoded_blob", "env_secrets"):
                a.hooks.append(Hook("install_exec", h.file, h.line, h.snippet))


def _npm_hooks(a: Analysis, root: Path) -> None:
    base = root.parent if root.is_file() else root
    for pj in _walk(root):
        if pj.name != "package.json":
            continue
        try:
            scripts = json.loads(pj.read_text()).get("scripts", {})
        except (json.JSONDecodeError, AttributeError):
            continue
        lines = pj.read_text().splitlines()
        for key in NPM_LIFECYCLE:
            if isinstance(scripts, dict) and key in scripts:
                n = next((i for i, ln in enumerate(lines, 1) if f'"{key}"' in ln), 1)
                kind = "network_at_install" if NPM_NET.search(str(scripts[key])) else "install_exec"
                a.hooks.append(Hook(kind, pj.relative_to(base).as_posix(), n, f"{key}: {scripts[key]}"[:160]))


def _remote_exec_hits(a: Analysis) -> list[Hit]:
    """Dynamic execution in a file that also reaches the network."""
    net_files = {h.file for h in a.hits if h.cap == "network"}
    return [h for h in a.hits if h.cap == "dynamic_exec" and h.file in net_files and h.api in ("exec", "eval", "compile")]


def extract(package_dir: Path) -> dict[str, list[str]]:
    """capability -> ["file:line", ...]. Deterministic; no LLM."""
    a = analyse(package_dir)
    out: dict[str, list[str]] = {}
    for h in a.hits:
        out.setdefault(h.cap, []).append(h.ref)
    for hook in a.hooks:
        out.setdefault(hook.kind, []).append(f"{hook.file}:{hook.line}")
    for h in _remote_exec_hits(a):
        out.setdefault("dynamic_exec_of_remote_code", []).append(h.ref)
    return out


def diff_capabilities(old: dict[str, list[str]], new: dict[str, list[str]]) -> dict[str, list[str]]:
    """Capabilities (per file) in `new` that `old` lacked; lines are ignored so shifted code isn't 'new'."""
    def files(d: dict[str, list[str]]) -> set[tuple[str, str]]:
        return {(cap, ref.rsplit(":", 1)[0]) for cap, refs in d.items() for ref in refs}

    added = files(new) - files(old)
    out: dict[str, list[str]] = {}
    for cap, refs in new.items():
        fresh = [r for r in refs if (cap, r.rsplit(":", 1)[0]) in added]
        if fresh:
            out[cap] = fresh
    return out


_BASE_SEVERITY = {
    "network": "medium", "filesystem": "low", "subprocess": "medium", "env_secrets": "medium",
    "dynamic_exec": "high", "encoded_blob": "medium", "obfuscation": "high",
}
_TITLES = {
    "network": "Code can open network connections",
    "filesystem": "Code reads or writes the filesystem",
    "subprocess": "Code runs subprocesses or shell commands",
    "env_secrets": "Code reads environment variables or credential files",
    "dynamic_exec": "Code executes dynamically built code (exec/eval/import)",
    "encoded_blob": "Code decodes encoded or compressed blobs",
    "obfuscation": "Code uses obfuscation techniques",
}
_HOOK_TITLES = {
    "startup_hook": "Code runs automatically at interpreter start-up (.pth / sitecustomize)",
    "network_at_install": "Install-time code reaches the network",
    "install_exec": "Install-time code runs commands or dynamic code",
}


def _evidence(hits: list[Hit], limit: int = 10):
    return [ev("file_line", h.ref, f"{h.api}: {h.snippet}"[:200]) for h in hits[:limit]]


def findings_from(a: Analysis, only_new: bool = False) -> list[Finding]:
    out: list[Finding] = []
    new = " (newly added)" if only_new else ""
    by_cap: dict[str, list[Hit]] = {}
    for h in a.hits:
        by_cap.setdefault(h.cap, []).append(h)
    for cap in CAPABILITIES:
        hits = by_cap.get(cap, [])
        if not hits:
            continue
        sev = _BASE_SEVERITY[cap]
        if cap == "env_secrets" and not any(f in h.flags for h in hits for f in ("bulk", "secret_key", "sensitive_path")):
            sev = "low"
        if cap == "filesystem" and only_new:
            sev = "low"
        out.append(finding(f"PKG.CAP.{cap.upper()}", _TITLES[cap] + new, sev, "code", "S4", _evidence(hits)))
    for h in (x for x in a.hits if "decoded_exec" in x.flags):
        out.append(finding("PKG.CODE.DECODE_EXEC", f"Decodes a blob and executes it ({h.api}){new}", "critical",
                           "code", "S4", [ev("file_line", h.ref, h.snippet)]))
    for h in _remote_exec_hits(a):
        out.append(finding("PKG.CODE.REMOTE_EXEC_POSSIBLE", f"Network access and dynamic execution in one file{new}",
                           "high", "code", "S4", [ev("file_line", h.ref, h.snippet)]))
    risky_files = {h.file for h in a.hits if h.cap in ("network", "subprocess", "dynamic_exec", "encoded_blob", "env_secrets")}
    for kind in ("startup_hook", "network_at_install", "install_exec"):
        hooks = [k for k in a.hooks if k.kind == kind]
        if not hooks:
            continue
        sev = "high" if kind != "install_exec" else "medium"
        if kind == "startup_hook" and any(k.file in risky_files for k in hooks):
            sev = "critical"
        out.append(finding(f"PKG.HOOK.{kind.upper()}", _HOOK_TITLES[kind] + new, sev, "code", "S4",
                           [ev("file_line", f"{k.file}:{k.line}", k.detail) for k in hooks[:10]]))
    return out


def scan(package_dir: Path, previous: Path | None = None) -> list[Finding]:
    """Findings for risky capabilities; if `previous` is given, only newly added capabilities are raised."""
    cur = analyse(package_dir)
    if previous is None:
        return findings_from(cur)
    old = analyse(previous)
    seen = {(h.cap, h.file) for h in old.hits}
    seen_hooks = {(k.kind, k.file) for k in old.hooks}
    delta = Analysis(
        hits=[h for h in cur.hits if (h.cap, h.file) not in seen],
        hooks=[k for k in cur.hooks if (k.kind, k.file) not in seen_hooks],
    )
    out = findings_from(delta, only_new=True)
    if not out:
        out = [finding("PKG.CAP.NO_NEW", "No new capabilities versus the previous version", "info", "code", "S4")]
    return out
