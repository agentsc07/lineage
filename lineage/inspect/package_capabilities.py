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

from lineage.inspect import _hosts
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
    r"(\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker/config|\.kube/config"
    r"|/etc/passwd|/etc/shadow|\.config/gcloud|\.env\b|Login Data|wallet\.dat)"
)
SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSW|CRED|AUTH)", re.I)
TIME_SOURCES = {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today", "datetime.date.today",
                "datetime.now", "datetime.utcnow", "date.today", "time.time", "time.gmtime", "time.localtime", "time.strftime"}
DELAY_MIN_SECONDS = 60
INSTALL_COMMANDS = {"install", "develop", "egg_info", "install_lib", "install_scripts"}
B64_LIKE = re.compile(r"^[A-Za-z0-9+/=_-]{200,}$")
INSTALL_FILES = {"setup.py", "hatch_build.py", "_custom_build.py", "custom_build.py", "build_backend.py"}
STARTUP_FILES = {"sitecustomize.py", "usercustomize.py"}
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
NPM_NET = re.compile(r"(curl|wget|https?://|node\s+-e|base64|nc\s|powershell|bash\s+-c|eval)", re.I)


TEST_DIRS = {"tests", "test", "testing", "_tests", "_test", "testsuite", "test_utils"}


def is_test_file(rel: str) -> bool:
    """Test code in a wheel is shipped but not run on import; its hits are signals only. conftest.py is the
    exception pytest imports automatically, so it is treated as ordinary code."""
    parts = rel.lower().split("/")
    name = parts[-1]
    return bool(set(parts[:-1]) & TEST_DIRS) or name.startswith("test_") or name.endswith("_test.py")


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
        self.is_test = is_test_file(pf.rel)
        self.consts: dict[str, str] = {}
        for n in ast.walk(pf.tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.consts[t.id] = n.value.value
        self.docstrings = {
            n.body[0].value
            for n in ast.walk(pf.tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)
        }

    def at_import_time(self, node: ast.AST) -> bool:
        """Runs when the module is imported: not inside a function, and not under `if __name__ == "__main__"`."""
        cur = self.parents.get(node)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            if isinstance(cur, ast.If) and "__name__" in ast.dump(cur.test) and "__main__" in ast.dump(cur.test):
                return False
            if isinstance(cur, ast.If) and "TYPE_CHECKING" in ast.dump(cur.test):
                return False
            cur = self.parents.get(cur)
        return True

    def hosts_of(self, call: ast.Call) -> set[str]:
        """Literal destinations in a network call: URLs in its arguments (direct, via a constant name, or in an f-string),
        or a bare host as the first argument of a connection constructor."""
        found: set[str] = set()
        values = [*call.args, *[k.value for k in call.keywords]]
        for v in values:
            for sub in ast.walk(v):
                text = None
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    text = sub.value
                elif isinstance(sub, ast.Name) and sub.id in self.consts:
                    text = self.consts[sub.id]
                if text:
                    found |= _hosts.hosts_in_text(text)
        ctor = (self.names.dotted(call.func) or "").rsplit(".", 1)[-1]
        if ctor in ("HTTPConnection", "HTTPSConnection", "create_connection", "SMTP", "SMTP_SSL", "FTP", "FTP_TLS", "connect", "Telnet",
                    "connect_ex", "sendto", "bind"):
            for a in call.args[:1]:  # host is the first argument, or the first element of an (host, port) tuple
                for sub in ([a] if not isinstance(a, ast.Tuple) else a.elts[:1]):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _hosts.looks_like_host(sub.value):
                        found.add(sub.value.lower())
        return found

    def add(self, cap: str, node: ast.AST, api: str, flags: tuple[str, ...] = ()) -> None:
        line = getattr(node, "lineno", 1)
        extra = set(flags)
        if self.is_test:
            extra.add("test")
        elif cap in ("network", "subprocess", "dynamic_exec", "delayed_exec") and self.at_import_time(node):
            extra.add("toplevel")
        if cap in ("network", "subprocess") and isinstance(node, ast.Call):
            extra |= {f"host={h}" for h in self.hosts_of(node)}
        self.hits.append(Hit(cap, self.pf.rel, line, api, line_text(self.lines, line), frozenset(extra)))

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
            self.add("subprocess", node, d, ("empty_command",) if d == "os.system" and node.args and isinstance(node.args[0], ast.Constant)
                     and not str(node.args[0].value).strip() else ())
        elif d.startswith("ctypes.") and d.rsplit(".", 1)[-1] in ("system", "popen", "execv", "execve", "execl", "execvp", "posix_spawn"):
            self.add("subprocess", node, d, ("native",))  # libc's system() reached through ctypes: the same shell, without the subprocess import
        if d in ("threading.Timer", "sched.scheduler.enter", "asyncio.call_later") and node.args:
            delay = node.args[0]
            long_delay = not isinstance(delay, ast.Constant) or (isinstance(delay.value, (int, float)) and delay.value >= DELAY_MIN_SECONDS)
            if long_delay:
                payload = ast.Module(body=[ast.Expr(value=a) for a in node.args[1:]] + [ast.Expr(value=k.value) for k in node.keywords], type_ignores=[])
                self.add("delayed_exec", node, f"{d}(<delay>)", ("risky_payload",) if self._risky_under(payload) else ())
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
            par = self.parents.get(node)
            called = isinstance(par, ast.Call) and par.func is node
            self.add("obfuscation", node, "getattr(builtins, ...)", ("strong",) if called else ())  # looking up a builtin by name is ordinary
            if called:  # getattr(builtins, "ex" + "ec")(...): exec reached by a built-up name
                self.add("dynamic_exec", node, "getattr(builtins, <name>)(...)", ("hidden",))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and any(
            isinstance(n, ast.Call) and self.names.dotted(n.func) == "chr" for a in node.args for n in ast.walk(a)
        ):
            literal_codes = any(isinstance(g, ast.comprehension) and isinstance(g.iter, (ast.Tuple, ast.List, ast.Constant))
                                and len(getattr(g.iter, "elts", [0] * 4)) >= 4 for a in node.args for g in ast.walk(a)) or any(
                isinstance(n, ast.Call) and self.names.dotted(n.func) == "chr" and n.args and isinstance(n.args[0], ast.Constant)
                for a in node.args for n in ast.walk(a))
            self.add("obfuscation", node, "''.join(chr(...))", ("strong",) if literal_codes else ())  # chr() over a literal list spells a name; over a variable it formats text
        self.generic_visit(node)

    def _risky_under(self, node: ast.AST) -> bool:
        """Does anything under `node` touch the network, run a command, exec code or write a file?"""
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            d = self.names.dotted(sub.func) or ""
            if _matches(d, NETWORK) or _matches(d, SUBPROCESS) or d in DYN_EXEC or d in ("shutil.rmtree", "os.remove", "os.unlink"):
                return True
            if d in ("open", "io.open") or (d.startswith("pathlib.Path") and d.rsplit(".", 1)[-1] in ("write_text", "write_bytes", "unlink")):
                mode = next((a.value for a in sub.args[1:2] if isinstance(a, ast.Constant)), None)
                mode = mode or next((k.value.value for k in sub.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)), "r")
                if d != "open" and d != "io.open" or any(c in str(mode) for c in "wax+"):
                    return True
        return False

    def visit_If(self, node: ast.If) -> None:
        """Execution gated on the clock or calendar: `if datetime.now() > date(...): <payload>`."""
        gated = [self.names.dotted(c.func) for c in ast.walk(node.test) if isinstance(c, ast.Call)]
        if any(g in TIME_SOURCES for g in gated if g) and any(isinstance(c, ast.Compare) for c in ast.walk(node.test)):
            if self._risky_under(ast.Module(body=node.body, type_ignores=[])):
                self.add("delayed_exec", node, "date-gated branch", ("risky_payload",))
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
            self.add("obfuscation", node, "reversed string literal", ("strong",))
        if (self.names.dotted(node.value) or "") == "__builtins__":  # a variable that merely happens to be called `builtins` is not Python's
            self.add("obfuscation", node, "__builtins__[...]", ("strong",))
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
        v.hits.append(Hit("obfuscation", pf.rel, 1, "obfuscated identifiers", line_text(lines, 1), frozenset({"strong"})))
    if len(_HEX_ESCAPES.findall(pf.text)) >= 20:
        first = next((i for i, ln in enumerate(lines, 1) if _HEX_ESCAPES.search(ln)), 1)
        v.hits.append(Hit("obfuscation", pf.rel, first, "dense \\x escapes", line_text(lines, first)))  # regexes and byte tables are full of them
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
    if (pf.rel in install or name in INSTALL_FILES) and pf.tree is not None:
        _custom_install_hooks(a, pf, hits)
    if pf.rel in install or name in INSTALL_FILES:
        for h in hits:
            if h.cap == "network":
                a.hooks.append(Hook("network_at_install", h.file, h.line, h.snippet))
            elif h.cap in ("subprocess", "dynamic_exec", "encoded_blob", "env_secrets"):
                a.hooks.append(Hook("install_exec", h.file, h.line, h.snippet))


def _custom_install_hooks(a: Analysis, pf: PyFile, hits: list[Hit]) -> None:
    """A setup.py (or build backend) that subclasses an install-time command and overrides what it runs, or registers one."""
    names = Names(pf.tree)
    for cls in (n for n in ast.walk(pf.tree) if isinstance(n, ast.ClassDef)):
        bases = {(names.dotted(b) or "").rsplit(".", 1)[-1] for b in cls.bases}
        if not bases & INSTALL_COMMANDS:
            continue
        methods = [m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in ("run", "__init__", "finalize_options")]
        if not methods:
            continue
        end = max(getattr(n, "end_lineno", cls.lineno) or cls.lineno for n in ast.walk(cls))
        inside = [h for h in hits if h.file == pf.rel and cls.lineno <= h.line <= end
                  and h.cap in ("network", "subprocess", "dynamic_exec", "encoded_blob", "env_secrets", "filesystem")]
        kind = "custom_install_exec" if inside else "custom_install"
        detail = f"class {cls.name}({', '.join(sorted(bases & INSTALL_COMMANDS))}) overrides {', '.join(m.name for m in methods)}"
        if inside:
            detail += f"; it uses {', '.join(sorted({h.cap for h in inside}))}"
        a.hooks.append(Hook(kind, pf.rel, cls.lineno, detail))


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
    "custom_install": "setup.py overrides an install-time command",
    "custom_install_exec": "setup.py overrides an install-time command and that command does things",
    "startup_hook": "Code runs automatically at interpreter start-up (.pth / sitecustomize)",
    "network_at_install": "Install-time code reaches the network",
    "install_exec": "Install-time code runs commands or dynamic code",
}
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.I)
RISKY = ("network", "subprocess", "dynamic_exec", "encoded_blob", "env_secrets")


def _evidence(hits: list[Hit], limit: int = 10):
    return [ev("file_line", h.ref, f"{h.api}: {h.snippet}"[:200]) for h in hits[:limit]]


def _live(hits: list[Hit]) -> list[Hit]:
    """Hits in code that runs. Test code shipped in a wheel is a signal, never evidence of a payload."""
    return [h for h in hits if "test" not in h.flags]


def _hit_hosts(h: Hit) -> set[str]:
    return {f[5:] for f in h.flags if f.startswith("host=")}


def signals(a: Analysis, note: str = "") -> list[Finding]:
    """What the code can do, one info finding per capability. A capability alone proves nothing (every HTTP client
    opens sockets), so signals carry no score; `combos` and the release diff decide when they matter."""
    out: list[Finding] = []
    by_cap: dict[str, list[Hit]] = {}
    for h in a.hits:
        by_cap.setdefault(h.cap, []).append(h)
    for cap in CAPABILITIES:
        hits = by_cap.get(cap, [])
        if hits:
            out.append(finding(f"PKG.SIGNAL.{cap.upper()}", _TITLES[cap] + note, "info", "code", "S4", _evidence(hits)))
    remote = _remote_exec_hits(a)
    if remote:
        out.append(finding("PKG.SIGNAL.REMOTE_EXEC_POSSIBLE", "Network access and dynamic execution in one file" + note, "info", "code", "S4",
                           [ev("file_line", h.ref, h.snippet) for h in remote[:5]]))
    return out


def combos(a: Analysis, package: str = "", declared: set[str] | None = None) -> list[Finding]:
    """Findings that exist only because two signals appear together. Each names the pair so a reviewer can check it."""
    declared = declared or set()
    out: list[Finding] = []
    live = _live(a.hits)
    by_file: dict[str, list[Hit]] = {}
    for h in live:
        by_file.setdefault(h.file, []).append(h)

    for f_, hs in sorted(by_file.items()):
        creds = [h for h in hs if h.cap == "env_secrets" and ({"sensitive_path", "secret_key"} & h.flags)]
        sends = [h for h in hs if h.cap in ("network", "subprocess")]
        if creds and sends:
            hosts = {x for h in sends for x in _hit_hosts(h)}
            stray = sorted(x for x in hosts if not _hosts_declared(x, package, declared))
            cred_file = any("sensitive_path" in h.flags for h in creds)
            hidden = cred_file and not hosts and any("strong" in h.flags for h in hs if h.cap == "obfuscation")
            if stray or hidden:
                where = ", ".join(stray) if stray else "a host built at run time"
                out.append(finding("PKG.COMBO.CREDENTIAL_EXFIL", f"{f_} reads a credential and can send data to {where}, which the package's metadata does not declare",
                                   "critical", "code", "S4", _evidence(creds, 3) + _evidence([h for h in sends if _hit_hosts(h) & set(stray)] or sends, 3)))
        strong = [h for h in hs if h.cap == "obfuscation" and "strong" in h.flags]
        acts = [h for h in hs if h.cap in ("dynamic_exec", "subprocess", "network", "encoded_blob")]
        if strong and acts:
            hidden_exec = any("hidden" in h.flags for h in acts)
            out.append(finding("PKG.COMBO.OBFUSCATED_PAYLOAD", f"{f_} hides what it does ({strong[0].api}) and also {acts[0].cap.replace('_', ' ')}s",
                               "critical", "code", "S4", _evidence(strong, 3) + _evidence(acts, 3)))
        runs = [h for h in hs if h.cap == "subprocess" and "toplevel" in h.flags and "empty_command" not in h.flags]
        fetch = [h for h in runs if PIPE_TO_SHELL.search(h.snippet)]
        if fetch:
            out.append(finding("PKG.COMBO.FETCH_AND_RUN", f"{f_} downloads a script and pipes it to a shell", "critical", "code", "S4", _evidence(fetch, 3)))
        elif runs:
            out.append(finding("PKG.COMBO.IMPORT_TIME_EXEC", f"{f_} runs a command as soon as it is imported", "critical", "code", "S4", _evidence(runs, 3)))
    return out


def _hosts_declared(host: str, package: str, declared: set[str]) -> bool:
    return _hosts.is_declared(host, package, declared)


def hook_findings(a: Analysis, baseline: Analysis | None = None) -> list[Finding]:
    """Install-time and start-up hooks. One that the previous release already had is `info`; a new one keeps its
    severity (a new start-up hook is a hard finding)."""
    out: list[Finding] = []
    risky_files = {h.file for h in _live(a.hits) if h.cap in ("network", "subprocess", "dynamic_exec", "encoded_blob", "env_secrets")}
    before = {(k.kind, k.file) for k in baseline.hooks} if baseline else set()
    for kind in ("startup_hook", "network_at_install", "install_exec", "custom_install", "custom_install_exec"):
        hooks = [k for k in a.hooks if k.kind == kind]
        if not hooks:
            continue
        sev = "critical" if kind == "custom_install_exec" else "high" if kind != "install_exec" else "high"
        if kind == "startup_hook":
            sev = "critical"
        elif kind == "custom_install":
            sev = "medium"
        old = [k for k in hooks if (k.kind, k.file) in before]
        fresh = [k for k in hooks if (k.kind, k.file) not in before]
        if fresh:
            out.append(finding(f"PKG.HOOK.{kind.upper()}", _HOOK_TITLES[kind] + (" (new in this release)" if baseline else ""), sev, "code", "S4",
                               [ev("file_line", f"{k.file}:{k.line}", k.detail) for k in fresh[:10]]))
        if old:
            out.append(finding(f"PKG.HOOK.{kind.upper()}", _HOOK_TITLES[kind] + " (already in the previous release)", "info", "code", "S4",
                               [ev("file_line", f"{k.file}:{k.line}", k.detail) for k in old[:10]]))
    return out


def content_findings(a: Analysis) -> list[Finding]:
    """Findings that need no baseline and no second signal: a decoded blob that is executed, an armed delayed payload."""
    out: list[Finding] = []
    for h in (x for x in a.hits if "decoded_exec" in x.flags):
        out.append(finding("PKG.CODE.DECODE_EXEC", f"Decodes a blob and executes it ({h.api})", "critical", "code", "S4", [ev("file_line", h.ref, h.snippet)]))
    delayed = [h for h in a.hits if h.cap == "delayed_exec"]
    armed = [h for h in delayed if "risky_payload" in h.flags]
    if armed:
        out.append(finding("PKG.CODE.DELAYED_EXEC", "Code runs later or only after a date and the delayed part does real work", "critical", "code", "S4", _evidence(armed)))
    elif delayed:
        out.append(finding("PKG.SIGNAL.DELAYED_EXEC", "Code schedules work for later", "info", "code", "S4", _evidence(delayed)))
    return out


def _cred_paths(hits: list[Hit]) -> set[str]:
    return {h.api for h in hits if h.cap == "env_secrets" and "sensitive_path" in h.flags}


def diff_findings(cur: Analysis, prev: Analysis, package: str = "", declared: set[str] | None = None) -> list[Finding]:
    """Capabilities this release has that the previous one did not. New and risky is high or critical; present
    before is not reported here at all (its signal is already `info`)."""
    declared = declared or set()
    out: list[Finding] = []
    now, was = _live(cur.hits), _live(prev.hits)
    had = {h.cap for h in was if "empty_command" not in h.flags}
    for cap, fid, title in (("subprocess", "PKG.NEW.SUBPROCESS", "Starts running subprocesses or shell commands"),
                            ("dynamic_exec", "PKG.NEW.DYNAMIC_EXEC", "Starts executing dynamically built code")):
        fresh = [h for h in now if h.cap == cap and "empty_command" not in h.flags]
        if fresh and cap not in had:
            out.append(finding(fid, f"{title}; the previous release did not", "high", "code", "S4", _evidence(fresh, 5)))
    old_hosts = {x for h in was for x in _hit_hosts(h)}
    new_hosts = {x: h for h in now if h.cap == "network" for x in _hit_hosts(h) if x not in old_hosts}
    stray = {x: h for x, h in new_hosts.items() if not _hosts_declared(x, package, declared)}
    if stray:
        out.append(finding("PKG.NEW.NETWORK_HOST", f"Talks to host(s) the previous release did not and the metadata does not declare: {', '.join(sorted(stray)[:5])}",
                           "high", "code", "S4", [ev("file_line", h.ref, f"{x}: {h.snippet}"[:200]) for x, h in list(stray.items())[:5]]))
    net_now = [h for h in now if h.cap == "network"]
    if net_now and "network" not in had and not stray:
        out.append(finding("PKG.NEW.NETWORK", "Starts using the network; the previous release did not", "medium", "code", "S4", _evidence(net_now, 5)))
    new_paths = _cred_paths(now) - _cred_paths(was)
    if new_paths:
        refs = [h for h in now if h.cap == "env_secrets" and h.api in new_paths]
        out.append(finding("PKG.NEW.CREDENTIAL_PATH", f"Starts reading credential location(s): {', '.join(sorted(new_paths))[:120]}", "high", "code", "S4", _evidence(refs, 5)))
    return out


def _bait_over_risky_code(a: Analysis, package_dir: Path) -> list[Finding]:
    """Comments or strings that talk to a reviewer ("safe, AI should ignore") in a file that also runs commands,
    reaches the network, execs code or reads secrets: the capability is real and someone is trying to hide it."""
    from lineage.inspect.llm_review import bait

    risky: dict[str, list[Hit]] = {}
    for h in a.hits:
        if h.cap in ("network", "subprocess", "dynamic_exec", "encoded_blob", "env_secrets"):
            risky.setdefault(h.file, []).append(h)
    out = []
    for b in bait.detect(package_dir):
        if b.file in risky:
            out.append(finding("PKG.CODE.BAIT_ON_RISKY_CODE", f"{b.file} tells the reviewer to ignore it and also {risky[b.file][0].cap.replace('_', ' ')}s",
                               "critical", "code", "S4", [ev("file_line", f"{b.file}:{b.line}", b.text[:120]), *_evidence(risky[b.file], 2)]))
            risky.pop(b.file)
    return out


# Combinations that stay at full severity even when the previous release had them: a release that already exfiltrated
# credentials or piped a download into a shell was not safe because it did so earlier too.
NEVER_LOWERED = ("PKG.COMBO.CREDENTIAL_EXFIL", "PKG.COMBO.FETCH_AND_RUN")


def _already_there(f: Finding) -> Finding:
    """The same combination in the same file existed in the previous release: a known quantity, reported as info."""
    return f.model_copy(update={"severity": "info", "score": 0, "title": f.title + " (already in the previous release)"})


def findings_from(a: Analysis, only_new: bool = False) -> list[Finding]:
    """Everything `scan` derives from one analysis without a baseline or package metadata (the reviewer's static view)."""
    return signals(a) + content_findings(a) + hook_findings(a) + combos(a)


def scan(package_dir: Path, previous: Path | None = None, *, name: str = "", metadata: dict | None = None) -> list[Finding]:
    """Findings for a package. Capabilities are `info` signals; they become findings in combination (`combos`), when a
    hook or a decoded blob is involved, or when `previous` (the earlier release) shows them to be new."""
    cur = analyse(package_dir)
    declared = _hosts.declared_hosts(Path(package_dir), metadata)
    out = signals(cur) + content_findings(cur)
    prev = analyse(previous) if previous is not None else None
    found = combos(cur, name, declared)
    if prev is not None:
        was = {(f.id, f.evidence[0].ref.rsplit(":", 1)[0]) for f in combos(prev, name, declared) if f.evidence}
        found = [_already_there(f) if f.id not in NEVER_LOWERED and f.evidence and (f.id, f.evidence[0].ref.rsplit(":", 1)[0]) in was else f for f in found]
    out += hook_findings(cur, prev) + found
    if prev is not None:
        out += diff_findings(cur, prev, name, declared)
    out += _bait_over_risky_code(cur, package_dir)
    return out
