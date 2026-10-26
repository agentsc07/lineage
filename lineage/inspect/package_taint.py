"""Intra-procedural taint slicer (source -> sink) for Python (Track C)."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from lineage.inspect import _hosts
from lineage.inspect._common import ev, finding
from lineage.inspect._pycode import Names, PyFile, iter_python
from lineage.inspect.package_capabilities import ENCODED, NETWORK, SENSITIVE_PATH, SUBPROCESS, _matches
from lineage.schemas.finding import Finding
from lineage.schemas.gpu import CodeSlice

MAX_SLICE_LINES = 80
NET_SEND_ATTRS = {"post", "put", "patch", "sendall", "sendto", "sendmail", "storbinary", "storlines"}
EXEC_SINKS = {"exec", "eval", "compile", "os.system", "os.popen", "pickle.loads", "marshal.loads", "__import__"}
FILE_READ_ATTRS = {"read", "read_text", "read_bytes", "readlines", "readline"}
# `.put()`/`.post()` is a network send only on something that is a connection. A queue, cache or pool has the same verbs.
NOT_NETWORK_RECEIVER = re.compile(r"(queue|(^|[._])q$|pool|cache|dict|stack|buffer|store|lock|heap|futures?)", re.I)
NETWORK_RECEIVER = re.compile(r"(sock|conn|session|client|http|request|smtp|ftp|api|urllib|aiohttp|httpx|s3|bucket|transport|channel|webhook)", re.I)


@dataclass(frozen=True)
class Taint:
    kind: str  # env | cred_file | file | remote | encoded
    src_line: int
    path: tuple[int, ...] = ()  # lines of statements that propagated it
    desc: str = ""


@dataclass(frozen=True)
class Flow:
    file: str
    source: Taint
    sink_kind: str  # net_send | code_exec
    sink_line: int
    sink_end: int
    sink_api: str
    hosts: tuple[str, ...] = ()  # literal destinations of a net_send sink, if the call names any

    @property
    def start(self) -> int:
        return min((self.source.src_line, *self.source.path))


# (source kind, sink kind) -> (finding id, title, severity)
_FLOWS = {
    ("cred_file", "net_send"): ("PKG.TAINT.CREDENTIAL_EXFIL", "Credential file contents flow to a network call", "critical"),
    ("env", "net_send"): ("PKG.TAINT.ENV_EXFIL", "Environment variables flow to a network host the package does not declare", "critical"),
    ("file", "net_send"): ("PKG.TAINT.FILE_UPLOAD", "File contents flow to a network call", "info"),
    ("remote", "code_exec"): ("PKG.TAINT.REMOTE_EXEC", "Data fetched from the network is executed", "critical"),
    ("encoded", "code_exec"): ("PKG.TAINT.ENCODED_EXEC", "A decoded blob is executed", "critical"),
}


class _Scope:
    """Walks one function body (or module top level) in source order."""

    def __init__(self, pf: PyFile, names: Names, consts: dict[str, str] | None = None, blobs: set[str] | None = None):
        self.pf, self.names = pf, names
        self.consts = consts or {}  # NAME = "literal"
        self.blobs = blobs or set()  # names bound to a long literal string/bytes (an embedded blob)
        self.conn_hosts: dict[str, tuple[str, ...]] = {}  # s = socket.create_connection(("host", 9)): later s.sendall(...) goes there
        self.env: dict[str, set[Taint]] = {}
        self.flows: list[Flow] = []

    # --- expression taint
    def _source_of_call(self, call: ast.Call) -> Taint | None:
        d = self.names.dotted(call.func) or ""
        line = call.lineno
        if d in ("os.getenv", "os.getenvb"):
            return Taint("env", line, desc=d)
        if d == "open" or d.startswith("pathlib.Path"):
            args = ast.walk(ast.Tuple(elts=call.args, ctx=ast.Load()))
            sensitive = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and SENSITIVE_PATH.search(n.value)
                            for n in args)
            if d == "open" or d.rsplit(".", 1)[-1] in FILE_READ_ATTRS:
                return Taint("cred_file" if sensitive else "file", line, desc=d)
        if d.rsplit(".", 1)[-1] in FILE_READ_ATTRS and d.startswith(("open()", "pathlib.Path()")):
            return Taint("file", line, desc=d)
        if _matches(d, NETWORK) and not d.startswith("socket.socket") and d.rsplit(".", 1)[-1] not in NET_SEND_ATTRS:
            return Taint("remote", line, desc=d)
        if d.endswith((".recv", ".recvfrom", ".recv_into")):
            return Taint("remote", line, desc=d)
        if d in ENCODED and d != "zlib.compress" and self._embedded(call):
            return Taint("encoded", line, desc=d)
        return None

    def _embedded(self, call: ast.Call) -> bool:
        """Is the thing being decoded written into the source? Decoding a literal blob and running it is a payload;
        decoding data that arrives at run time (a cache file, a parameter) is ordinary."""
        for sub in ast.walk(ast.Tuple(elts=call.args, ctx=ast.Load())):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, (str, bytes)) and len(sub.value) >= 16:
                return True
            if isinstance(sub, ast.Name) and sub.id in self.blobs:
                return True
        return False

    def _netish(self, d: str) -> bool:
        base = d.rsplit(".", 1)[0] if "." in d else ""
        if _matches(d, NETWORK) or base in self.conn_hosts:
            return True
        return bool(NETWORK_RECEIVER.search(base)) and not NOT_NETWORK_RECEIVER.search(base)

    def _sink_hosts(self, call: ast.Call) -> tuple[str, ...]:
        found: set[str] = set(self.conn_hosts.get((self.names.dotted(call.func) or "").split(".")[0], ()))
        for a in call.args[:1]:  # connection constructors take the host as the first argument or first tuple element
            for sub in ([a] if not isinstance(a, ast.Tuple) else a.elts[:1]):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _hosts.looks_like_host(sub.value):
                    found.add(sub.value.lower())
        for v in [*call.args, *[k.value for k in call.keywords]]:
            for sub in ast.walk(v):
                text = sub.value if isinstance(sub, ast.Constant) and isinstance(sub.value, str) else self.consts.get(sub.id) if isinstance(sub, ast.Name) else None
                if text:
                    found |= _hosts.hosts_in_text(text)
        return tuple(sorted(found))

    def taint_of(self, node: ast.AST | None) -> set[Taint]:
        if node is None:
            return set()
        out: set[Taint] = set()
        if isinstance(node, ast.Attribute) and (self.names.dotted(node) or "") in ("os.environ", "os.environb"):
            out.add(Taint("env", node.lineno, desc="os.environ"))
        elif isinstance(node, ast.Name):
            out |= self.env.get(node.id, set())
        elif isinstance(node, ast.Attribute):
            d = self.names.dotted(node)
            if d and d in self.env:
                out |= self.env[d]
        if isinstance(node, ast.Call):
            src = self._source_of_call(node)
            if src:
                out.add(src)
            if isinstance(node.func, ast.Attribute):  # receiver taint flows through methods: x.encode(), f.read()
                out |= self.taint_of(node.func.value)
            for a in node.args:
                out |= self.taint_of(a)
            for k in node.keywords:
                out |= self.taint_of(k.value)
            return out
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return out
        for child in ast.iter_child_nodes(node):
            out |= self.taint_of(child)
        return out

    # --- sinks
    def _check_sinks(self, expr: ast.AST) -> None:
        for call in (n for n in ast.walk(expr) if isinstance(n, ast.Call)):
            d = self.names.dotted(call.func) or ""
            attr = d.rsplit(".", 1)[-1]
            if d in EXEC_SINKS or _matches(d, SUBPROCESS):
                kind = "code_exec"
            elif (_matches(d, NETWORK) and not d.endswith((".recv", ".recvfrom"))) or (attr in NET_SEND_ATTRS and self._netish(d)) or (
                attr == "send" and "sock" in d.lower()
            ):
                kind = "net_send"
            else:
                continue
            args: set[Taint] = set()
            for a in call.args:
                args |= self.taint_of(a)
            for k in call.keywords:
                args |= self.taint_of(k.value)
            # data passed to exec(b64decode("...")) is tainted by the nested decode call itself
            for t in args:
                if t.src_line == call.lineno and t.desc == d:
                    continue  # the sink's own result is not its input
                if (t.kind, kind) in _FLOWS:
                    self.flows.append(Flow(self.pf.rel, t, kind, call.lineno, call.end_lineno or call.lineno, d or attr,
                                           self._sink_hosts(call) if kind == "net_send" else ()))

    # --- statements
    def _bind(self, target: ast.AST, taint: set[Taint], line: int) -> None:
        if isinstance(target, ast.Name):
            key = target.id
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self._bind(t, taint, line)
            return
        elif isinstance(target, ast.Subscript):
            return self._bind(target.value, taint, line)
        elif isinstance(target, ast.Attribute):
            key = self.names.dotted(target) or ""
            if not key:
                return
        else:
            return
        moved = {Taint(t.kind, t.src_line, t.path + (line,), t.desc) for t in taint}
        if isinstance(target, (ast.Name, ast.Attribute)) and not isinstance(target.ctx, ast.Store):
            return
        self.env[key] = (self.env.get(key, set()) | moved) if moved else self.env.get(key, set())

    def run(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # separate scope
            self._stmt(stmt)

    def _stmt(self, s: ast.stmt) -> None:
        header: list[ast.AST] = []
        if isinstance(s, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = s.value
            if value is not None:
                self._check_sinks(value)
                if isinstance(value, ast.Call) and _matches(self.names.dotted(value.func) or "", NETWORK) and isinstance(s, ast.Assign):
                    hosts = self._sink_hosts(value)
                    for tg in s.targets:
                        if isinstance(tg, ast.Name) and hosts:
                            self.conn_hosts[tg.id] = hosts
                t = self.taint_of(value)
                targets = s.targets if isinstance(s, ast.Assign) else [s.target]
                for tg in targets:
                    self._bind(tg, t, s.lineno)
            return
        if isinstance(s, (ast.For, ast.AsyncFor)):
            self._check_sinks(s.iter)
            self._bind(s.target, self.taint_of(s.iter), s.lineno)
            for _ in range(2):
                self.run(s.body)
            self.run(s.orelse)
            return
        if isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                self._check_sinks(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, self.taint_of(item.context_expr), s.lineno)
            self.run(s.body)
            return
        if isinstance(s, (ast.If, ast.While)):
            header = [s.test]
        elif isinstance(s, ast.Try):
            for blk in (s.body, *[h.body for h in s.handlers], s.orelse, s.finalbody):
                self.run(blk)
            return
        elif isinstance(s, (ast.Expr, ast.Return, ast.Raise, ast.Assert, ast.Delete)):
            header = [c for c in ast.iter_child_nodes(s)]
        for h in header:
            self._check_sinks(h)
        if isinstance(s, ast.If):
            self.run(s.body)
            self.run(s.orelse)
        elif isinstance(s, ast.While):
            for _ in range(2):
                self.run(s.body)
            self.run(s.orelse)


def _scopes(tree: ast.Module):
    yield tree.body
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body


def flows(package_dir: Path) -> list[tuple[Flow, PyFile]]:
    out, seen = [], set()
    for pf in iter_python(Path(package_dir)):
        if pf.tree is None:
            continue
        names = Names(pf.tree)
        consts, blobs = {}, set()
        for n in ast.walk(pf.tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, (str, bytes)):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        if isinstance(n.value.value, str):
                            consts[t.id] = n.value.value
                        if len(n.value.value) >= 16:
                            blobs.add(t.id)
        for body in _scopes(pf.tree):
            sc = _Scope(pf, names, consts, blobs)
            sc.run(body)
            for f in sc.flows:
                key = (f.file, f.sink_line, f.source.kind)
                if key not in seen:
                    seen.add(key)
                    out.append((f, pf))
    return sorted(out, key=lambda x: (x[0].file, x[0].sink_line))


def slices(package_dir: Path) -> list[CodeSlice]:
    """Source->sink slices; only these are sent to the LLM reviewer."""
    out: list[CodeSlice] = []
    for f, pf in flows(package_dir):
        lines = pf.text.splitlines()
        start, end = f.start, max(f.sink_end, f.sink_line)
        start = max(start, end - MAX_SLICE_LINES + 1)
        out.append(CodeSlice(file=f.file, start=start, end=end, code="\n".join(lines[start - 1:end])))
    return out


def scan(package_dir: Path, name: str = "", metadata: dict | None = None) -> list[Finding]:
    """Flows that matter. A token sent to a host the package's metadata declares (its own vendor's API) is the product
    working, and a destination the caller supplies is the library's interface; neither is exfiltration."""
    declared = _hosts.declared_hosts(Path(package_dir), metadata)
    out: list[Finding] = []
    for f, pf in flows(package_dir):
        fid, title, sev = _FLOWS[(f.source.kind, f.sink_kind)]
        if f.source.kind == "env" and f.sink_kind == "net_send":
            stray = [h for h in f.hosts if not _hosts.is_declared(h, name, declared)]
            if not stray:
                continue  # no destination named in the call (caller-supplied) or only the vendor's own
        src = f"{f.file}:{f.source.src_line}"
        out.append(finding(fid, title, sev, "code", "S4", [
            ev("file_line", src, f"source: {f.source.desc}"),
            ev("file_line", f"{f.file}:{f.sink_line}", f"sink: {f.sink_api}"),
        ]))
    return out
