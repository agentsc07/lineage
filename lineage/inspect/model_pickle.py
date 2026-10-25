"""Pickle-opcode scanner: GLOBAL/STACK_GLOBAL/REDUCE to os/subprocess/builtins/etc. (Track C).

Never unpickles anything: it only walks the opcode stream with `pickletools.genops`.
"""
from __future__ import annotations

import io
import pickletools
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from lineage.inspect._common import ev, finding
from lineage.schemas.finding import Finding

PICKLE_SUFFIXES = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"}
MAX_MEMBER = 256 * 1024 * 1024

# Modules whose every attribute is dangerous to reach from a pickle.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "socket", "pty", "ctypes", "shutil", "webbrowser", "runpy", "importlib",
    "sys", "marshal", "code", "codeop", "commands", "pip", "requests", "urllib", "urllib2", "urllib3", "http",
    "httplib", "ftplib", "smtplib", "telnetlib", "asyncio", "multiprocessing", "threading", "signal", "platform",
    "pickle", "_pickle", "dill", "cloudpickle", "torch.hub", "torch.distributed", "zipimport", "tempfile",
    "glob", "fileinput", "pathlib", "io", "inspect", "types", "operator", "functools", "base64",
    "binascii", "zlib", "bz2", "lzma", "pydoc", "timeit", "cProfile", "profile", "trace", "doctest",
}
DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "__import__", "open", "input", "breakpoint", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "memoryview", "help", "exit", "quit",
}
SAFE_EXACT = {
    ("collections", "OrderedDict"), ("collections", "defaultdict"), ("collections", "deque"), ("copyreg", "_reconstructor"),
    ("_codecs", "encode"), ("torch", "Size"), ("torch", "device"), ("torch", "dtype"),
    ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "dict"), ("builtins", "list"), ("builtins", "tuple"),
    ("builtins", "slice"), ("builtins", "complex"), ("builtins", "bytearray"), ("builtins", "int"),
    ("builtins", "float"), ("builtins", "str"), ("builtins", "bytes"), ("builtins", "bool"), ("builtins", "range"),
    ("numpy", "dtype"), ("numpy", "ndarray"), ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"), ("numpy._core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "scalar"),
    ("numpy.core.numeric", "_frombuffer"), ("numpy._core.numeric", "_frombuffer"),
    ("torch._utils", "_rebuild_tensor_v2"), ("torch._utils", "_rebuild_tensor"), ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_device_tensor_from_numpy"), ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch.nn.parameter", "Parameter"), ("torch.serialization", "_get_layout"),
}
SAFE_PREFIXES = ("torch.storage", "torch.nn.modules", "torch.nn.parameter")
STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
GET_OPS = {"BINGET", "LONG_BINGET", "GET"}
PUT_OPS = {"BINPUT", "LONG_BINPUT", "PUT"}
CALL_OPS = {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST", "BUILD"}


@dataclass
class Global:
    module: str
    name: str
    pos: int
    opcode: str
    called: bool = False
    argument: str = ""  # last string pushed before the call, e.g. the shell command


@dataclass
class Scan:
    globals: list[Global] = field(default_factory=list)
    unresolved: list[int] = field(default_factory=list)
    error: str | None = None


def classify(module: str, name: str) -> str:
    """dangerous | safe | unknown"""
    if module in ("builtins", "__builtin__"):
        return "dangerous" if name in DANGEROUS_BUILTINS else "safe" if ("builtins", name) in SAFE_EXACT else "unknown"
    if (module, name) in SAFE_EXACT or module.startswith(SAFE_PREFIXES):
        return "safe"
    top = module.split(".")[0]
    if module in DANGEROUS_MODULES or top in DANGEROUS_MODULES:
        return "dangerous"
    return "unknown"


def _scan_one(stream: BinaryIO, out: Scan) -> bool:
    """Walk one pickle; True if the stream continues with another pickle (legacy torch files concatenate several)."""
    recent: list[str] = []
    memo: dict[int, str] = {}
    stack_globals: list[Global] = []
    for op, arg, pos in pickletools.genops(stream):
        name = op.name
        if name in STRING_OPS and isinstance(arg, (str, bytes)):
            recent.append(arg.decode(errors="replace") if isinstance(arg, bytes) else arg)
        elif name in GET_OPS and arg in memo:
            recent.append(memo[arg])
        elif name == "MEMOIZE" and recent:
            memo[len(memo)] = recent[-1]
        elif name in PUT_OPS and recent:
            memo[arg] = recent[-1]
        elif name == "GLOBAL" and isinstance(arg, str):
            mod, _, attr = arg.partition(" ")
            g = Global(mod, attr, pos, "GLOBAL")
            out.globals.append(g)
            stack_globals.append(g)
        elif name == "INST" and isinstance(arg, str):
            mod, _, attr = arg.partition(" ")
            g = Global(mod, attr, pos, "INST", called=True, argument=recent[-1] if recent else "")
            out.globals.append(g)
        elif name == "STACK_GLOBAL":
            if len(recent) >= 2:
                g = Global(recent[-2], recent[-1], pos, "STACK_GLOBAL")
                out.globals.append(g)
                stack_globals.append(g)
            else:
                out.unresolved.append(pos)
        elif name in CALL_OPS and name != "BUILD":
            # Which global a REDUCE applies to depends on stack depth; treat every global seen so far as called.
            for g in stack_globals:
                if not g.called:
                    g.called = True
                    g.argument = recent[-1] if recent and recent[-1] != g.name else ""
    rest = stream.read(1)
    return rest == b"\x80"  # next pickle starts with a PROTO opcode


def scan_stream(data: BinaryIO) -> Scan:
    out = Scan()
    try:
        while True:
            more = _scan_one(data, out)
            if not more:
                break
            data.seek(data.tell() - 1)
    except Exception as e:  # malformed or deliberately mangled opcode stream
        if not out.globals:
            out.error = f"{type(e).__name__}: {e}"[:200]
        else:
            out.error = None
    return out


def _looks_like_pickle(head: bytes) -> bool:
    return head[:1] == b"\x80" or head[:2] == b"PK" or head[:1] in (b"(", b"]", b"}", b"c", b"S", b"I")


def _members(path: Path):
    """(label, stream) for each pickle inside a file: the file itself, or each *.pkl in a torch zip."""
    with path.open("rb") as f:
        head = f.read(4)
    if head[:2] == b"PK" and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.filename.endswith((".pkl", "/data.pkl")) and info.file_size <= MAX_MEMBER:
                    yield f"{path.name}!{info.filename}", io.BytesIO(z.read(info))
        return
    if path.suffix == ".bin" and not _looks_like_pickle(head):
        return  # e.g. GGUF or raw weights
    with path.open("rb") as f:
        yield path.name, f


def _files(path: Path):
    if path.is_file():
        yield path
        return
    for p in sorted(path.rglob("*")):
        if p.is_file() and p.suffix in PICKLE_SUFFIXES and ".git" not in p.parts:
            yield p


def scan(path: Path) -> list[Finding]:
    """`path` is a pickle/torch file or a model directory."""
    path = Path(path)
    out: list[Finding] = []
    for p in _files(path):
        rel = p.name if path.is_file() else p.relative_to(path).as_posix()
        any_pickle = False
        for label, stream in _members(p):
            any_pickle = True
            label = label.replace(p.name, rel, 1)
            res = scan_stream(stream)
            out.extend(_findings(label, res))
        if any_pickle:
            out.append(finding("MODEL.PICKLE.PRESENT", f"{rel} uses the pickle format (prefer safetensors)", "low", "model", "S3",
                               [ev("field", rel, "pickle-based weights can run code when loaded")]))
    return out


def _findings(label: str, res: Scan) -> list[Finding]:
    out: list[Finding] = []
    if res.error:
        return [finding("MODEL.PICKLE.UNPARSEABLE", f"{label}: pickle stream cannot be parsed", "medium", "model", "S3",
                        [ev("field", label, res.error)])]
    dangerous = [g for g in res.globals if classify(g.module, g.name) == "dangerous"]
    unknown = [g for g in res.globals if classify(g.module, g.name) == "unknown"]
    for g in dangerous:
        sev = "critical" if g.called else "high"
        detail = f"{g.opcode} {g.module}.{g.name}" + (f" called with {g.argument[:120]!r}" if g.argument else "")
        out.append(finding("MODEL.PICKLE.DANGEROUS_GLOBAL",
                           f"{label}: pickle {'calls' if g.called else 'references'} {g.module}.{g.name}", sev, "model", "S3",
                           [ev("field", f"{label}@{g.pos}", detail)]))
    if res.unresolved:
        out.append(finding("MODEL.PICKLE.UNRESOLVED_GLOBAL", f"{label}: STACK_GLOBAL with non-literal module/name", "high",
                           "model", "S3", [ev("field", f"{label}@{p}", "STACK_GLOBAL") for p in res.unresolved[:5]]))
    if unknown:
        names = sorted({f"{g.module}.{g.name}" for g in unknown})
        out.append(finding("MODEL.PICKLE.UNKNOWN_GLOBAL", f"{label}: pickle imports {len(names)} unrecognised global(s)", "low",
                           "model", "S3", [ev("field", f"{label}@{g.pos}", f"{g.module}.{g.name}") for g in unknown[:5]]))
    return out
