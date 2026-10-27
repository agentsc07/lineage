"""Extra package rules (REFACTOR_SPEC 8.2), each with a positive and a benign fixture in tests/test_package_rules.py.

- PKG.RULE.ATEXIT_EFFECT      a function registered with `atexit` that writes files, opens the network or runs a process
- PKG.RULE.IMPORT_HOOK        insertion into `sys.meta_path` / `sys.path_hooks` (a hook that sees every later import)
- PKG.RULE.OBFUSCATED_TARGET  an import or call target built at run time: reversed, joined or concatenated string constants
- PKG.RULE.GIT_HOOK_WRITE     writing into `.git/hooks/` (code that runs on the developer's next commit)
- PKG.RULE.BEACON_THREAD      a daemon thread looping over a network call (a beacon)
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._pycode import Names, PyFile, iter_python
from lineage.inspect.package_capabilities import NETWORK, SUBPROCESS, _matches
from lineage.schemas.finding import Finding

GIT_HOOKS = re.compile(r"\.git[/\\]hooks")
WRITES = {"write_text", "write_bytes", "write", "copy", "copyfile", "copy2", "chmod", "symlink", "move", "replace", "rename"}


def _functions(tree: ast.Module) -> dict[str, ast.AST]:
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _effects(node: ast.AST, names: Names) -> list[str]:
    """What a function body does that matters at exit or in a loop: network, a process, a file write."""
    out = []
    for c in ast.walk(node):
        if not isinstance(c, ast.Call):
            continue
        d = names.dotted(c.func) or ""
        if _matches(d, NETWORK):
            out.append(f"network ({d})")
        elif _matches(d, SUBPROCESS):
            out.append(f"process ({d})")
        elif d == "open" and len(c.args) > 1 and isinstance(c.args[1], ast.Constant) and any(m in str(c.args[1].value) for m in "wax+"):
            out.append("file write (open)")
        elif d.rsplit(".", 1)[-1] in {"write_text", "write_bytes"}:
            out.append(f"file write ({d.rsplit('.', 1)[-1]})")
    return out


def _target_fn(arg: ast.AST, fns: dict[str, ast.AST]) -> ast.AST | None:
    if isinstance(arg, ast.Name):
        return fns.get(arg.id)
    if isinstance(arg, ast.Lambda):
        return arg
    return None


def _built_string(node: ast.AST) -> bool:
    """A string assembled at run time from literals: reversed, joined or concatenated."""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and isinstance(node.slice.step, ast.UnaryOp):
        return isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)  # "sys"[::-1]
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "join" and isinstance(f.value, ast.Constant) and node.args and isinstance(node.args[0], (ast.List, ast.Tuple, ast.GeneratorExp, ast.ListComp)):
            return True  # "".join(["o", "s"]) / "".join(reversed("so"))
        if isinstance(f, ast.Name) and f.id in {"reversed", "chr"} and node.args:
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = [node.left, node.right]
        return all(isinstance(p, ast.Constant) and isinstance(p.value, str) or isinstance(p, ast.BinOp) for p in parts) and isinstance(node.left, (ast.Constant, ast.BinOp))
    return False


def scan_file(pf: PyFile) -> list[Finding]:
    if pf.tree is None:
        return []
    names, fns, out = Names(pf.tree), _functions(pf.tree), []
    for n in ast.walk(pf.tree):
        # sys.meta_path / sys.path_hooks mutation
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"insert", "append", "extend"}:
            d = names.dotted(n.func.value) or ""
            if d in {"sys.meta_path", "sys.path_hooks"}:
                out.append(finding("PKG.RULE.IMPORT_HOOK", f"Registers an import hook ({d}.{n.func.attr}): it sees every later import in the process", "high", "code", "S3",
                                   [ev("file_line", f"{pf.rel}:{n.lineno}", f"{d}.{n.func.attr}")]))
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and (names.dotted(t.value) or "") in {"sys.meta_path", "sys.path_hooks"}:
                    out.append(finding("PKG.RULE.IMPORT_HOOK", "Replaces an entry of the import machinery", "high", "code", "S3", [ev("file_line", f"{pf.rel}:{n.lineno}", "sys.meta_path[...] =")]))
        if not isinstance(n, ast.Call):
            continue
        d = names.dotted(n.func) or ""
        # atexit
        if d == "atexit.register" and n.args:
            fn = _target_fn(n.args[0], fns)
            fx = _effects(fn, names) if fn is not None else []
            if fx:
                out.append(finding("PKG.RULE.ATEXIT_EFFECT", f"A function run at interpreter exit does {fx[0]}", "high", "code", "S3",
                                   [ev("file_line", f"{pf.rel}:{n.lineno}", "atexit.register(" + (n.args[0].id if isinstance(n.args[0], ast.Name) else "lambda") + ")")]))
        # obfuscated import / call target
        if (d in {"__import__", "importlib.import_module"} and n.args and _built_string(n.args[0])) or \
                (d == "getattr" and len(n.args) >= 2 and _built_string(n.args[1])):
            out.append(finding("PKG.RULE.OBFUSCATED_TARGET", f"{d}() with a name assembled at run time (reversed, joined or concatenated literals)", "high", "code", "S3",
                               [ev("file_line", f"{pf.rel}:{n.lineno}", d)]))
        # writing into .git/hooks
        last = d.rsplit(".", 1)[-1]
        if (d == "open" or last in WRITES or d.startswith(("shutil.", "os.", "pathlib."))) and any(
                isinstance(c, ast.Constant) and isinstance(c.value, str) and GIT_HOOKS.search(c.value) for a in [*n.args, *[k.value for k in n.keywords]] for c in ast.walk(a)):
            out.append(finding("PKG.RULE.GIT_HOOK_WRITE", "Writes into .git/hooks: code that runs on the developer's next git command", "high", "code", "S3",
                               [ev("file_line", f"{pf.rel}:{n.lineno}", d)]))
        # beacon: daemon thread whose target loops over a network call
        if d in {"threading.Thread", "Thread"}:
            kw = {k.arg: k.value for k in n.keywords}
            daemon = isinstance(kw.get("daemon"), ast.Constant) and kw["daemon"].value is True
            fn = _target_fn(kw["target"], fns) if "target" in kw else None
            if daemon and fn is not None and any(isinstance(c, (ast.While, ast.For)) for c in ast.walk(fn)):
                fx = [e for e in _effects(fn, names) if e.startswith("network")]
                if fx:
                    out.append(finding("PKG.RULE.BEACON_THREAD", f"A daemon thread loops over a network call ({fx[0]}): a beacon", "high", "code", "S3",
                                       [ev("file_line", f"{pf.rel}:{n.lineno}", "threading.Thread(daemon=True)")]))
    return out


def scan(package_dir: Path) -> list[Finding]:
    out: list[Finding] = []
    for pf in iter_python(Path(package_dir)):
        out += scan_file(pf)
    return out
