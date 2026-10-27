"""Extra package rules (REFACTOR_SPEC 8.2), each with a positive and a benign fixture in tests/test_package_rules.py.

- PKG.RULE.ATEXIT_EFFECT      a function registered with `atexit` that opens the network or runs a process (a file write alone is `info`: caches and logs)
- PKG.RULE.IMPORT_HOOK        insertion into `sys.meta_path` / `sys.path_hooks` (a hook that sees every later import). Precise by default: a package
                              that ships import machinery (six, pytest, pip, importlib-metadata, wrapt ...) does this legitimately, so the finding is `info`
                              unless the hook does something (network, process, code execution, a file write) or is installed from a startup file
- PKG.RULE.OBFUSCATED_TARGET  an import or call target built from string literals (reversed, joined or concatenated) that spells a dangerous module or
                              function. Built from anything that is not a literal (dnspython, scipy) it is not flagged
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

DANGEROUS_NAMES = {"os", "sys", "subprocess", "socket", "ctypes", "builtins", "importlib", "base64", "marshal", "pty", "shutil", "pickle", "urllib", "requests",
                   "system", "popen", "call", "run", "check_call", "check_output", "Popen", "exec", "eval", "compile", "__import__", "urlopen", "getoutput"}
STARTUP_FILES = {"sitecustomize.py", "usercustomize.py"}
HOOK_METHODS = {"find_spec", "find_module", "exec_module", "load_module", "create_module"}
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


def _fold(node: ast.AST) -> str | None:
    """The string a literal-only expression evaluates to (concatenation, join of literals, reversal of a literal); None if any part is not a literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _fold(node.left), _fold(node.right)
        return l + r if l is not None and r is not None else None
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and isinstance(node.slice.step, ast.UnaryOp):
        v = _fold(node.value)
        return v[::-1] if v is not None else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" and isinstance(node.func.value, ast.Constant) and node.args:
        sep, arg = node.func.value.value, node.args[0]
        if isinstance(arg, (ast.List, ast.Tuple)):
            parts = [_fold(e) for e in arg.elts]
            return sep.join(parts) if all(p is not None for p in parts) else None
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "reversed" and arg.args:
            v = _fold(arg.args[0])
            return sep.join(reversed(v)) if v is not None else None
    return None


def _built_string(node: ast.AST) -> bool:
    """A name assembled at run time from literals (reversed, joined, concatenated) that spells something dangerous. A plain literal is not
    obfuscation, and a name built from variables is how real libraries do dynamic dispatch."""
    if isinstance(node, ast.Constant):
        return False
    v = _fold(node)
    return v is not None and v in DANGEROUS_NAMES


def _hook_does_something(name_node: ast.AST, tree: ast.Module, names: Names, rel: str) -> str | None:
    """Why an import hook registered in this file is more than plumbing: its class (defined here) calls the network, a process, code execution
    or writes a file inside a finder/loader method; or the file is a startup file."""
    if Path(rel).name in STARTUP_FILES or rel.endswith(".pth"):
        return "installed from a startup file"
    target = name_node.func if isinstance(name_node, ast.Call) else name_node
    cname = target.id if isinstance(target, ast.Name) else None
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and (cname is None or n.name == cname)):
        for fn in (m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in HOOK_METHODS):
            fx = _effects(fn, names)
            for c in ast.walk(fn):
                if isinstance(c, ast.Call) and (names.dotted(c.func) or "") in {"exec", "eval", "compile", "marshal.loads", "pickle.loads", "base64.b64decode"} \
                        and not (names.dotted(c.func) == "exec" and len(c.args) > 1 and isinstance(c.args[1], ast.Attribute) and c.args[1].attr == "__dict__"):  # `exec(code, module.__dict__)` is the loader contract
                    fx.append(f"code execution ({names.dotted(c.func)})")
            if fx:
                return f"its {fn.name} does {fx[0]}"
    return None


def scan_file(pf: PyFile) -> list[Finding]:
    if pf.tree is None:
        return []
    names, fns, out = Names(pf.tree), _functions(pf.tree), []
    for n in ast.walk(pf.tree):
        # sys.meta_path / sys.path_hooks mutation
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"insert", "append", "extend"}:
            d = names.dotted(n.func.value) or ""
            if d in {"sys.meta_path", "sys.path_hooks"}:
                why = _hook_does_something(n.args[-1], pf.tree, names, pf.rel) if n.args else None
                out.append(finding("PKG.RULE.IMPORT_HOOK", f"Registers an import hook ({d}.{n.func.attr}); {why}" if why else
                                   f"Registers an import hook ({d}.{n.func.attr}); nothing in it touches the network, a process or code execution (import machinery)",
                                   "high" if why else "info", "code", "S3", [ev("file_line", f"{pf.rel}:{n.lineno}", f"{d}.{n.func.attr}")]))
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and (names.dotted(t.value) or "") in {"sys.meta_path", "sys.path_hooks"}:
                    why = _hook_does_something(n.value, pf.tree, names, pf.rel)
                    out.append(finding("PKG.RULE.IMPORT_HOOK", f"Replaces an entry of the import machinery; {why}" if why else "Replaces an entry of the import machinery (nothing in it touches the network, a process or code execution)",
                                       "high" if why else "info", "code", "S3", [ev("file_line", f"{pf.rel}:{n.lineno}", "sys.meta_path[...] =")]))
        if not isinstance(n, ast.Call):
            continue
        d = names.dotted(n.func) or ""
        # atexit
        if d == "atexit.register" and n.args:
            fn = _target_fn(n.args[0], fns)
            fx = _effects(fn, names) if fn is not None else []
            hard = [e for e in fx if e.startswith(("network", "process"))]
            if fx:
                out.append(finding("PKG.RULE.ATEXIT_EFFECT", f"A function run at interpreter exit does {(hard or fx)[0]}" + ("" if hard else " (a file write alone is ordinary: caches, logs)"),
                                   "high" if hard else "info", "code", "S3",
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
