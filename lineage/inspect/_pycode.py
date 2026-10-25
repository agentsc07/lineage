"""Python source loading and name resolution shared by the capability extractor and the taint slicer."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache"}
MAX_BYTES = 2_000_000


@dataclass
class PyFile:
    rel: str  # path relative to the scanned root, posix style
    path: Path
    text: str
    tree: ast.Module | None  # None if the source does not parse
    kind: str  # "py" | "pth"


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS):
            yield p


def _pth_tree(text: str) -> ast.Module:
    """Executable lines of a .pth file (those starting with `import`) as one module, keeping line numbers."""
    body: list[ast.stmt] = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith(("import ", "import\t")):
            try:
                sub = ast.parse(line.strip())
            except SyntaxError:
                continue
            ast.increment_lineno(sub, n - 1)
            body.extend(sub.body)
    return ast.Module(body=body, type_ignores=[])


def iter_python(root: Path) -> list[PyFile]:
    out: list[PyFile] = []
    base = root.parent if root.is_file() else root
    for p in _walk(root):
        if p.suffix not in (".py", ".pth") or p.stat().st_size > MAX_BYTES:
            continue
        text = p.read_text(errors="replace")
        rel = p.relative_to(base).as_posix()
        if p.suffix == ".pth":
            out.append(PyFile(rel, p, text, _pth_tree(text), "pth"))
            continue
        try:
            tree: ast.Module | None = ast.parse(text)
        except (SyntaxError, ValueError):
            tree = None
        out.append(PyFile(rel, p, text, tree, "py"))
    return out


class Names:
    """Resolves Name/Attribute/Call chains to dotted names, expanding import aliases.

    `open(p).read` -> "open().read"; `from urllib.request import urlopen as u; u(x)` -> "urllib.request.urlopen".
    """

    def __init__(self, tree: ast.AST):
        self.alias: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.alias[a.asname or a.name] = f"{node.module}.{a.name}"

    def dotted(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.dotted(node.func)
            return f"{base}()" if base else None
        return None


def line_text(text_lines: list[str], line: int, width: int = 160) -> str:
    return text_lines[line - 1].strip()[:width] if 0 < line <= len(text_lines) else ""
