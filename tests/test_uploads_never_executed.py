"""F6: nothing that inspects an uploaded artifact imports, runs, unpickles or installs it. This is a source-level guard: a new call to one of
these primitives in production code fails the test until it is reviewed and added to ALLOWED with a reason."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRODUCTION = ["lineage", "lineage_server", "mcp_gateway", "gpu_worker"]
DANGEROUS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "os.system", "os.popen",
    "os.execv", "os.execve", "os.execvp", "pickle.load", "pickle.loads", "pickle.Unpickler", "dill.load", "dill.loads", "cloudpickle.load",
    "joblib.load", "torch.load", "marshal.loads", "exec", "eval", "compile", "__import__", "importlib.import_module", "runpy.run_path",
    "runpy.run_module", "importlib.util.spec_from_file_location", "ctypes.CDLL", "ctypes.cdll.LoadLibrary",
}
# path -> why it is not "executing an upload"
ALLOWED = {
    "lineage/run.py": "`lineage run` runs the user's own command by design; it never touches registry uploads",
    "lineage/inspect/package_previous.py": "`pip download --no-deps --only-binary=:all:` of the PUBLIC previous release (a wheel is never built or imported); not the upload",
    "lineage/cli.py": "the CLI's own commands (no upload content)",
    "lineage/hashing/bench.py": "benchmark helper over synthetic files",
    "lineage_server/seed.py": "demo seed data writes inert payload text; nothing is run",
    "lineage_server/mock.py": "demo mock data",
    "gpu_worker/train_lora_bank.py": "offline training tool run by an engineer; asks nvidia-smi for the GPU name",
    "lineage/inspect/package_taint.py": "string constants naming sinks it looks for, not calls",
}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""  # a method on a call result such as `model.cuda().eval()` is not the builtin


def _calls(path: Path) -> list[tuple[str, int]]:
    out = []
    for n in ast.walk(ast.parse(path.read_text())):
        if isinstance(n, ast.Call) and _dotted(n.func) in DANGEROUS:
            out.append((_dotted(n.func), n.lineno))
    return out


def test_no_production_module_runs_imports_or_unpickles_what_it_inspects():
    offenders = {}
    for top in PRODUCTION:
        for p in sorted((ROOT / top).rglob("*.py")):
            rel = p.relative_to(ROOT).as_posix()
            hits = _calls(p)
            if hits and rel not in ALLOWED:
                offenders[rel] = hits
    assert not offenders, f"execution primitives outside the reviewed allow-list: {offenders}"


def test_the_pickle_scanner_only_disassembles_opcodes():
    src = (ROOT / "lineage/inspect/model_pickle.py").read_text()
    assert "pickletools" in src
    assert not _calls(ROOT / "lineage/inspect/model_pickle.py")
