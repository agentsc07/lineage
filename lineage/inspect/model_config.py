"""Model config scanner: trust_remote_code, auto_map (collects .py files for code review) (Track C)."""
from __future__ import annotations

import json
from pathlib import Path

from lineage.inspect import package_capabilities, package_taint
from lineage.inspect._common import ev, finding
from lineage.schemas.finding import Finding

CONFIG_FILES = ("config.json", "tokenizer_config.json", "preprocessor_config.json", "processor_config.json",
                "generation_config.json", "adapter_config.json")


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _auto_map_targets(value) -> list[str]:
    """auto_map values are 'module.Class', 'repo--module.Class', or a [slow, fast] pair of those."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for x in value for v in _auto_map_targets(x)]
    return []


def auto_map_files(model_dir: Path) -> dict[str, list[str]]:
    """config file -> custom-code targets named by its auto_map."""
    found: dict[str, list[str]] = {}
    for name in CONFIG_FILES:
        targets = [t for v in (_load(model_dir / name).get("auto_map") or {}).values() for t in _auto_map_targets(v)]
        if targets:
            found[name] = targets
    return found


def remote_code_files(model_dir: Path) -> list[Path]:
    """The .py files that would execute if the model is loaded with trust_remote_code: for code review."""
    model_dir = Path(model_dir)
    files = {p for p in model_dir.rglob("*.py") if ".git" not in p.parts}
    for targets in auto_map_files(model_dir).values():
        for t in targets:
            if "--" in t:
                continue  # code lives in another repo; reported as a finding instead
            module = t.rsplit(".", 1)[0]
            p = model_dir / (module.replace(".", "/") + ".py")
            if p.exists():
                files.add(p)
    return sorted(files)


def scan(model_dir: Path) -> list[Finding]:
    model_dir = Path(model_dir)
    out: list[Finding] = []
    for name in CONFIG_FILES:
        cfg = _load(model_dir / name)
        if cfg.get("trust_remote_code") is True:
            out.append(finding("MODEL.CONFIG.TRUST_REMOTE_CODE", f"{name} sets trust_remote_code=true", "high", "model", "S3",
                               [ev("field", f"{name}#trust_remote_code", "true")]))
    for name, targets in auto_map_files(model_dir).items():
        external = [t for t in targets if "--" in t]
        local = [t for t in targets if "--" not in t]
        missing = [t for t in local if not (model_dir / (t.rsplit(".", 1)[0].replace(".", "/") + ".py")).exists()]
        out.append(finding("MODEL.CONFIG.AUTO_MAP", f"{name} maps classes to custom code that runs on load", "high" if local or external else "medium",
                           "model", "S3", [ev("field", f"{name}#auto_map", t) for t in targets[:8]]))
        if external:
            out.append(finding("MODEL.CONFIG.EXTERNAL_CODE", "auto_map pulls code from a different repository", "high", "model", "S3",
                               [ev("field", f"{name}#auto_map", t) for t in external]))
        if missing:
            out.append(finding("MODEL.CONFIG.AUTO_MAP_MISSING", "auto_map references code files that are not in the model directory",
                               "medium", "model", "S3", [ev("field", f"{name}#auto_map", t) for t in missing]))
    code = remote_code_files(model_dir)
    if code:
        out.append(finding("MODEL.CONFIG.CUSTOM_CODE", f"{len(code)} custom Python file(s) ship with the model and need code review",
                           "medium", "model", "S3", [ev("file_line", f"{p.relative_to(model_dir).as_posix()}:1") for p in code[:10]]))
        out.extend(package_capabilities.scan(model_dir))
        out.extend(package_taint.scan(model_dir))
    return out
