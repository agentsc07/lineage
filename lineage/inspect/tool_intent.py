"""Intent gap: extracted code capabilities vs declared permissions in the tool manifest (Track C)."""
from __future__ import annotations

import json
from pathlib import Path

from lineage.inspect import package_capabilities
from lineage.inspect._common import ev, finding
from lineage.schemas.finding import Finding

# capability -> (permission keywords that declare it, severity if undeclared)
_RULES = {
    "network": (("net", "http", "web", "internet", "fetch", "socket", "url", "request"), "high"),
    "filesystem": (("fs", "file", "disk", "read", "write", "path", "dir", "storage"), "medium"),
    "subprocess": (("exec", "shell", "process", "command", "spawn", "run", "bash"), "high"),
    "env_secrets": (("env", "secret", "credential", "token", "key", "password"), "high"),
    "dynamic_exec": (("eval", "dynamic", "code", "exec"), "high"),
    "encoded_blob": ((), "high"),
    "obfuscation": ((), "high"),
}
_TITLES = {
    "network": "opens network connections",
    "filesystem": "reads or writes files",
    "subprocess": "runs subprocesses",
    "env_secrets": "reads environment variables or credential files",
    "dynamic_exec": "executes dynamically built code",
    "encoded_blob": "decodes encoded blobs",
    "obfuscation": "uses obfuscation",
}


def declared_permissions(manifest: dict) -> list[str]:
    perms = manifest.get("permissions", [])
    if isinstance(perms, dict):  # {"network": true, "filesystem": "read"}
        perms = [k for k, v in perms.items() if v]
    if isinstance(perms, str):
        perms = [perms]
    return [str(p).lower() for p in perms]


def is_declared(capability: str, perms: list[str]) -> bool:
    return any(k in p for p in perms for k in _RULES[capability][0])


def scan(manifest_path: Path, code_dir: Path) -> list[Finding]:
    try:
        manifest = json.loads(Path(manifest_path).read_text())
    except (OSError, json.JSONDecodeError):
        manifest = {}
    perms = declared_permissions(manifest if isinstance(manifest, dict) else {})
    caps = package_capabilities.extract(code_dir)
    out: list[Finding] = []
    for cap, (_, sev) in _RULES.items():
        refs = caps.get(cap)
        if refs and not is_declared(cap, perms):
            out.append(finding(f"TOOL.INTENT.UNDECLARED_{cap.upper()}", f"Tool code {_TITLES[cap]} but its manifest does not declare it", sev,
                               "tool", "S4", [ev("file_line", r) for r in refs[:8]]
                               + [ev("field", f"{Path(manifest_path).name}#permissions", f"declared: {perms or 'none'}")]))
    for hook in ("startup_hook", "network_at_install", "install_exec"):
        if caps.get(hook):
            out.append(finding(f"TOOL.INTENT.{hook.upper()}", f"Tool ships {hook.replace('_', ' ')} code that a tool never needs", "critical",
                               "tool", "S4", [ev("file_line", r) for r in caps[hook][:5]]))
    for cap, (kw, _) in _RULES.items():
        if kw and any(k in p for p in perms for k in kw) and not caps.get(cap):
            declared = [p for p in perms if any(k in p for k in kw)]
            out.append(finding(f"TOOL.INTENT.UNUSED_{cap.upper()}", f"Manifest declares {declared} but the code never uses {cap}", "info",
                               "tool", "S4", [ev("field", f"{Path(manifest_path).name}#permissions", ", ".join(declared))]))
    return out
