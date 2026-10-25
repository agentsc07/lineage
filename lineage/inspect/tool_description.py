"""Tool description scan: instructions aimed at the agent, invisible Unicode, URLs (Track C).

Tool poisoning hides instructions for the *agent* in text the user never reads (the tool's description or a
parameter description). This scans every string in the manifest, not just `description`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._text import decode_tag_chars, invisible_chars
from lineage.schemas.finding import Finding

URL = re.compile(r"https?://[^\s'\"<>)\]]+|\bwww\.[^\s'\"<>)\]]+", re.I)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")
SENSITIVE = re.compile(r"(~/|/etc/(passwd|shadow)|\.ssh\b|id_rsa|\.env\b|\.aws\b|credentials|api[_ -]?key|password|secret|token|cookie|"
                       r"mcp\.json|keychain)", re.I)
# patterns that address the agent rather than describe the tool
AGENT_ADDRESSED = [
    ("framing tag", re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|override)\s*>", re.I)),
    ("override", re.compile(r"ignore (all |any |the )?(previous|prior|above|earlier)|disregard (the |all )?(previous|above|system)|override (the )?(system|user)", re.I)),
    ("concealment", re.compile(r"do not (tell|mention|reveal|inform|show|disclose|let)|don'?t (tell|mention|reveal)|without (telling|informing|notifying|the user)|never (mention|reveal)|keep (this|it) (secret|hidden)", re.I)),
    ("pre/post-condition", re.compile(r"(before|after|when) (using|calling|invoking|running) (this|any|the|every) (tool|function)|(first|also),? (call|use|invoke|run|read)\b", re.I)),
    ("directive", re.compile(r"\byou (must|should|need to|have to|are required to)\b|\balways (call|use|include|pass|send|add|append)\b|\bmake sure (to|you)\b", re.I)),
    ("exfiltration", re.compile(r"\b(send|post|forward|upload|email|transmit|leak|copy)\b.{0,60}\b(to|at|via)\b", re.I)),
    ("cross-tool", re.compile(r"\b(instead of|rather than)\b.{0,40}\b(tool|function)|(call|use) the .{1,30} (tool|function)", re.I)),
]


def _strings(obj, path: str = ""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")


def scan_manifest(manifest: object, ref: str = "manifest.json") -> list[Finding]:
    out: list[Finding] = []
    for path, text in _strings(manifest):
        where = f"{ref}#{path}"
        inv = invisible_chars(text)
        if inv:
            hidden = decode_tag_chars(text)
            out.append(finding("TOOL.DESC.INVISIBLE_UNICODE", f"{path}: {len(inv)} invisible character(s)" + (" hiding text" if hidden else ""),
                               "critical" if hidden else "high", "tool", "S3",
                               [ev("field", where, f"hidden text: {hidden[:120]!r}" if hidden else f"{inv[0][1]} {inv[0][2]} (+{len(inv) - 1} more)")]))
        reasons = [(label, m.group(0)) for label, rx in AGENT_ADDRESSED for m in [rx.search(text)] if m]
        if reasons:
            sens = SENSITIVE.search(text)
            conceal = any(label in ("concealment", "override", "framing tag") for label, _ in reasons)
            sev = "critical" if sens and (conceal or any(l == "exfiltration" for l, _ in reasons)) else "high"
            if len(reasons) == 1 and reasons[0][0] in ("directive", "pre/post-condition") and not sens and path != "description":
                sev = "medium"  # parameter docs often say "you must pass an absolute path"
            out.append(finding("TOOL.DESC.AGENT_INSTRUCTION", f"{path}: text is aimed at the agent ({', '.join(l for l, _ in reasons)})", sev, "tool", "S3",
                               [ev("field", where, f"{snippet!r}") for _, snippet in reasons[:3]] + ([ev("field", where, f"mentions {sens.group(0)!r}")] if sens else [])))
        img = MD_IMAGE.findall(text)
        urls = URL.findall(text)
        if img:
            out.append(finding("TOOL.DESC.MARKDOWN_IMAGE", f"{path}: markdown image can leak data through its URL", "high", "tool", "S3",
                               [ev("url", u[:150], where) for u in img[:3]]))
        elif urls:
            sev = "medium" if any("?" in u or "{" in u for u in urls) else "low"
            out.append(finding("TOOL.DESC.URL", f"{path}: description contains {len(urls)} URL(s)", sev, "tool", "S3",
                               [ev("url", u[:150], where) for u in urls[:5]]))
        if len(text) > 2000:
            out.append(finding("TOOL.DESC.VERY_LONG", f"{path}: unusually long text ({len(text)} chars) can bury instructions", "low", "tool", "S3",
                               [ev("field", where, f"{len(text)} chars")]))
    return out


def scan(manifest_path: Path) -> list[Finding]:
    p = Path(manifest_path)
    try:
        manifest = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return [finding("TOOL.DESC.UNREADABLE", f"Manifest cannot be read ({type(e).__name__})", "medium", "tool", "S3",
                        [ev("field", p.name, str(e)[:120])])]
    return scan_manifest(manifest, p.name)
