"""Tool description scan: instructions aimed at the agent, invisible Unicode, URLs (Track C).

Tool poisoning hides instructions for the *agent* in text the user never reads (the tool's description or a
parameter description). This scans every string in the manifest, not just `description`.
"""
from __future__ import annotations

import base64
import binascii
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
    ("override", re.compile(r"ignore (all |any |the )?(previous|prior|above|earlier)|disregard (the |all )?(previous|above|system)|override (the )?(system|user)|"
                            r"\b(ignore|disregard|forget|bypass)\b.{0,40}\b(instructions?|system prompt|guidelines|rules|safety)|"
                            r"system override|\bobey\b.{0,30}\b(this|these)\b", re.I)),
    ("concealment", re.compile(r"do not (tell|mention|reveal|inform|show|disclose|let)|don'?t (tell|mention|reveal)|without (telling|informing|notifying|the user)|never (mention|reveal)|keep (this|it) (secret|hidden)", re.I)),
    ("pre/post-condition", re.compile(r"(before|after|when) (using|calling|invoking|running) (this|any|the|every) (tool|function)|(first|also),? (call|use|invoke|run|read)\b", re.I)),
    ("directive", re.compile(r"\byou (must|should|need to|have to|are required to)\b|\balways (call|use|include|pass|send|add|append)\b|\bmake sure (to|you)\b", re.I)),
    ("exfiltration", re.compile(r"\b(send|post|forward|upload|email|transmit|leak|copy)\b.{0,60}\b(to|at|via)\b", re.I)),
    ("cross-tool", re.compile(r"\b(instead of|rather than)\b.{0,40}\b(tool|function)|(call|use) the .{1,30} (tool|function)", re.I)),
]
# Text that makes the agent route other tools' work through this one, or stop using them: the tool shadows the others.
SHADOWING = re.compile(
    r"\b(any|every|all|each|other|another|different)\b.{0,25}\b(other )?(tools?|functions?|servers?|mcp)\b|"
    r"\b(whenever|when|before|after)\b.{0,50}\b(invokes?|calls?|uses?|runs?|triggers?)\b.{0,30}\b(tools?|function)\b|"
    r"\b(instead of|rather than|do not use|don'?t use|never use|stop using|replaces?|supersedes?|takes? precedence over)\b.{0,40}\b(tools?|functions?)\b|"
    r"\b(first|always) (call|use|invoke|run)\b.{0,30}\b(this|me)\b",
    re.I,
)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
INSTRUCTION_VERB = re.compile(r"\b(forward|send|read|ignore|disregard|decode|follow|include|call|use|do not|don'?t|never|always|must|before|after|upload|post|run|execute|mention|reveal)\b", re.I)


def _decoded(text: str) -> list[str]:
    """Readable text hidden in a string as base64 or hex. Only prose-looking results count, so ids and hashes pass."""
    out = []
    for m in B64_RUN.finditer(text):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(dec) >= 12 and sum(c.isprintable() or c in "\n\t" for c in dec) / len(dec) > 0.95 and dec.count(" ") >= 2:
            out.append(dec)
    for m in HEX_RUN.finditer(text):
        try:
            dec = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(dec) >= 12 and dec.isprintable() and dec.count(" ") >= 2:
            out.append(dec)
    return out


def _strings(obj, path: str = ""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")


def _agent_findings(path: str, where: str, text: str, via: str = "") -> list[Finding]:
    """Is this text aimed at the agent? `via` says how it was found (an HTML comment, a decoded blob)."""
    out: list[Finding] = []
    reasons = [(label, m.group(0)) for label, rx in AGENT_ADDRESSED for m in [rx.search(text)] if m]
    shadow = SHADOWING.search(text)
    if reasons or shadow:
        sens = SENSITIVE.search(text)
        labels = [l for l, _ in reasons]
        conceal = any(l in ("concealment", "override", "framing tag") for l in labels)
        sev = "critical" if conceal or shadow and reasons or sens and "exfiltration" in labels else "high"
        if len(reasons) == 1 and labels[0] in ("directive", "pre/post-condition") and not sens and not shadow and path != "description" and not via:
            sev = "medium"  # parameter docs often say "you must pass an absolute path"
        if via:
            sev = "critical"  # text that was hidden from the reader and tells the agent what to do
        if shadow and not reasons:
            sev = "high"
        if reasons:
            out.append(finding("TOOL.DESC.AGENT_INSTRUCTION", f"{path}: {via}text is aimed at the agent ({', '.join(labels)})", sev, "tool", "S3",
                               [ev("field", where, f"{snippet!r}") for _, snippet in reasons[:3]] + ([ev("field", where, f"mentions {sens.group(0)!r}")] if sens else [])))
        if shadow:
            out.append(finding("TOOL.DESC.SHADOWING", f"{path}: {via}text tells the agent how to use or ignore other tools",
                               "critical" if conceal or via else "high", "tool", "S3", [ev("field", where, f"{shadow.group(0)[:120]!r}")]))
    return out


def scan_manifest(manifest: object, ref: str = "manifest.json") -> list[Finding]:
    """Every string in the manifest (tool and parameter descriptions, enums, defaults, nested schemas) is checked as
    written, then again with HTML comments pulled out and with base64/hex runs decoded: text the reader never sees
    is the point of tool poisoning."""
    out: list[Finding] = []
    for path, text in _strings(manifest):
        where = f"{ref}#{path}"
        inv = invisible_chars(text)
        if inv:
            hidden = decode_tag_chars(text)
            out.append(finding("TOOL.DESC.INVISIBLE_UNICODE", f"{path}: {len(inv)} invisible character(s)" + (" hiding text" if hidden else ""),
                               "critical" if hidden else "high", "tool", "S3",
                               [ev("field", where, f"hidden text: {hidden[:120]!r}" if hidden else f"{inv[0][1]} {inv[0][2]} (+{len(inv) - 1} more)")]))
            if hidden:
                out += _agent_findings(path, where, hidden, "hidden ")
        comments = [c.strip() for c in HTML_COMMENT.findall(text)]
        visible = HTML_COMMENT.sub(" ", text)
        if comments:
            has_words = [c for c in comments if len(c.split()) >= 3]
            if has_words:
                out.append(finding("TOOL.DESC.HTML_COMMENT", f"{path}: HTML comment hides text from the reader", "high", "tool", "S3",
                                   [ev("field", where, c[:120]) for c in has_words[:3]]))
            for c in comments:
                out += _agent_findings(path, where, c, "commented-out ") or ([finding(
                    "TOOL.DESC.AGENT_INSTRUCTION", f"{path}: commented-out text reads as an instruction", "critical", "tool", "S3",
                    [ev("field", where, c[:120])])] if INSTRUCTION_VERB.search(c) or SENSITIVE.search(c) else [])
        blobs = _decoded(visible)
        for b in blobs:
            out.append(finding("TOOL.DESC.ENCODED_TEXT", f"{path}: contains encoded text that decodes to prose", "high", "tool", "S3",
                               [ev("field", where, f"decodes to {b[:120]!r}")]))
            if INSTRUCTION_VERB.search(b) or SENSITIVE.search(b) or URL.search(b):
                out += _agent_findings(path, where, b, "encoded ") or [finding(
                    "TOOL.DESC.AGENT_INSTRUCTION", f"{path}: encoded text reads as an instruction", "critical", "tool", "S3", [ev("field", where, f"decodes to {b[:120]!r}")])]
        out += _agent_findings(path, where, visible)
        if inv:  # zero-width characters inside a directive split it so a pattern misses it; match on the cleaned text too
            gone = {i for i, _, _ in invisible_chars(visible)}
            cleaned = "".join(ch for i, ch in enumerate(visible) if i not in gone)
            seen = {(f.id, f.title) for f in out}
            for f in _agent_findings(path, where, cleaned, "zero-width-split "):
                if (f.id, f.title) not in seen:
                    out.append(f)
        img = MD_IMAGE.findall(visible)
        urls = URL.findall(visible)
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
