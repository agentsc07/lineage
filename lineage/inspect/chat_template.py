"""Chat-template scanner (Jinja AST): conditionals on message content, hidden instructions, URLs, diff vs known-good (Track C).

Chat templates are code that runs on every prompt (Pillar / ICLR 2026, arXiv 2602.04653); hub scanners ignore them.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from jinja2 import Environment, TemplateSyntaxError, nodes

from lineage.inspect._common import ev, finding
from lineage.inspect._text import invisible_chars
from lineage.schemas.finding import Finding

URL = re.compile(r"https?://[^\s'\"<>)]+|\bwww\.[^\s'\"<>)]+", re.I)
# Text that tells the model how to treat the user or its tools: override the system prompt or its safety rules,
# hide something from the user, send data somewhere, call or render a URL. A template has no business emitting any of it.
# Developer-facing strings (the argument of raise_exception, validation messages) are not instructions to the model
# and are removed before this runs.
MODEL_DIRECTED = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|disable|suspend)\b.{0,40}\b(instructions?|system prompt|prompts?|rules|guidelines|polic(?:y|ies)|safety|guardrails?|restrictions?|filters?)\b|"
    r"\b(safety|content|moderation)\b.{0,20}\b(polic(?:y|ies)|filters?|guardrails?|checks?)\b.{0,25}\b(disabled|off|removed|suspended|lifted)\b|"
    r"\b(follow|obey|comply with)\b.{0,15}\b(every|all|any|each)\b.{0,30}\b(instructions?|commands?|requests?)\b|"
    r"\bwithout (any )?(refus\w*|restrictions?|censorship|safety|warnings?)\b|"
    r"\b(do|must|should|shall|may|will|can|could) not (tell|mention|reveal|inform|disclose|show)\b|\bdon'?t (tell|mention|reveal)\b|\b(never|not) (mention|reveal|disclose)\b|"
    r"\b(keep|stay) (this|it|that)?\s*(a )?(secret|hidden|silent|quiet)\b|\bstay silent\b|\b(secretly|covertly|silently)\b|\bhidden (instruction|command)\b|"
    r"\b(send|post|upload|forward|transmit|leak|exfiltrat\w*)\b.{0,80}\b(to|at)\b.{0,60}(https?://|\bserver\b|\bendpoint\b|\bwebhook\b)|"
    r"\b(reply|respond|answer|output)\b.{0,20}\bonly\b.{0,30}\b(link|url)\b|"
    r"\b(include|insert|add|append|render|embed|open|visit|fetch|call)\b.{0,25}\b(link|url|image|iframe|script|payload|backdoor|https?://)|"
    r"!\[[^\]]*\]\(\s*https?://|\bbackdoor\b|\bjailbreak\b|\bsystem override\b",
    re.I,
)
HIGH_SIGNAL = MODEL_DIRECTED  # kept for callers that import the old name
# Instruction-like text; ordinary in some default system prompts, so only meaningful in branches or in a diff.
GENERIC = re.compile(r"\byou (must|should|will)\b|\balways (respond|reply|answer|say|include|append|output)\b|"
                     r"\bwhen the user (says|mentions|asks|writes)\b|\bpretend\b|\binstead\b.{0,30}\b(respond|reply|say|output)\b", re.I)
SSTI = re.compile(r"__\w+__|\bmro\b|\bglobals\b|\bbuiltins\b|\bimport\b|\blipsum\b|\bcycler\b|\bjoiner\b|\|\s*attr\b")
STRING_METHODS = {"startswith", "endswith", "find", "count", "index", "lower", "upper", "strip", "__contains__"}
STRING_FILTERS = {"regex_search", "regex_match", "match", "search"}
MIN_PAYLOAD = 8


def find_templates(model_dir: Path) -> list[tuple[str, str]]:
    """(source ref, template text) for every chat template shipped with the model."""
    d = Path(model_dir)
    found: list[tuple[str, str]] = []
    for name in ("tokenizer_config.json", "chat_template.json", "processor_config.json"):
        try:
            data = json.loads((d / name).read_text())
        except (OSError, json.JSONDecodeError):
            continue
        tpl = data.get("chat_template") if isinstance(data, dict) else None
        if isinstance(tpl, str):
            found.append((f"{name}#chat_template", tpl))
        elif isinstance(tpl, list):
            for item in tpl:
                if isinstance(item, dict) and isinstance(item.get("template"), str):
                    found.append((f"{name}#chat_template[{item.get('name', '?')}]", item["template"]))
    for p in sorted(d.glob("*.jinja")):
        found.append((p.name, p.read_text()))
    return found


def _all(node: nodes.Node, cls) -> list:
    """Like Node.find_all, but also yields `node` itself."""
    return ([node] if isinstance(node, cls) else []) + list(node.find_all(cls))


class _Analysis:
    def __init__(self, ast_root: nodes.Template):
        self.root = ast_root
        self.message_vars: set[str] = set()   # loop variables over `messages`
        self.text_vars: set[str] = set()      # names bound to message text
        self._collect()

    def _is_messages(self, n: nodes.Node) -> bool:
        return any(isinstance(x, nodes.Name) and x.name in ("messages", "message_list") for x in _all(n, nodes.Name))

    def _collect(self) -> None:
        for _ in range(3):  # fixed point over aliases (set x = message['content']; set y = x|trim)
            for f in self.root.find_all(nodes.For):
                if self._is_messages(f.iter) and isinstance(f.target, nodes.Name):
                    self.message_vars.add(f.target.name)
            for a in self.root.find_all(nodes.Assign):
                if isinstance(a.target, nodes.Name) and self.is_text(a.node):
                    self.text_vars.add(a.target.name)
            for f in self.root.find_all(nodes.For):  # `for item in message['content']`: items are content parts
                if isinstance(f.target, nodes.Name) and self._derives_from_content(f.iter):
                    self.message_vars.add(f.target.name)

    def _derives_from_content(self, n: nodes.Node) -> bool:
        return (isinstance(n, nodes.Getitem) and isinstance(n.arg, nodes.Const) and n.arg.value == "content") or (
            isinstance(n, nodes.Getattr) and n.attr == "content") or (isinstance(n, nodes.Name) and n.name in self.text_vars)

    def is_text(self, n: nodes.Node) -> bool:
        """True if `n` evaluates to (a transformation of) the user-controlled message text."""
        if isinstance(n, nodes.Getattr):
            return n.attr in ("content", "text") and self._base_is_message(n.node) or self.is_text(n.node) and n.attr not in ("role",)
        if isinstance(n, nodes.Getitem):
            if isinstance(n.arg, nodes.Const) and n.arg.value in ("content", "text") and self._base_is_message(n.node):
                return True
            if isinstance(n.arg, nodes.Const) and isinstance(n.arg.value, str):
                return False  # item['type'], message['role'], ...
            return self.is_text(n.node)  # slices / indexes of the text
        if isinstance(n, nodes.Name):
            return n.name in self.text_vars
        if isinstance(n, nodes.Filter):
            return self.is_text(n.node) if n.node is not None else False
        if isinstance(n, nodes.Call):
            return isinstance(n.node, nodes.Getattr) and self.is_text(n.node.node)
        if isinstance(n, nodes.CondExpr):
            return self.is_text(n.expr1) or (n.expr2 is not None and self.is_text(n.expr2))
        if isinstance(n, nodes.Concat):
            return any(self.is_text(x) for x in n.nodes)
        return False

    def _base_is_message(self, n: nodes.Node) -> bool:
        if isinstance(n, nodes.Name):
            return n.name in self.message_vars or n.name in ("message", "msg", "m")
        if isinstance(n, nodes.Getitem):  # messages[-1]
            return self._is_messages(n.node)
        return False

    def literal_triggers(self, test: nodes.Node) -> list[str]:
        """String literals the message text is compared against inside a condition."""
        lits: list[str] = []
        for c in _all(test, nodes.Compare):
            operands = [c.expr] + [o.expr for o in c.ops]
            for i, o in enumerate(operands):
                if self.is_text(o):
                    lits += [x.value for x in operands if isinstance(x, nodes.Const) and isinstance(x.value, str) and x.value]
        for call in _all(test, nodes.Call):
            if isinstance(call.node, nodes.Getattr) and call.node.attr in STRING_METHODS and self.is_text(call.node.node):
                lits += [a.value for a in call.args if isinstance(a, nodes.Const) and isinstance(a.value, str)]
        for f in _all(test, nodes.Filter):
            if f.name in STRING_FILTERS and f.node is not None and self.is_text(f.node):
                lits += [a.value for a in f.args if isinstance(a, nodes.Const) and isinstance(a.value, str)]
        for t in _all(test, nodes.Test):
            if t.name in STRING_FILTERS | {"in"} and self.is_text(t.node):
                lits += [a.value for a in t.args if isinstance(a, nodes.Const) and isinstance(a.value, str)]
        return lits


_SKIP: set[int] = set()  # ids of Const nodes inside raise_exception(...) for the template being scanned


def _developer_strings(tree: nodes.Template) -> set[int]:
    """Constants passed to raise_exception(): an error message for whoever called the template, never prompt text."""
    skip: set[int] = set()
    for call in tree.find_all(nodes.Call):
        f = call.node
        name = f.name if isinstance(f, nodes.Name) else f.attr if isinstance(f, nodes.Getattr) else ""
        if name in ("raise_exception", "raise_error"):
            skip |= {id(c) for c in call.find_all(nodes.Const)}
    return skip


def _literal_text(node: nodes.Node) -> list[tuple[int, str]]:
    """(line, text) of every literal string the template can emit under `node` (inclusive)."""
    out = []
    if isinstance(node, nodes.Const) and isinstance(node.value, str) and node.value.strip() and id(node) not in _SKIP:
        out.append((node.lineno, node.value))
    for o in _all(node, nodes.TemplateData):
        if o.data.strip():
            out.append((o.lineno, o.data))
    for c in _all(node, nodes.Output):
        for child in c.nodes:
            for k in _all(child, nodes.Const):
                if isinstance(k.value, str) and k.value.strip() and id(k) not in _SKIP:
                    out.append((k.lineno, k.value))
    return out


def _is_markup(literal: str) -> bool:
    """A control token or tag ('</think>', '<|im_start|>', '[INST]') rather than words a person would write."""
    return bool(re.search(r"[<>\[\]{}|]", literal)) and len(re.findall(r"[A-Za-z]{4,}", re.sub(r"[<>\[\]{}|/_\-]", " ", literal))) <= 2


def _urls_with_data(tree: nodes.Template) -> bool:
    """A URL literal in an output that also interpolates a variable: the template builds a link out of the conversation."""
    for out in tree.find_all(nodes.Output):
        has_url = any(isinstance(k, nodes.Const) and isinstance(k.value, str) and URL.search(k.value) for n in out.nodes for k in _all(n, nodes.Const))
        has_var = any(not isinstance(k, (nodes.Const, nodes.TemplateData, nodes.Add, nodes.Concat)) for n in out.nodes for k in _all(n, (nodes.Name, nodes.Getitem, nodes.Getattr)))
        if has_url and has_var:
            return True
    return False


def _normalise(src: str) -> list[str]:
    return [ln.strip() for ln in re.sub(r"\s+", " ", src.replace("{%-", "{%").replace("-%}", "%}")).replace("}}", "}}\n").replace("%}", "%}\n").split("\n") if ln.strip()]


def scan(model_dir: Path, known_good_template: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    for ref, tpl in find_templates(model_dir):
        out.extend(scan_template(tpl, ref, known_good_template))
    return out


def scan_template(template: str, ref: str = "chat_template", known_good: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    env = Environment()
    try:
        tree = env.parse(template)
    except TemplateSyntaxError as e:
        return [finding("MODEL.TEMPLATE.UNPARSEABLE", f"{ref}: template does not parse ({e.message})", "medium", "model", "S3",
                        [ev("field", ref, f"line {e.lineno}")])]
    an = _Analysis(tree)
    _SKIP.clear()
    _SKIP.update(_developer_strings(tree))

    inv = invisible_chars(template)
    if inv:
        out.append(finding("MODEL.TEMPLATE.INVISIBLE_UNICODE", f"{ref}: template contains {len(inv)} invisible character(s)", "high",
                           "model", "S3", [ev("field", ref, f"{cp} {name} at offset {i}") for i, cp, name in inv[:5]]))
    if SSTI.search(template):
        m = SSTI.search(template)
        out.append(finding("MODEL.TEMPLATE.SSTI", f"{ref}: template reaches for interpreter internals ({m.group(0)})", "critical", "model", "S3",
                           [ev("field", ref, template[max(0, m.start() - 30): m.end() + 30])]))

    reported: set[str] = set()
    # conditionals on message content
    conditions = [(n.test, n, n.lineno) for n in tree.find_all(nodes.If)] + [(n.test, n, n.lineno) for n in tree.find_all(nodes.CondExpr)]
    for test, node, line in conditions:
        lits = an.literal_triggers(test)
        if not lits:
            continue
        branch: list[nodes.Node] = list(getattr(node, "body", []) or []) + list(getattr(node, "else_", []) or [])
        if isinstance(node, nodes.CondExpr):
            branch = [x for x in (node.expr1, node.expr2) if x is not None]
        payload = [t for b in branch for _, t in _literal_text(b) if len(t.strip()) >= MIN_PAYLOAD]
        trig = ", ".join(repr(x[:40]) for x in lits[:3])
        markup = all(_is_markup(x) for x in lits)  # '</think>', '<tool_response>': structure the template formats, not a phrase a user would type
        directed = [t for t in payload if MODEL_DIRECTED.search(t) or URL.search(t)]
        if payload and (not markup or directed):
            out.append(finding("MODEL.TEMPLATE.TRIGGER_BRANCH", f"{ref}: when message text matches {trig}, the template emits extra text",
                               "critical", "model", "S3", [ev("field", f"{ref}:{line}", f"trigger {trig}; emits {payload[0].strip()[:100]!r}")]))
        else:
            out.append(finding("MODEL.TEMPLATE.CONTENT_CONDITIONAL", f"{ref}: template branches on message text matching {trig}",
                               "info" if markup else "high", "model", "S3", [ev("field", f"{ref}:{line}", f"trigger {trig}")]))
        for t in payload:
            if MODEL_DIRECTED.search(t):
                out.append(finding("MODEL.TEMPLATE.HIDDEN_INSTRUCTION", f"{ref}: conditional branch injects an instruction", "critical",
                                   "model", "S3", [ev("field", f"{ref}:{line}", t.strip()[:120])]))
                reported.add(t)
                break

    # instruction text that only appears under some condition, whatever the condition tests (message text is covered above)
    for node in list(tree.find_all(nodes.If)) + list(tree.find_all(nodes.CondExpr)):
        branch = list(getattr(node, "body", []) or []) + list(getattr(node, "else_", []) or [])
        if isinstance(node, nodes.CondExpr):
            branch = [x for x in (node.expr1, node.expr2) if x is not None]
        for b in branch:
            for ln, t in _literal_text(b):
                if t in reported or not MODEL_DIRECTED.search(t):
                    continue
                reported.add(t)
                out.append(finding("MODEL.TEMPLATE.CONDITIONAL_INSTRUCTION",
                                   f"{ref}: instruction text appears only under a condition", "critical", "model", "S3",
                                   [ev("field", f"{ref}:{ln}", t.strip()[:120])]))
    # instructions aimed at the model, and links, in the text every prompt will carry
    for line, text in _literal_text(tree):
        if text in reported:
            continue
        m = MODEL_DIRECTED.search(text)
        g = GENERIC.search(text)
        if m:
            out.append(finding("MODEL.TEMPLATE.HIDDEN_INSTRUCTION", f"{ref}: template text instructs the model against its user or tools ({m.group(0)[:40]!r})",
                               "critical", "model", "S3", [ev("field", f"{ref}:{line}", text.strip()[:120])]))
        elif g and len(text.split()) >= 4:  # ordinary system-prompt prose ("You must answer in English"): a signal, not a risk
            out.append(finding("MODEL.TEMPLATE.EMBEDDED_INSTRUCTION", f"{ref}: template text addresses the model ({g.group(0)[:40]!r})",
                               "info", "model", "S3", [ev("field", f"{ref}:{line}", text.strip()[:120])]))
    urls = sorted({u for _, t in _literal_text(tree) for u in URL.findall(t)})
    if urls:
        dynamic = _urls_with_data(tree)
        out.append(finding("MODEL.TEMPLATE.URL", f"{ref}: template embeds {len(urls)} URL(s)" + (" and appends message data to one" if dynamic else ""),
                           "critical" if dynamic else "low", "model", "S3", [ev("url", u[:150]) for u in urls[:5]]))

    # diff vs known-good
    if known_good is not None:
        a, b = _normalise(known_good), _normalise(template)
        if a != b:
            diff = [ln for ln in difflib.unified_diff(a, b, lineterm="", n=0) if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
            added = [ln[1:] for ln in diff if ln[0] == "+"]
            try:
                good_text = {t.strip() for _, t in _literal_text(env.parse(known_good))}
            except TemplateSyntaxError:
                good_text = set()
            new_text = [t.strip() for _, t in _literal_text(tree) if t.strip() not in good_text and len(t.strip()) >= MIN_PAYLOAD]
            injected = [t for t in new_text if GENERIC.search(t) or HIGH_SIGNAL.search(t) or URL.search(t)]
            sev = "critical" if injected else "high" if new_text else "medium"
            out.append(finding("MODEL.TEMPLATE.DIFF_FROM_KNOWN_GOOD", f"{ref}: template differs from the known-good version ({len(added)} changed line(s))",
                               sev, "model", "S3",
                               [ev("field", ref, ln[:140]) for ln in diff[:6]] + [ev("field", ref, f"new text: {t[:100]!r}") for t in new_text[:3]]))
    return out
