"""Render bench/results_holdout.json to bench/results_holdout.md (validation run)."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Hand-written judgements for the high-signal findings (read the cited code). Anything not listed gets the generic
# capability judgement below. FA = false alarm; DEF = defensible flag (the pattern is real) but the artifact is not malicious.
MANUAL = {
    "coverage": ("DEF", "a1_coverage.pth is a real start-up hook (exec at every interpreter start), gated on COVERAGE_PROCESS_START; legitimate, but the mechanism is identical to the .pth malware technique."),
    "setuptools": ("DEF", "distutils-precedence.pth is a real start-up hook that installs the distutils shim; legitimate and well known."),
    "opentelemetry-instrumentation": ("DEF", "ships a sitecustomize.py that runs on every start; that is the auto-instrumentation design, not an attack."),
    "dill": ("DEF", "eval/compile in a serializer is the library's purpose; REMOTE_EXEC_POSSIBLE is a true statement about dill, not evidence of malice."),
    "scikit-learn": ("DEF", "pickle.loads of the local 20newsgroups cache file after zlib decode; unsafe-deserialization pattern is real, source is a cache the library wrote itself."),
    "ghapi": ("FA", "build-time helper that sends GITHUB_TOKEN to api.github.com as its Authorization header; taint rule cannot tell the intended destination."),
    "huggingface-hub": ("FA", "git-lfs transfer agent uploading a file the user asked to push; file->PUT is the feature."),
    "pandas": ("FA", "'sink' is chunk_queue.put (a local queue); the taint rule matched any .put() as a network upload."),
    "Qwen__Qwen3-8B": ("FA", "template branches on '<tool_response>' / '</think>' markers to format tool-calling and reasoning turns; no injected text."),
    "deepseek-ai__DeepSeek-R1-Distill-Qwen-7B": ("FA", "template strips reasoning up to '</think>' from assistant turns; standard formatting, no injected text."),
    "openai__gpt-oss-20b": ("FA", "the 'hidden instruction' is a developer-facing error string in a guard branch ('You have passed a message containing <|channel|> tags...'); misfire, but it BLOCKS (risk 90) a major model."),
    "THUDM__glm-4-9b-chat": ("DEF", "auto_map points the tokenizer at repo-shipped Python (needs trust_remote_code); policy-correct to hold for review, vendor is well known."),
    "internlm__internlm2_5-7b-chat": ("DEF", "auto_map tokenizer classes ship as repo Python (trust_remote_code); policy-correct to hold, vendor is well known."),
    "moonshotai__Kimi-K2-Instruct": ("DEF", "auto_map tokenizer class ships as repo Python (trust_remote_code); policy-correct to hold, vendor is well known."),
}


def _pct(x) -> str:
    return "–" if x is None else f"{x:.0%}"


def _generic(row: dict) -> tuple[str, str]:
    ids = [f["id"] for f in row["findings"] if f["id"] != "PROV.PUBLISHER.UNLISTED"]
    caps = ", ".join(sorted({i.split(".")[-1].lower() for i in ids}))
    ev = next((f["evidence"][0] for f in row["findings"] if f["id"] not in ("PROV.PUBLISHER.UNLISTED",) and f["evidence"]), "")
    return "FA", f"capability findings ({caps}) are ordinary for this library, no hook/taint/decode-exec chain; e.g. {ev[:110]}"


def render(src: Path, out: Path) -> None:
    r = json.loads(src.read_text())
    ref = json.loads((ROOT / "bench" / "results.json").read_text())["modes"]["dev, no GPU worker"]
    h = r["holdout"]
    L = ["# Held-out validation (Inspector, dev / CPU)", "",
         f"Generated {r['generated']} · {r['environment']} · policy `examples/policy.org.yaml` (allow ≤ 30, quarantine ≤ 70, block > 70)", "",
         "**Flagged** is defined exactly as in `bench/run_bench.py`: outcome `block`, or risk above the policy's allow threshold.",
         "Held-out corpus: `bench/corpus_holdout/` (built by `bench/build_holdout.py` before the Inspector was run on it; no rule was changed afterwards).", "",
         "## 1. Held-out corpus", "",
         f"Overall: **TPR {_pct(h['overall']['tpr'])}** ({h['overall']['n_malicious']} malicious) · **FPR {_pct(h['overall']['fpr'])}** ({h['overall']['n_benign']} benign)",
         f"(in-sample `bench/corpus`, same mode, for comparison: TPR {_pct(ref['overall']['tpr'])}, FPR {_pct(ref['overall']['fpr'])}; "
         "that includes LoRA/bind/dataset categories not re-tested here.)", "",
         "| category | malicious | TPR | benign | FPR | in-sample TPR | in-sample FPR |", "|---|---|---|---|---|---|---|"]
    for cat, c in sorted(h["categories"].items()):
        rc = ref["categories"].get(cat, {})
        L.append(f"| {cat} | {c['n_malicious']} | {_pct(c['tpr'])} ({c['tp']}/{c['n_malicious']}) | {c['n_benign']} | {_pct(c['fpr'])} ({c['fp']}/{c['n_benign']}) | {_pct(rc.get('tpr'))} | {_pct(rc.get('fpr'))} |")
    L += ["", "### Misses and false positives", "", "| item | label | outcome | risk | non-info findings that did fire |", "|---|---|---|---|---|"]
    for i in h["items"]:
        if (i["label"] == "malicious") != i["positive"]:
            L.append(f"| {i['id']} | {i['label']} | {i.get('outcome', '–')} | {i.get('risk', '–')} | {', '.join(i.get('findings', [])) or 'none'} |")
    L += ["", "Reading the table: threshold/weighting misses (the right finding fired, score stayed under the allow threshold): all six `h_look_*` (`PKG.PROV.LOOKALIKE_NAME`, risk 17), "
          "`h_pkg_mal_popen_setup` (INSTALL_EXEC, 29), `h_pkg_mal_aws_creds_http`, `h_pkg_mal_builtins_exec` (30), `h_pkg_mal_shell_rc_persist`, `h_tool_mal_shadow_other_tools` (30), "
          "`h_tool_mal_undeclared_creds_read` (22) and `h_tpl_mal_md_image_exfil` (22). True detection misses (nothing but `UNLISTED` fired): `h_pkg_mal_ctypes_system`, "
          "`h_tool_mal_param_override`, `h_tool_mal_encoded_directive`, `h_tool_mal_html_comment`, `h_tpl_mal_system_override`, `h_tok_swap_special_remap`.",
          "The six benign pickle FPs are policy, not detection: `allow_pickle: false` blocks any pickle checkpoint. The benign corpus in `bench/corpus` contains no pickles, so this category had no benign-pickle test before.", ""]

    rw = r["realworld"]
    rows = rw["rows"]
    L += ["## 2. Real-world false-positive check (presumed benign)", "",
          f"PyPI top list dated {rw['fetch']['top_list_updated']} (hugovk/top-pypi-packages, 30-day downloads). `pip download --no-deps --only-binary=:all:` for CPython 3.11 / manylinux x86_64 "
          "(wheels only: pip would execute sdist build code to read metadata), unzipped into a temp folder outside the repo. "
          "Chat templates: `tokenizer_config.json` (or `chat_template.jinja/json`) from Hugging Face, wrapped in a stub tiny model dir the same way `bench/corpus` templates are. "
          "Sidecar metadata is `released_at` 2025-01-01, licence `mit`, so provenance/licence/cooldown rules do not trip and the numbers isolate the Inspector. "
          "Every package carries `PROV.PUBLISHER.UNLISTED` (+5) because `pypi` / `hf` is not on the example allow list.", ""]
    ok_t = [t for t in rw["fetch"]["templates"] if t["ok"]]
    bad_t = [t for t in rw["fetch"]["templates"] if not t["ok"] and t.get("error") != "surplus"]
    L.append(f"Fetched: {sum(p['ok'] for p in rw['fetch']['packages'])}/200 packages, {len(ok_t)} templates "
             f"({len(bad_t)} candidates skipped: " + ", ".join(f"{t['repo']} ({t['error'][:30]})" for t in bad_t) + ").")
    L += ["", "| set | n | flagged | FPR | allow | quarantine | block | errors |", "|---|---|---|---|---|---|---|---|"]
    for kind, name in (("package", "PyPI packages"), ("model", "chat templates")):
        rs = [x for x in rows if x["kind"] == kind]
        oc = Counter(x.get("outcome") for x in rs)
        fl = sum(x["flagged"] for x in rs)
        L.append(f"| {name} | {len(rs)} | {fl} | **{_pct(fl / len(rs))}** | {oc['allow']} | {oc['quarantine']} | {oc['block']} | {sum('error' in x for x in rs)} |")
    flagged = [x for x in rows if x["flagged"]]
    judged = {x["id"]: MANUAL.get(x["id"]) or _generic(x) for x in flagged}
    fa = sum(j[0] == "FA" for j in judged.values())
    de = sum(j[0] == "DEF" for j in judged.values())
    L += ["", f"Of {len(flagged)} flagged: **{fa} false alarms**, **{de} defensible** (real pattern, benign artifact), **0** malicious. "
          f"Calling only the false alarms errors, FPR = {fa / len(rows):.0%} ({fa}/{len(rows)}); counting every flag, {len(flagged) / len(rows):.0%}.", ""]
    c = Counter()
    for x in flagged:
        for i in {f["id"] for f in x["findings"]}:
            c[i] += 1
    L += ["Findings across flagged items (items affected):", "", "| finding | items |", "|---|---|"] + [f"| {k} | {v} |" for k, v in c.most_common()]
    L += ["", "### Every flagged item", "", "FA = false alarm · DEF = defensible flag, artifact not malicious. High-signal items were judged by reading the cited code; "
          "the rest are judged from the finding set (capability findings only, no hook / taint / decode-exec chain).", "",
          "| artifact | outcome (risk) | findings that fired | judgement |", "|---|---|---|---|"]
    for x in sorted(flagged, key=lambda x: (x["kind"], -x["risk"], x["id"])):
        j = judged[x["id"]]
        ids = ", ".join(sorted({f["id"].replace("PROV.PUBLISHER.UNLISTED", "UNLISTED") for f in x["findings"]}))
        L.append(f"| {x['id']} | {x['outcome']} ({x['risk']}) | {ids} | **{j[0]}**: {j[1].replace('|', '/')} |")
    errs = [x for x in rows if "error" in x]
    if errs:
        L += ["", "Errors: " + "; ".join(f"{x['id']}: {x['error']}" for x in errs)]
    out.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    render(ROOT / "bench" / "results_holdout.json", ROOT / "bench" / "results_holdout.md")
