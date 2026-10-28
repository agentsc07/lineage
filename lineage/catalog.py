"""The catalogue of checks: what each one is called, what it looks at and how, in plain words.

One entry per checker (the code that produces findings), not per finding code. A finding id is mapped to its checker by the longest
matching prefix (`checker_for`). The dashboard shows this next to every finding; `scripts/gen_checks_doc.py` turns it, together with the
source of each checker, into `docs/CHECKS_REFERENCE.md`; `tests/test_catalog.py` fails if a finding id has no entry, so the page cannot
silently show a code nobody explains.
"""
from __future__ import annotations

from pydantic import BaseModel

# What a finding's `source` means for a reader.
KINDS = {
    "deterministic": "Rule-based check: the same input always gives the same answer",
    "statistical": "Statistical analysis: a measured score against a threshold",
    "llm": "AI reviewer: a model's claim, accepted only if it points to a real line of the artifact",
    "human": "A person's decision",
}
STAGE_NAMES = {"S0": "Acquire", "S1": "Identify", "S2": "Provenance", "S3": "Static inspection", "S4": "Deep inspection", "S5": "LLM review"}


class Checker(BaseModel):
    key: str
    name: str                 # what a person calls it
    stage: str                # the stage that runs it (S0..S5)
    types: list[str]          # artifact types it applies to
    detects: str              # the problem it looks for
    how: str                  # how it looks, in one or two sentences
    reads: str                # exactly what it reads
    needs: str = "nothing beyond the files"  # what has to be present for it to run
    entry: str                # module:function that runs it (the source shown in the checks reference)
    prefixes: list[str]       # finding-id prefixes this checker produces


_ALL = ["model", "dataset", "package", "tool", "agent"]
CHECKERS: list[Checker] = [
    Checker(key="identify", name="Fingerprint every file", stage="S1", types=_ALL,
            detects="Files that are unreadable or malformed, and artifacts we already hold",
            how="Computes a SHA-256 for every file and a Merkle root over them; for .safetensors also one hash per tensor. A repeated Merkle root is reported as already registered.",
            reads="Every file of the artifact (a shipped passport.json is evidence, not part of the artifact)", entry="lineage.intake.pipeline:_identify",
            prefixes=["INTAKE.DIGEST", "INTAKE.REF", "INTAKE.PASSPORT", "INTAKE.STAGE", "MODEL.FORMAT."]),
    Checker(key="origin", name="Does it match its claimed origin?", stage="S2", types=_ALL,
            detects="A copy that differs from the repository it says it came from",
            how="Compares the SHA-256 of every file with the hash the hub published for the claimed repository and revision. One differing file makes it a modified copy. With no claim nothing can be compared and trust stays unknown.",
            reads="File hashes (computed) against the hub's published file list", needs="a claimed origin (hf:org/name@rev or pypi:name==ver) and a reachable hub",
            entry="lineage.intake.inspectors:origin_check", prefixes=["PROV.ORIGIN."]),
    Checker(key="publisher", name="Publisher allow and block lists", stage="S2", types=_ALL,
            detects="A blocked publisher, a look-alike of an allowed publisher, or a publisher only the uploader vouches for",
            how="Matches the publisher name against the policy's block patterns, measures its edit distance to every allowed publisher, and notes when the name is only declared.",
            reads="The publisher fact (from the hub or signed passport = trusted; from the upload form = declared) and the policy lists", entry="lineage.intake.inspectors:publisher_policy",
            prefixes=["PROV.PUBLISHER.", "PROV.LOOKALIKE."]),
    Checker(key="signature", name="Creator passport and signature", stage="S2", types=_ALL,
            detects="A tampered or untrusted creator passport, files that differ from the passport, unpinned files",
            how="Checks the Ed25519 signature over the passport, that the signing key is one your policy trusts and in scope for this source, that the passport has not expired, and that every file hash in it equals the hash we computed.",
            reads="passport.json (or <name>.passport.json) shipped with the artifact; the policy's trusted_publishers", needs="a passport shipped with the artifact",
            entry="lineage.intake.inspectors:signed_passport", prefixes=["PROV.SIGNATURE.", "PROV.PASSPORT.", "INTEGRITY."]),
    Checker(key="parents", name="Is the parent admitted and not revoked?", stage="S2", types=_ALL,
            detects="A parent artifact that is revoked, unknown or not admitted",
            how="Looks up each parent passport id in the registry and reports its status.", reads="Parent ids from a verified passport or from weights identified in S4",
            entry="lineage.intake.inspectors:parent_chain", prefixes=["PROV.PARENT."]),
    Checker(key="licence", name="Licence", stage="S2", types=_ALL,
            detects="A licence that is not on the allow list, or one only the uploader states",
            how="Looks the licence up in the policy's allowed list; a declared licence never counts as allowed.", reads="The licence fact", needs="a licence fact and a non-empty allow list",
            entry="lineage.intake.inspectors:licence", prefixes=["POLICY.LICENCE."]),
    Checker(key="cooldown", name="Release age (cooldown)", stage="S2", types=["package", "model", "dataset", "tool"],
            detects="A release that is too new, or whose age cannot be established",
            how="Needs a release date from the hub or a signed passport; an upload-form date does not count. Without one the cooldown cannot be cleared.", reads="The released_at fact",
            entry="lineage.intake.inspectors:release_age", prefixes=["PROV.COOLDOWN"]),
    Checker(key="pkg_provenance", name="Package name, repository and maintainers", stage="S2", types=["package"],
            detects="Names that imitate popular packages, a source repository that differs from the build or an earlier release, a repository owned by the wrong account, new maintainers",
            how="Normalises the name and compares it with the 5,000 most downloaded PyPI names (typo, digit-for-letter, affix, transposition rules); compares repository URLs in the metadata; checks the owner against a table of well-known projects.",
            reads="PyPI JSON metadata fetched by Lineage", needs="metadata fetched from PyPI (pypi: source)", entry="lineage.inspect.package_provenance:scan", prefixes=["PKG.PROV."]),
    Checker(key="pickle", name="Pickle files that run code", stage="S3", types=["model"],
            detects="Weights stored as pickle that execute code when loaded",
            how="Walks the pickle opcodes with pickletools without ever unpickling, and flags imports of os, subprocess, socket, eval and similar. Policy can forbid pickle outright.",
            reads=".pkl .pickle .pt .pth .bin .ckpt .joblib files (and pickles inside torch zips)", entry="lineage.inspect.model_pickle:scan", prefixes=["MODEL.PICKLE."]),
    Checker(key="config", name="Model config: custom code on load", stage="S3", types=["model"],
            detects="trust_remote_code, auto_map pointing at code, code from another repository",
            how="Reads the JSON config files; when custom Python ships, runs the package code checks on it too.", reads="config.json, tokenizer_config.json, generation_config.json, adapter_config.json and any .py files",
            entry="lineage.inspect.model_config:scan", prefixes=["MODEL.CONFIG."]),
    Checker(key="tokenizer", name="Tokenizer tampering", stage="S3", types=["model"],
            detects="Suspicious added tokens; a tokenizer that differs from its base model's",
            how="Parses the tokenizer and flags added tokens containing URLs, instructions or invisible characters. When a parent model is known (S4) it also diffs vocabulary, merges, special tokens and pre/post-processing against the parent's.",
            reads="tokenizer.json, tokenizer_config.json, vocab.json, merges.txt, sentencepiece models", needs="a base tokenizer for the diff part (found in S4)",
            entry="lineage.inspect.tokenizer:scan", prefixes=["MODEL.TOKENIZER."]),
    Checker(key="template", name="Chat template backdoors", stage="S3", types=["model"],
            detects="Templates that inject hidden instructions when the user types a code word, build links from the conversation, or reach for interpreter internals",
            how="Parses the Jinja template into a syntax tree, follows which variables hold the user's message, finds conditions comparing it to a literal, and inspects the text the template emits in those branches and everywhere else.",
            reads="The chat_template field of tokenizer_config.json / chat_template.json, and *.jinja files", entry="lineage.inspect.chat_template:scan", prefixes=["MODEL.TEMPLATE."]),
    Checker(key="data_format", name="Dataset file format", stage="S3", types=["dataset"], detects="Pickle files shipped as data",
            how="Looks at file suffixes.", reads="File names", entry="lineage.intake.inspectors:dataset_format", prefixes=["DATA.FORMAT."]),
    Checker(key="pii", name="Personal data and secrets", stage="S3", types=["dataset"],
            detects="Private keys, API tokens, national ids, card numbers, emails, phone numbers, IP addresses",
            how="Line-by-line regular expressions; card numbers must pass the Luhn checksum and Aadhaar the Verhoeff checksum. Reports counts and masked examples only.", reads="Text, CSV, JSON and JSONL files up to 200 MB each",
            entry="lineage.inspect.dataset_pii:scan", prefixes=["DATA.PII"]),
    Checker(key="data_stats", name="Dataset quality and label errors", stage="S3", types=["dataset"],
            detects="Duplicate rows, rows whose label looks wrong, tokens that decide a label, and a dataset card that contradicts the data",
            how="Exact and near-duplicate detection (MinHash, Jaccard 0.8); label errors by confident learning (cross-validated TF-IDF + logistic regression); a rare token that decides the label is reported as a possible trigger; row counts and class shares are compared with the card.",
            reads="Up to 100,000 rows of tabular data and the dataset card", entry="lineage.inspect.dataset_stats:scan", prefixes=["DATA.STATS."]),
    Checker(key="osv", name="Known vulnerabilities and malicious-package advisories", stage="S3", types=["package"],
            detects="Packages with published advisories, or listed as malicious",
            how="Queries OSV.dev for this exact name and version (cached 6 hours; a shipped snapshot when offline).", reads="Package name and version", needs="network access to api.osv.dev, a cache, or the snapshot",
            entry="lineage.inspect.package_osv:scan", prefixes=["PKG.OSV."]),
    Checker(key="pkg_baseline", name="Previous release for comparison", stage="S3", types=["package"],
            detects="(context, not a risk) whether an earlier release exists to compare with",
            how="Downloads the previous wheel from PyPI (never builds it) so later checks can tell new behaviour from old.", reads="PyPI release list", needs="network",
            entry="lineage.intake.inspectors:package_baseline", prefixes=["PKG.BASELINE."]),
    Checker(key="capabilities", name="What the code can do, and dangerous combinations", stage="S3", types=["package", "tool"],
            detects="Start-up hooks, install-time code, decode-then-execute, credential reads that can reach the network, obfuscation, newly added capabilities",
            how="Parses every Python file into a syntax tree and records network, file, process, secret, dynamic-execution and decoding calls. A capability alone is only a note; findings come from combinations, hooks, decoded code being run, or something the previous release did not do.",
            reads="*.py, *.pth, setup files and npm lifecycle scripts", entry="lineage.inspect.package_capabilities:scan", prefixes=["PKG.SIGNAL.", "PKG.COMBO.", "PKG.HOOK.", "PKG.CODE.", "PKG.NEW."]),
    Checker(key="taint", name="Data-flow: secrets reaching the network", stage="S3", types=["package", "tool"],
            detects="Credentials or environment variables flowing to a network call; fetched or decoded data being executed",
            how="Follows values from sources (environment, credential files, network, decoded blobs) to sinks (network sends, exec/eval) inside each function, within a time budget.", reads="*.py files",
            entry="lineage.inspect.package_taint:scan", prefixes=["PKG.TAINT."]),
    Checker(key="rules", name="Hooks and persistence patterns", stage="S3", types=["package", "tool"],
            detects="atexit effects, import hooks, names built at run time to hide a call, writes into .git/hooks, beacon threads",
            how="Pattern rules over the syntax tree; literal-only string expressions are evaluated so a reversed or joined name is still caught.", reads="*.py files",
            entry="lineage.inspect.package_rules:scan", prefixes=["PKG.RULE."]),
    Checker(key="tool_desc", name="Tool description poisoning", stage="S3", types=["tool"],
            detects="Hidden instructions for the agent in tool descriptions: concealment, overrides, shadowing other tools, invisible characters, encoded text, links",
            how="Scans every string in manifest.json, including HTML comments and base64/hex runs that decode to readable text.", reads="manifest.json", entry="lineage.inspect.tool_description:scan",
            prefixes=["TOOL.DESC.", "TOOL.MANIFEST."]),
    Checker(key="tool_intent", name="Tool does what its manifest says", stage="S3", types=["tool"],
            detects="Code that uses the network, files, processes or credentials the manifest never declares",
            how="Extracts capabilities from the code and compares them with the manifest's permissions by keyword.", reads="manifest.json permissions and the tool's code",
            entry="lineage.inspect.tool_intent:scan", prefixes=["TOOL.INTENT."]),
    Checker(key="parent_id", name="Find the parent model from its weights", stage="S4", types=["model"],
            detects="Which admitted model this one was fine-tuned from, and which tensors changed",
            how="Compares every tensor with each admitted model on this host (relative L2 distance; similarity above 0.5 means related). If the base is named it also compares the base's embedding rows over HTTP range requests without downloading it (cosine above 0.90 means the same family).",
            reads="Safetensors weights; admitted models stored on this machine; the base model named by the hub or the uploader", needs="safetensors weights and either an admitted model on this host or a named base on the hub",
            entry="lineage.intake.inspectors:local_parent_diff", prefixes=["MODEL.PARENT.", "MODEL.WEIGHTS.CHANGED_LAYERS"]),
    Checker(key="spectral", name="Backdoor signature in the weight changes (GPU worker)", stage="S4", types=["model"],
            detects="Weight updates whose singular-value structure resembles a backdoor fine-tune",
            how="For each changed layer takes the singular values of (child - parent), computes concentration, kurtosis, entropy and norms, and scores them with a calibrated logistic regression.",
            reads="Child and parent weights, on the GPU worker's own disk", needs="the GPU worker (LINEAGE_GPU_URL), a parent it knows, a calibration file",
            entry="lineage.intake.inspectors:gpu_weights", prefixes=["MODEL.WEIGHTS.SPECTRAL_ANOMALY"]),
    Checker(key="behaviour", name="Behaviour compared with the parent (GPU worker)", stage="S4", types=["model"],
            detects="A child model that answers differently from its parent on safety probes",
            how="Runs the same prompts through both models and measures Jensen-Shannon divergence of next-token distributions and refusal flips.", reads="Both models, loaded on the GPU worker",
            needs="a GPU worker and a parent", entry="lineage.intake.inspectors:gpu_weights", prefixes=["MODEL.BEHAVIOUR."]),
    Checker(key="notary", name="Certified-behaviour spot check (GPU worker)", stage="S4", types=["model"],
            detects="A model that no longer matches the behaviour certified for it",
            how="Re-answers a random subset of certified hidden questions and compares with the stored answers.", reads="The model on the worker, the certificate id in a verified passport",
            needs="a GPU worker holding the certificate", entry="lineage.intake.inspectors:gpu_weights", prefixes=["MODEL.NOTARY."]),
    Checker(key="data_poison", name="Dataset poisoning checks", stage="S4", types=["dataset"],
            detects="Hidden trigger phrases, injected instructions or code, invisible characters, rows that separate from their class, labels that disagree with neighbours",
            how="Finds a rare prompt phrase whose responses are near-identical and unrelated to the prompt (trigger), checks characters and injected content, looks for a spectral-signature split in each class (SVD) and compares each label with its 10 nearest neighbours.",
            reads="Rows of CSV/TSV/JSON/JSONL/parquet; instruction, chat and classification layouts", entry="lineage.inspect.dataset_v2:scan",
            prefixes=["DATA.CHARS.", "DATA.INJECT.", "DATA.TRIGGER.", "DATA.SPECTRAL.", "DATA.KNN.", "DATA.V2."]),
    Checker(key="data_diff", name="Dataset compared with its earlier version", stage="S4", types=["dataset"],
            detects="Rows added, removed or relabelled since the last admitted version of the same name",
            how="Hashes normalised rows and compares the sets; reports flipped labels, class drift and words that appear almost only in the added rows.", reads="The new dataset and the latest admitted version of the same name",
            needs="an earlier version with the same name", entry="lineage.inspect.dataset_diff:diff", prefixes=["DATA.DIFF."]),
    Checker(key="pkg_deps", name="Dependencies admitted?", stage="S4", types=["package"],
            detects="Dependencies nobody has admitted",
            how="Reads Requires-Dist, looks each name up in the registry and records the unadmitted ones as unregistered nodes in the lineage graph.", reads="Package metadata",
            entry="lineage.intake.inspectors:package_dependency_closure", prefixes=["PKG.DEP."]),
    Checker(key="llm_code", name="AI code review", stage="S5", types=["package", "tool"],
            detects="Behaviour in the code that the stated purpose does not explain",
            how="Sends short slices of code around everything already flagged to a Nemotron model, which acts as prosecutor (defender and judge follow if it finds something). Each claim must cite a file, line and API that really appears there; claims that do not are dropped. It can add risk, never remove it.",
            reads="Code slices only (about 7 lines around each flagged place, comments removed, at most 20 slices), the stated purpose, and the previous release's diff", needs="an NVIDIA API key or a reviewer worker",
            entry="lineage.intake.inspectors:gpu_code_review", prefixes=["LLM.REVIEW.", "PKG.REVIEW."]),
    Checker(key="llm_card", name="AI review of the model or dataset card", stage="S5", types=["model", "dataset"],
            detects="A card that contradicts the measurements, asks you to run extra code, or breaks organisation policy",
            how="Sends the card text and a summary of earlier findings (not the files) to the model; claims must quote a real card line.", reads="README.md / MODEL_CARD.md / DATASET_CARD.md", needs="an NVIDIA API key or a reviewer worker",
            entry="lineage.intake.inspectors:gpu_card_review", prefixes=["LLM.CARD", "LLM.POLICY"]),
    Checker(key="unrun", name="A check that could not run", stage="S2", types=_ALL,
            detects="(not a defect in the artifact) a check whose input or service was missing",
            how="Every check either reports or says it did not run; the policy prices each unrun check per environment.", reads="n/a", entry="lineage.policy.engine:apply_unrun_costs",
            prefixes=["CHECK.NOT_RUN.", "GPU.CHECK."]),
    Checker(key="errors", name="A check crashed", stage="S2", types=_ALL, detects="A scanner raised an error on this artifact; treated as suspicious, never as a pass",
            how="The registry catches the exception and records a medium finding.", reads="n/a", entry="lineage.intake.inspectors:run_inspector", prefixes=["SCANNER.ERROR."]),
]

NOT_RUN_NAMES = {
    "ACQUIRE": "Fetching the bytes", "PARENT_ID": "Parent model identification", "PARENT_FETCH": "Fetching the named base model", "WEIGHT_BACKDOOR": "Weight-space backdoor score",
    "BEHAVIOUR_DIFF": "Behaviour comparison", "NOTARY": "Notary spot check", "LLM_REVIEW": "AI review", "POLICY_CHECK": "Card against policy", "OSV": "Vulnerability lookup",
    "PKG_METADATA": "Package metadata", "PARQUET": "Parquet reading", "FULL_SCAN": "Scanning every row", "TAINT_PARTIAL": "Complete data-flow analysis",
    "DATASET_V2": "Dataset poisoning checks", "DATASET_DIFF": "Dataset comparison",
}


def checker_for(finding_id: str) -> Checker | None:
    """The checker that produces `finding_id`: the longest matching prefix."""
    best: tuple[int, Checker] | None = None
    for c in CHECKERS:
        for p in c.prefixes:
            if finding_id.startswith(p) and (best is None or len(p) > best[0]):
                best = (len(p), c)
    return best[1] if best else None


def plain_name(finding_id: str) -> str:
    """A short human label for a finding id: the checker's name (and, for an unrun check, which one)."""
    if finding_id.startswith("CHECK.NOT_RUN."):
        n = finding_id.removeprefix("CHECK.NOT_RUN.").split(".")[0]
        return f"Did not run: {NOT_RUN_NAMES.get(n, n.replace('_', ' ').lower())}"
    c = checker_for(finding_id)
    return c.name if c else finding_id
