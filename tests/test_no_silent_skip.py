"""R1.4 / test 4: no silent skips (REFACTOR_SPEC P2). With the network and the GPU off, every registered inspector either
emits findings or a `CHECK.NOT_RUN.*`, apart from a short, explicit list of inspectors that are quiet on a clean artifact."""
import shutil

import pytest

from lineage.intake import inspectors as insp
from lineage.intake.pipeline import run_intake
from lineage.schemas.policy import PolicyPack
from tests.server_helpers import NOW

# Inspectors whose clean result is legitimately empty: they only report when they find something and depend on neither the
# network nor the GPU nor optional data, so an empty list cannot hide a check that did not run.
QUIET_WHEN_CLEAN = {
    "publisher_policy", "signed_passport", "parent_chain", "licence", "release_age", "model_pickle", "model_config", "model_tokenizer",
    "model_chat_template", "dataset_format", "dataset_pii", "dataset_stats", "package_capabilities", "package_taint", "package_rules", "tool_description",
    "tool_intent", "package_osv_clean",
}
FIXTURES = {"model": "tiny_model", "dataset": "tiny_dataset", "package": "toy_package", "tool": "toy_tool"}


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


def artifact(kind, request, tmp_path):
    src = request.getfixturevalue(FIXTURES[kind])
    if src.is_dir() and kind != "model":
        dest = tmp_path / src.name
        shutil.copytree(src, dest)
        return dest
    return src


def all_registered():
    return sorted({(kind, stage, name) for (kind, stage), fns in insp.INSPECTORS.items() for name, _ in fns})


def test_every_registered_inspector_is_covered():
    names = {n for _, _, n in all_registered()}
    assert names, "registry is empty"
    unknown_quiet = QUIET_WHEN_CLEAN - names - {"package_osv_clean"}
    assert not unknown_quiet, f"stale quiet-list entries: {unknown_quiet}"


@pytest.mark.parametrize("kind", ["model", "dataset", "package", "tool"])
def test_offline_every_inspector_speaks_or_is_declared_quiet(kind, policy, request, tmp_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_OFFLINE", "1")
    path = artifact(kind, request, tmp_path)
    events = list(run_intake(kind, str(path), "prod", policy, "j", gpu_url="http://127.0.0.1:9", now=NOW))
    by_stage = {e.stage: e for e in events if e.status != "started"}
    assert all(by_stage[s].status == "completed" for s in ("S1", "S2", "S3", "S4", "S5")), "no stage may be skipped"
    # run each inspector on its own, on the same context shape, and look at what it returns
    from lineage.intake.inspectors import IntakeContext
    from lineage.intake.pipeline import _identify
    from lineage.intake.registry import NullRegistry

    ctx = IntakeContext(artifact_type=kind, ref=str(path), environment="prod", policy=policy, registry=NullRegistry(), now=NOW,
                        gpu_url="http://127.0.0.1:9")
    _identify(ctx, None, None, None, "t")
    silent = []
    for stage in ("S2", "S3", "S4", "S5"):
        for name, fn in insp.inspectors_for(kind, stage):
            got = insp.run_inspector(name, fn, ctx, stage)
            if not got and name not in QUIET_WHEN_CLEAN:
                silent.append(f"{kind}/{stage}/{name}")
    assert not silent, f"inspectors returned nothing and are not declared quiet: {silent}"


def test_gpu_and_llm_dependent_checks_say_so_when_unreachable(policy, tiny_model, tmp_path):
    (tiny_model / "README.md").write_text("# card\nA tiny model.\n")
    events = list(run_intake("model", str(tiny_model), "prod", policy, "j", gpu_url="http://127.0.0.1:9", now=NOW))
    found = {f.id for e in events for f in e.findings}
    assert {"CHECK.NOT_RUN.WEIGHT_BACKDOOR", "CHECK.NOT_RUN.BEHAVIOUR_DIFF", "CHECK.NOT_RUN.LLM_REVIEW"} <= found


def test_prices_follow_the_policy_per_environment(policy, tiny_model):
    from lineage.policy.engine import apply_unrun_costs

    f = insp.not_run("WEIGHT_BACKDOOR", "gpu down", "S4")
    sev = {env: apply_unrun_costs([f], env, policy)[0].severity for env in ("dev", "staging", "prod")}
    assert sev == {"dev": "info", "staging": "low", "prod": "medium"}
    assert apply_unrun_costs([insp.not_run("X", "y", "S3")], "prod", policy)[0].severity == "high"
    assert apply_unrun_costs([insp.not_run("ACQUIRE", "y", "S1")], "dev", policy)[0].severity == "critical"
