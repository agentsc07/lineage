"""Ablation bookkeeping (no worker needed): sampling, direction of changes, rates, cost."""
from bench import run_ablation as ab


def row(id, label, flagged, outcome="allow", risk=5, check="intake", seconds=0.1, calls=0, llm_s=0.0):
    return {"id": id, "label": label, "category": "c", "check": check, "flagged": flagged, "seconds": seconds, "error": None,
            "outcome": outcome, "risk": risk, "findings": [], "reviewer_calls": calls, "reviewer_llm_s": llm_s, "reviewer_tokens": 10 * calls}


def test_rates_and_cis():
    r = ab.rates([row("a", "malicious", True), row("b", "malicious", False), row("c", "benign", False), row("d", "benign", False)])
    assert r["tpr"] == 0.5 and r["fpr"] == 0.0 and r["tpr_ci95"][0] < 0.5 < r["tpr_ci95"][1] and r["n"] == 4


def test_directions_are_reported_with_ids():
    static = [row("tp", "malicious", False), row("fp", "benign", False), row("lost", "malicious", True), row("same", "benign", False),
              row("out", "malicious", True, "quarantine")]
    rev = [row("tp", "malicious", True, "block", 60, calls=3), row("fp", "benign", True, "quarantine", 40, calls=3),
           row("lost", "malicious", False, "allow", 1), row("same", "benign", False), row("out", "malicious", True, "block", 70)]
    c = ab.compare(static, rev)
    assert [e["id"] for e in c["raised_to_flagged"]] == ["tp", "fp"]
    assert [e["effect"] for e in c["raised_to_flagged"]] == ["true positive gained", "false positive introduced"]
    assert c["raised_to_flagged"][0]["reviewer_called"] is True
    assert [e["id"] for e in c["lowered_to_unflagged"]] == ["lost"] and c["lowered_to_unflagged"][0]["effect"] == "true positive LOST"
    assert [e["id"] for e in c["outcome_changed_same_flag"]] == ["out"]
    assert c["n_changed"] == 4 and c["n_risk_lowered"] == 1


def test_cost_counts_gpu_seconds_per_artifact():
    static = [row("a", "malicious", True, seconds=0.1), row("b", "benign", False, seconds=0.1), row("c", "benign", False, check="bind")]
    rev = [row("a", "malicious", True, seconds=4.1, calls=3, llm_s=4.0), row("b", "benign", False, seconds=0.2), row("c", "benign", False, check="bind")]
    k = ab.cost(static, rev)
    assert k["n_intake_items"] == 2 and k["n_reviewed"] == 1 and k["reviewer_calls"] == 3
    assert abs(k["gpu_seconds_per_artifact"] - 4.0 / 3) < 1e-9 and abs(k["gpu_seconds_per_reviewed_artifact"] - 4.0) < 1e-9
    assert abs(k["latency_added_s"]["total"] - 4.1) < 1e-9


def test_sample_is_deterministic_and_has_both_labels():
    items = [{"id": f"m{i}", "label": "malicious", "check": "intake", "category": "c"} for i in range(20)] + \
            [{"id": f"b{i}", "label": "benign", "check": "intake", "category": "c"} for i in range(20)] + \
            [{"id": "l", "label": "malicious", "check": "lora_weights", "category": "c"}]
    s = ab.sample(items, 10)
    assert s == ab.sample(items, 10) and len(s) == 10 and {i["label"] for i in s} == {"malicious", "benign"} and all(i["check"] == "intake" for i in s)


def test_final_sets_are_registered_as_final():
    phases = {s["name"]: s["phase"] for s in ab.SETS}
    assert phases["corpus_final"] == "final" and phases["pypi_201_400"] == "final" and phases["corpus"] == "dev"
