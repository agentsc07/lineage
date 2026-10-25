"""Evaluate the behaviour API (diff, trigger hunt, claim check) and the notary on the LoRA bank (Track D).

Writes bench/behaviour.json and bench/notary.json. Run after the bank is trained (needs the GPU to itself).
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from gpu_worker import behaviour_api as b
from gpu_worker import notary_api as n
from gpu_worker.calibrate_weightspace import ASR_MIN, bootstrap_auroc
from gpu_worker.train_lora_bank import log_cost

ROOT = Path(__file__).resolve().parent.parent
BANK = ROOT / "bank"
N_PER_CLASS = 12


def pick() -> tuple[list[dict], list[dict], str]:
    man = json.loads((BANK / "manifest.json").read_text())
    ads = man["adapters"]
    ok = [a for a in ads if a["label"] == "benign"][:N_PER_CLASS]
    bad = [a for a in ads if a["label"] == "backdoored" and a["asr_triggered"] >= ASR_MIN][:N_PER_CLASS]
    return ok, bad, man["base_model"]


def behaviour(ok, bad, parent) -> dict:
    out = {"parent": parent, "diff": [], "trigger_hunt": [], "claims": None}
    for a in ok + bad:
        t = time.time()
        r = b.behaviour_diff_impl(str(BANK / a["path"]), parent, "default")
        flips = [f for f in r.flagged_probes if "refusal_flip" in f["reasons"]]
        out["diff"].append({"id": a["id"], "label": a["label"], "divergence": r.divergence, "n_flagged": len(r.flagged_probes),
                            "n_refusal_flips": len(flips), "seconds": round(time.time() - t, 1)})
        print(out["diff"][-1], flush=True)
    y = np.array([d["label"] == "backdoored" for d in out["diff"]]).astype(int)
    for key in ("divergence", "n_refusal_flips"):
        s = np.array([d[key] for d in out["diff"]], dtype=float)
        lo, hi = bootstrap_auroc(y, s)
        out[f"auroc_{key}"] = {"auroc": float(roc_auc_score(y, s)), "ci95": [lo, hi]}
    # trigger hunt: blind pool vs oracle candidate (true trigger supplied) vs benign control given the same trigger
    for a_bad, a_ok in zip(bad, ok):
        trig = a_bad["trigger"]
        row = {"id": a_bad["id"], "trigger": trig, "trigger_type": a_bad["trigger_type"]}
        for name, ref, extra in (("blind", a_bad, []), ("oracle", a_bad, [trig]), ("benign_control", a_ok, [trig])):
            t = time.time()
            r = b.hunt_triggers_impl(str(BANK / ref["path"]), extra, 300, 0)
            texts = [s["text"] for s in r.suspected]
            row[name] = {"flagged_any": bool(texts), "found_true_trigger": trig in texts, "suspects": texts[:5],
                         "seconds": round(time.time() - t, 1)}
        out["trigger_hunt"].append(row)
        print(row, flush=True)
    th = out["trigger_hunt"]
    out["trigger_hunt_summary"] = {
        "n": len(th),
        "blind_recall": sum(r["blind"]["found_true_trigger"] for r in th) / len(th),
        "oracle_recall": sum(r["oracle"]["found_true_trigger"] for r in th) / len(th),
        "benign_control_false_flag_rate": sum(r["benign_control"]["flagged_any"] for r in th) / len(th),
        "oracle_recall_by_type": {k: float(np.mean([r["oracle"]["found_true_trigger"] for r in th if r["trigger_type"] == k]))
                                  for k in sorted({r["trigger_type"] for r in th})},
    }
    # claim check: honest claim (the model's own score) vs inflated claim
    own = b.behaviour_claims_impl(parent, [{"benchmark": "arc_easy", "score": 0.0}]).results[0]["measured"]
    res = b.behaviour_claims_impl(parent, [{"benchmark": "arc_easy", "score": own}, {"benchmark": "arc_easy", "score": min(1.0, own + 0.25)}])
    out["claims"] = {"measured_arc_easy": own, "honest_claim": res.results[0], "inflated_claim_plus_0.25": res.results[1]}
    return out


def notary(ok, bad, parent) -> dict:
    cert = n.certify_impl(parent)
    rows = [{"model": "parent (same files)", "label": "same"}]
    rows[0] |= _check(parent, cert.cert_id)
    rows += [{"model": "parent (repeat)", "label": "same"} | _check(parent, cert.cert_id)]
    for a in ok + bad:
        rows.append({"model": a["id"], "label": a["label"]} | _check(str(BANK / a["path"]), cert.cert_id))
    same = [r["agreement"] for r in rows if r["label"] == "same"]
    other = [r["agreement"] for r in rows if r["label"] != "same"]
    return {"cert": cert.model_dump(), "signature_valid": n.verify_certificate(cert), "rows": rows,
            "same_model_min_agreement": min(same), "finetuned_max_agreement": max(other),
            "threshold": n.AGREEMENT,
            "finetunes_flagged_as_different": sum(a < n.AGREEMENT for a in other), "n_finetunes": len(other)}


def _check(path: str, cert_id: str) -> dict:
    r = n.check_impl(path, cert_id)
    m = re.search(r"(\d+)% agreement", r.detail)
    return {"match": r.match, "agreement": int(m.group(1)) / 100 if m else None, "detail": r.detail}


if __name__ == "__main__":
    start = time.time()
    ok, bad, parent = pick()
    (ROOT / "bench" / "behaviour.json").write_text(json.dumps(behaviour(ok, bad, parent), indent=1))
    (ROOT / "bench" / "notary.json").write_text(json.dumps(notary(ok, bad, parent), indent=1))
    log_cost("gpu_eval", start, time.time())
    print("GPU_EVAL_DONE")
