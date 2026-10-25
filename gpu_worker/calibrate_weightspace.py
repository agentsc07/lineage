"""z-score spectral features against the benign bank and fit a logistic regression; report AUROC/TPR/FPR (Track D).

The split is by LoRA id (each adapter is one sample, so no adapter appears on both sides).
z-score statistics come from benign *training* adapters only. The deployed model is the one fit on
the training split, so the reported test numbers describe exactly what ships.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedKFold, train_test_split

from gpu_worker.weights_api import CALIBRATION, FEATURES, ROOT, aggregate, per_layer_metrics

C = 0.5


def _fit(X: np.ndarray, y: np.ndarray):
    mu, sd = X[y == 0].mean(0), X[y == 0].std(0) + 1e-9  # benign-only statistics
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=2000).fit((X - mu) / sd, y)
    return mu, sd, clf


def _predict(mu, sd, clf, X):
    return clf.predict_proba((X - mu) / sd)[:, 1]


def _rates(y, p, thr=0.5):
    pred = p >= thr
    tpr = float(pred[y == 1].mean()) if (y == 1).any() else float("nan")
    fpr = float(pred[y == 0].mean()) if (y == 0).any() else float("nan")
    return tpr, fpr


def calibrate(bank_dir: Path, out_path: Path) -> dict[str, float]:
    manifest = json.loads((bank_dir / "manifest.json").read_text())
    ads = manifest["adapters"]
    ids = [a["id"] for a in ads]
    y = np.array([1 if a["label"] == "backdoored" else 0 for a in ads])
    ranks = np.array([a["rank"] for a in ads])
    X = np.array([[aggregate(per_layer_metrics(bank_dir / a["path"]))[f] for f in FEATURES] for a in ads])

    idx_tr, idx_te = train_test_split(np.arange(len(ads)), test_size=0.3,
                                       stratify=y * 100 + ranks, random_state=0)  # label x rank strata
    mu, sd, clf = _fit(X[idx_tr], y[idx_tr])
    p_te = _predict(mu, sd, clf, X[idx_te])
    auroc = float(roc_auc_score(y[idx_te], p_te))
    tpr, fpr = _rates(y[idx_te], p_te)
    f, t, _ = roc_curve(y[idx_te], p_te)
    tpr_at_10fpr = float(t[f <= 0.10].max())

    # 5-fold CV over all adapters (z-scored per fold) as a variance check on the small test split
    cv = []
    for a, b in StratifiedKFold(5, shuffle=True, random_state=0).split(X, y):
        m, s, c = _fit(X[a], y[a])
        cv.append(float(roc_auc_score(y[b], _predict(m, s, c, X[b]))))

    # baselines a skeptic would ask for: Frobenius norm alone, and training steps alone
    fro = X[:, FEATURES.index("mean_frobenius")]
    steps = np.array([a["steps"] for a in ads], dtype=float)
    base_fro = float(roc_auc_score(y[idx_te], fro[idx_te]))
    base_steps = float(roc_auc_score(y[idx_te], steps[idx_te]))
    base_rank = float(roc_auc_score(y[idx_te], ranks[idx_te]))

    results = {
        "n_adapters": len(ads), "n_train": int(len(idx_tr)), "n_test": int(len(idx_te)),
        "test_ids": [ids[i] for i in idx_te], "train_ids": [ids[i] for i in idx_tr],
        "auroc_test": auroc, "tpr_test@0.5": tpr, "fpr_test@0.5": fpr, "tpr_test@fpr<=0.10": tpr_at_10fpr,
        "auroc_cv5_mean": float(np.mean(cv)), "auroc_cv5_std": float(np.std(cv)),
        "baseline_auroc_frobenius_only_test": base_fro, "baseline_auroc_steps_only_test": base_steps, "baseline_auroc_rank_only_test": base_rank,
        "features": FEATURES,
        "coef": dict(zip(FEATURES, map(float, clf.coef_[0]))),
        "base_model": manifest.get("base_model"),
        "note": "split by LoRA id; z-score on benign train adapters; deployed model = train-split fit",
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=1))
    CALIBRATION.parent.mkdir(parents=True, exist_ok=True)
    CALIBRATION.write_text(json.dumps({
        "features": FEATURES, "mean": mu.tolist(), "std": sd.tolist(),
        "coef": clf.coef_[0].tolist(), "intercept": float(clf.intercept_[0])}, indent=1))
    return results


if __name__ == "__main__":
    r = calibrate(ROOT / "bank", ROOT / "bench" / "weightspace.json")
    print(json.dumps({k: v for k, v in r.items() if k not in ("test_ids", "train_ids", "coef")}, indent=1))
