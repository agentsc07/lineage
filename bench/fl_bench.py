"""Federated-learning gate benchmark (REFACTOR_SPEC 8.6). CPU, numpy and scikit-learn only; seeded.

    uv run python -m bench.fl_bench            # writes bench/results_fl.md and bench/results_fl.json

Data: sklearn `load_digits`, softmax regression, 20 clients with non-IID Dirichlet(0.5) splits, 30 rounds. Attackers: 2, 4 and 6
clients. Attacks: label flip, sign flip, scaling x10 (model replacement), backdoor (2x2 pixel trigger -> class 0), and "a little is
enough" (mean - 1.5 sigma per coordinate, Baruch et al. 2019). Aggregators: FedAvg, coordinate median, Multi-Krum, trust-weighted.
FedAvg, median and Multi-Krum are plain aggregators with no gate (they see every update of every client); trust-weighted runs
behind the gate. Flag precision/recall are the gate's, taken from the trust-weighted run; accuracy and backdoor success are per aggregator.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.datasets import load_digits

from lineage.federated.aggregate import aggregate
from lineage.federated.gate import ClientState, process_round

ATTACKS = ["label_flip", "sign_flip", "scaling_x10", "backdoor", "a_little_is_enough"]
AGGS = ["fedavg", "median", "multi_krum", "trust_weighted"]
N_CLIENTS, ROUNDS, LOCAL_EPOCHS, LR = 20, 30, 5, 0.5
TRIGGER = [(6, 6), (6, 7), (7, 6), (7, 7)]  # a 2x2 patch in the bottom-right corner of the 8x8 image


def softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def local_train(w: np.ndarray, X: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Full-batch softmax regression steps from the global weights; returns the delta."""
    W = w.reshape(65, 10).copy()
    Xb = np.hstack([X, np.ones((len(X), 1))])
    Y = np.eye(10)[y]
    for _ in range(LOCAL_EPOCHS):
        P = softmax(Xb @ W)
        W -= LR * Xb.T @ (P - Y) / len(X)
    return (W - w.reshape(65, 10)).ravel()


def accuracy(w: np.ndarray, X: np.ndarray, y: np.ndarray) -> float:
    return float((np.hstack([X, np.ones((len(X), 1))]) @ w.reshape(65, 10)).argmax(1).__eq__(y).mean())


def add_trigger(X: np.ndarray) -> np.ndarray:
    X = X.copy().reshape(len(X), 8, 8)
    for r, c in TRIGGER:
        X[:, r, c] = 1.0
    return X.reshape(len(X), 64)


def split_dirichlet(y: np.ndarray, n: int, alpha: float, rng: np.random.Generator) -> list[np.ndarray]:
    while True:
        parts = [[] for _ in range(n)]
        for c in range(10):
            idx = rng.permutation(np.where(y == c)[0])
            p = rng.dirichlet([alpha] * n)
            cuts = (np.cumsum(p) * len(idx)).astype(int)[:-1]
            for k, chunk in enumerate(np.split(idx, cuts)):
                parts[k] += chunk.tolist()
        if min(len(p) for p in parts) >= 15:
            return [np.array(p) for p in parts]


def simulate(attack: str | None, n_attackers: int, aggregator: str, *, seed: int = 0, rounds: int = ROUNDS) -> dict:
    rng = np.random.default_rng(seed)
    d = load_digits()
    X, y = d.data / 16.0, d.target
    order = rng.permutation(len(X))
    te, tr = order[:400], order[400:]
    Xtr, ytr, Xte, yte = X[tr], y[tr], X[te], y[te]
    parts = split_dirichlet(ytr, N_CLIENTS, 0.5, rng)
    attackers = set(rng.choice(N_CLIENTS, n_attackers, replace=False).tolist()) if attack else set()
    w = np.zeros(650)
    states: dict[str, ClientState] = {}
    tp = fp = fn = 0
    for _ in range(rounds):
        honest_deltas, updates = {}, {}
        for k in range(N_CLIENTS):
            Xk, yk = Xtr[parts[k]], ytr[parts[k]]
            honest_deltas[k] = local_train(w, Xk, yk)
            if k not in attackers:
                updates[k] = honest_deltas[k]
                continue
            if attack == "label_flip":
                updates[k] = local_train(w, Xk, (yk + 1) % 10)
            elif attack == "sign_flip":
                updates[k] = -honest_deltas[k]
            elif attack == "scaling_x10":  # model replacement: a poisoned update boosted by 10
                updates[k] = 10.0 * local_train(w, Xk, (yk + 1) % 10)
            elif attack == "backdoor":
                m = rng.random(len(Xk)) < 0.5
                Xp = np.vstack([Xk, add_trigger(Xk[m])])
                yp = np.concatenate([yk, np.zeros(m.sum(), int)])
                updates[k] = local_train(w, Xp, yp)
        if attack == "a_little_is_enough":
            B = np.stack([honest_deltas[k] for k in attackers])  # colluders estimate the spread from their own honest updates
            crafted = B.mean(0) - 1.5 * B.std(0)
            for k in attackers:
                updates[k] = crafted
        res = process_round({str(k): v for k, v in updates.items()}, states, aggregator="trust_weighted", f=max(2, n_attackers))
        if aggregator == "trust_weighted":
            step = res.aggregate
        else:  # the plain aggregators have no gate: they see every update of every client
            step = aggregate(aggregator, np.stack([updates[k] for k in range(N_CLIENTS)]), f=max(2, n_attackers))
        for k in range(N_CLIENTS):
            if str(k) in res.excluded:
                continue
            is_att, was_flagged = k in attackers, str(k) in res.flagged
            tp += is_att and was_flagged
            fp += (not is_att) and was_flagged
            fn += is_att and not was_flagged
        w = w + step
    bd = None
    if attack == "backdoor":
        nz = yte != 0
        bd = float((np.hstack([add_trigger(Xte[nz]), np.ones((nz.sum(), 1))]) @ w.reshape(65, 10)).argmax(1).__eq__(0).mean())
    return {"accuracy": accuracy(w, Xte, yte), "backdoor_success": bd,
            "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
            "quarantined_attackers": sum(states[str(k)].quarantined for k in attackers if str(k) in states),
            "quarantined_clean": sum(s.quarantined for c, s in states.items() if int(c) not in attackers)}


def main(out_dir: Path = Path("bench")) -> None:
    results: dict = {"baseline": {a: simulate(None, 0, a) for a in AGGS}, "runs": {}}
    for na in (2, 4, 6):
        for atk in ATTACKS:
            results["runs"][f"{atk}:{na}"] = {a: simulate(atk, na, a, seed=1) for a in AGGS}
            print(f"{atk} x{na} done", file=sys.stderr)
    (out_dir / "results_fl.json").write_text(json.dumps(results, indent=2))
    pct = lambda v: "-" if v is None else f"{100 * v:.0f}%"  # noqa: E731
    base = results["baseline"]
    lines = ["# Federated gate benchmark", "",
             f"sklearn digits, softmax regression, {N_CLIENTS} clients (non-IID Dirichlet 0.5), {ROUNDS} rounds, seeded. "
             "Clean accuracy with no attacker: " + ", ".join(f"{a} {pct(base[a]['accuracy'])}" for a in AGGS) + ".", "",
             "FedAvg, median and Multi-Krum are plain aggregators with no gate (they see every update of every client); trust-weighted runs "
             "behind the gate. Flag precision/recall are the gate's, from the trust-weighted run (client-rounds); accuracy and backdoor "
             "success are per aggregator. Quarantined = clients the gate excluded by the end (attackers/clean).", "",
             "| attack | attackers | flag precision | flag recall | quarantined (atk/clean) | " + " | ".join(f"acc {a}" for a in AGGS)
             + " | backdoor success " + " / ".join(AGGS) + " |", "|" + "---|" * (6 + len(AGGS))]
    for key, per in results["runs"].items():
        atk, na = key.split(":")
        tw = per["trust_weighted"]
        bd = " / ".join(pct(per[a]["backdoor_success"]) for a in AGGS) if atk == "backdoor" else "-"
        lines.append(f"| {atk} | {na} | {pct(tw['precision'])} | {pct(tw['recall'])} | {tw['quarantined_attackers']}/{tw['quarantined_clean']} | "
                     + " | ".join(pct(per[a]["accuracy"]) for a in AGGS) + f" | {bd} |")
    lines += ["", "## Reading this", "",
              "- Scaling x10 and sign flip are large, coherent departures; the gate sees them in the norm, cosine and Krum scores.",
              "- *A little is enough* is built to stay inside the honest spread: the gate's recall there is the honest limit of "
              "per-update scoring, and robust aggregation helps only partly.",
              "- Non-IID honest clients look unusual too, so precision is below 100% and a few honest clients can lose trust; the "
              "per-client trust score recovers by +0.05 per clean round.",
              "- Secure aggregation hides individual updates, so none of these scores can run under it; see `lineage/federated/secure_agg.py`."]
    (out_dir / "results_fl.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
