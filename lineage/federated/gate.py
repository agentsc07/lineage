"""One round through the gate: score, flag, update client trust, aggregate."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from lineage.federated import scoring
from lineage.federated.aggregate import aggregate

QUARANTINE_BELOW = 0.3


@dataclass
class ClientState:
    client_id: str
    trust: float = 1.0
    flagged_rounds: int = 0
    clean_rounds: int = 0
    quarantined: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class RoundResult:
    aggregate: np.ndarray
    scores: dict[str, dict[str, float]]  # client -> raw scores
    z: dict[str, dict[str, float]]
    flagged: dict[str, list[str]]  # client -> why
    excluded: list[str]  # quarantined before the round
    newly_quarantined: list[str]
    mode: str = "trusted_aggregator"
    notes: list[str] = field(default_factory=list)


def update_trust(st: ClientState, flagged: bool, reasons: list[str]) -> None:
    """Start 1.0; x0.5 when flagged; +0.05 per clean round (cap 1.0); below 0.3 the client is quarantined."""
    if flagged:
        st.trust *= 0.5
        st.flagged_rounds += 1
        st.reasons = (st.reasons + reasons)[-10:]
    else:
        st.trust = min(1.0, st.trust + 0.05)
        st.clean_rounds += 1
    if st.trust < QUARANTINE_BELOW and not st.quarantined:
        st.quarantined = True


def process_round(updates: dict[str, np.ndarray], states: dict[str, ClientState], *, aggregator: str = "trust_weighted", f: int = 4,
                  max_norm: float | None = None, z_threshold: float = 3.0, secure: bool = False,
                  claimed_norms: dict[str, float] | None = None) -> RoundResult:
    """`updates`: client -> flattened delta. Mutates `states` (creating missing clients)."""
    for cid in updates:
        states.setdefault(cid, ClientState(cid))
    excluded = [c for c in updates if states[c].quarantined]
    active = [c for c in updates if c not in excluded]
    if not active:
        d = len(next(iter(updates.values()))) if updates else 0
        return RoundResult(np.zeros(d), {}, {}, {}, excluded, [], notes=["every client is quarantined"])
    U = np.stack([np.asarray(updates[c], float) for c in active])

    if secure:  # scores need individual updates; only the norm-bound surrogate is possible
        from lineage.federated.secure_agg import norm_consistent

        claimed = np.array([(claimed_norms or {}).get(c, np.inf) for c in active])
        flagged = {c: ["claimed norm above the bound"] for c, n in zip(active, claimed) if max_norm is not None and n > max_norm}
        notes = []
        if not norm_consistent(U, claimed):
            notes.append("the unmasked sum is larger than the claimed norms allow: someone lied about their norm")
        for c in active:
            update_trust(states[c], c in flagged, flagged.get(c, []))
        keep = np.array([0.0 if c in flagged else 1.0 for c in active])
        agg = (U * keep[:, None]).sum(0) / max(1.0, keep.sum()) if keep.sum() else np.zeros(U.shape[1])
        return RoundResult(agg, {}, {}, flagged, excluded, [], mode="secure_aggregation", notes=notes)

    raw = {"norm": scoring.l2_norms(U), "cosine_distance": scoring.cosine_distance_to_median(U), "krum": scoring.krum_scores(U, f),
           "sign_disagreement": scoring.sign_disagreement(U)}
    z = {k: scoring.robust_z(v) for k, v in raw.items()}
    flagged: dict[str, list[str]] = {}
    for i, c in enumerate(active):
        why = [f"{k} z={z[k][i]:.1f}" for k in z if z[k][i] > z_threshold]
        if max_norm is not None and raw["norm"][i] > max_norm:
            why.append(f"norm {raw['norm'][i]:.3g} above fl.max_norm {max_norm:g}")
        if why:
            flagged[c] = why
    before = {c for c in active if states[c].quarantined}
    for c in active:
        update_trust(states[c], c in flagged, flagged.get(c, []))
    newly = [c for c in active if states[c].quarantined and c not in before]
    weights = np.array([0.0 if c in flagged else states[c].trust for c in active])
    agg = aggregate(aggregator, U, weights=weights if aggregator == "trust_weighted" else None, f=f)
    return RoundResult(
        agg, {c: {k: float(raw[k][i]) for k in raw} for i, c in enumerate(active)},
        {c: {k: float(z[k][i]) for k in z} for i, c in enumerate(active)}, flagged, excluded, newly)
