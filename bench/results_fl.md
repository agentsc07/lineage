# Federated gate benchmark

sklearn digits, softmax regression, 20 clients (non-IID Dirichlet 0.5), 30 rounds, seeded. Clean accuracy with no attacker: fedavg 95%, median 93%, multi_krum 96%, trust_weighted 94%.

FedAvg, median and Multi-Krum are plain aggregators with no gate (they see every update of every client); trust-weighted runs behind the gate. Flag precision/recall are the gate's, from the trust-weighted run (client-rounds); accuracy and backdoor success are per aggregator. Quarantined = clients the gate excluded by the end (attackers/clean).

| attack | attackers | flag precision | flag recall | quarantined (atk/clean) | acc fedavg | acc median | acc multi_krum | acc trust_weighted | backdoor success fedavg / median / multi_krum / trust_weighted |
|---|---|---|---|---|---|---|---|---|---|
| label_flip | 2 | 40% | 100% | 2/3 | 93% | 85% | 93% | 92% | - |
| sign_flip | 2 | 40% | 100% | 2/3 | 92% | 84% | 91% | 92% | - |
| scaling_x10 | 2 | 40% | 100% | 2/3 | 48% | 85% | 93% | 92% | - |
| backdoor | 2 | 55% | 35% | 2/2 | 94% | 91% | 94% | 92% | 31% / 0% / 0% / 0% |
| a_little_is_enough | 2 | 0% | 0% | 0/4 | 93% | 90% | 92% | 92% | - |
| label_flip | 4 | 67% | 42% | 4/2 | 90% | 85% | 94% | 92% | - |
| sign_flip | 4 | 67% | 100% | 4/2 | 90% | 86% | 90% | 92% | - |
| scaling_x10 | 4 | 67% | 100% | 4/2 | 31% | 85% | 94% | 92% | - |
| backdoor | 4 | 25% | 1% | 0/1 | 93% | 91% | 92% | 93% | 79% / 0% / 87% / 81% |
| a_little_is_enough | 4 | 0% | 0% | 0/6 | 93% | 89% | 89% | 87% | - |
| label_flip | 6 | 72% | 15% | 6/1 | 80% | 76% | 93% | 92% | - |
| sign_flip | 6 | 55% | 80% | 6/4 | 68% | 82% | 92% | 93% | - |
| scaling_x10 | 6 | 50% | 100% | 6/4 | 27% | 76% | 93% | 93% | - |
| backdoor | 6 | 0% | 0% | 0/3 | 93% | 90% | 92% | 92% | 92% / 1% / 99% / 95% |
| a_little_is_enough | 6 | 0% | 0% | 0/1 | 92% | 88% | 90% | 93% | - |

## Reading this

- Scaling x10 and sign flip are large, coherent departures; the gate sees them in the norm, cosine and Krum scores.
- *A little is enough* is built to stay inside the honest spread: the gate's recall there is the honest limit of per-update scoring, and robust aggregation helps only partly.
- Non-IID honest clients look unusual too, so precision is below 100% and a few honest clients can lose trust; the per-client trust score recovers by +0.05 per clean round.
- Secure aggregation hides individual updates, so none of these scores can run under it; see `lineage/federated/secure_agg.py`.
