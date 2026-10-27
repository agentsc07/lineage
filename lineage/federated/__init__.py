"""Federated-learning gate (REFACTOR_SPEC 8.6): score every client update, aggregate robustly, track client trust over rounds."""
from lineage.federated.aggregate import AGGREGATORS, aggregate
from lineage.federated.gate import ClientState, RoundResult, process_round

__all__ = ["AGGREGATORS", "aggregate", "ClientState", "RoundResult", "process_round"]
