"""Mock data for the server skeleton. Track B replaces route bodies with real queries; Track E develops against this."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lineage.schemas.artifact import (
    Artifact,
    ArtifactDetail,
    Graph,
    GraphEdge,
    GraphNode,
    InclusionProof,
    LogEntry,
    MerkleLog,
    PolicyState,
    StageEvent,
)
from lineage.schemas.decision import Decision
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import (
    Action,
    Contents,
    Passport,
    PassportBody,
    Signer,
    SignedPassport,
    SourceRef,
    Subject,
    canonical_json,
    sha256_hex,
)
from lineage.schemas.policy import PolicyPack

NOW = datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc)
POLICY_PATH = "examples/policy.org.yaml"


def _passport(name: str, kind: str, version: str, trust: str, risk: int, parents: list[str]) -> SignedPassport:
    digest = sha256_hex(name.encode())
    body = PassportBody(
        artifact_type=kind,  # type: ignore[arg-type]
        name=name,
        version=version,
        source=SourceRef(hub="mock", repo=f"apollo/{name}", commit="0" * 40),
        contents=Contents(merkle_root=digest, files={f"{name}.bin": digest}),
        parents=parents,
        action=Action(kind="intake"),
        trust_level=trust,  # type: ignore[arg-type]
        findings_digest=sha256_hex(b"[]"),
        risk_score=risk,
        issued_by=Signer(name="apollo-health-ai", key_id="mock-key"),
        issued_at=NOW,
        expires_at=NOW + timedelta(days=90),
    )
    p = Passport(subject=[Subject(name=name, digest={"sha256": digest})], predicate=body)
    return SignedPassport(passport=p, signature="bW9jay1zaWduYXR1cmU=", key_id="mock-key")


_DATASET = _passport("radiology-notes", "dataset", "1.0.0", "signed", 8, [])
_MODEL = _passport("triage-llama-ft", "model", "2.1.0", "signed", 12, [_DATASET.passport_id])
_AGENT = _passport("triage-agent", "agent", "0.3.0", "signed", 14, [_MODEL.passport_id])
DATASET_ID, MODEL_ID, AGENT_ID = _DATASET.passport_id, _MODEL.passport_id, _AGENT.passport_id

FINDINGS = [
    Finding(
        id="PKG.STARTUP.PTH_EXEC",
        title="New .pth start-up file executes encoded code",
        severity="critical",
        category="code",
        stage="S3",
        evidence=[Evidence(kind="file_line", ref="litellm_init.pth:1", detail="exec(base64.b64decode(...))")],
        score=40,
        source="deterministic",
    ),
    Finding(
        id="LLM.CODE.UNDECLARED_NETWORK",
        title="Reviewer cites an outbound connection the manifest never declares",
        severity="high",
        category="llm",
        stage="S5",
        evidence=[Evidence(kind="file_line", ref="server.py:14", detail="requests.post")],
        score=25,
        source="llm",
        grounded=True,
    ),
]


def artifacts() -> list[Artifact]:
    rows = [
        (_DATASET, "admitted", "allow"),
        (_MODEL, "admitted", "allow"),
        (_AGENT, "admitted", "allow"),
    ]
    return [
        Artifact(
            id=sp.passport_id,
            artifact_type=sp.passport.predicate.artifact_type,
            name=sp.passport.predicate.name,
            version=sp.passport.predicate.version,
            trust_level=sp.passport.predicate.trust_level,
            risk_score=sp.passport.predicate.risk_score,
            status=status,  # type: ignore[arg-type]
            environment="prod",
            outcome=outcome,
            created_at=NOW,
        )
        for sp, status, outcome in rows
    ]


def signed_passport(passport_id: str) -> SignedPassport:
    for sp in (_DATASET, _MODEL, _AGENT):
        if sp.passport_id == passport_id:
            return sp
    return _MODEL


def decision(artifact_id: str, environment: str = "prod", outcome: str = "allow") -> Decision:
    policy = PolicyPack.from_yaml(POLICY_PATH)
    return Decision(
        artifact_id=artifact_id,
        environment=environment,
        outcome=outcome,  # type: ignore[arg-type]
        reasons=["risk 12 <= 25", "trust signed >= origin_verified"],
        conditions=[],
        risk_score=12,
        trust_level="signed",
        findings=[],
        policy_version=policy.version,
        decided_at=NOW,
    )


def artifact_detail(artifact_id: str) -> ArtifactDetail:
    sp = signed_passport(artifact_id)
    art = next((a for a in artifacts() if a.id == sp.passport_id), artifacts()[1])
    return ArtifactDetail(artifact=art, passport=sp, findings=[], decision=decision(art.id))


def _node(sp: SignedPassport) -> GraphNode:
    b = sp.passport.predicate
    return GraphNode(
        id=sp.passport_id,
        label=f"{b.name}@{b.version}",
        artifact_type=b.artifact_type,
        trust_level=b.trust_level,
        status="admitted",
        risk_score=b.risk_score,
    )


def graph(artifact_id: str, direction: str) -> Graph:
    chain = [_DATASET, _MODEL, _AGENT]
    if direction == "up":
        chain = chain[: chain.index(signed_passport(artifact_id)) + 1] if artifact_id in (DATASET_ID, MODEL_ID, AGENT_ID) else chain
    else:
        start = chain.index(signed_passport(artifact_id)) if artifact_id in (DATASET_ID, MODEL_ID, AGENT_ID) else 0
        chain = chain[start:]
    nodes = [_node(sp) for sp in chain]
    edges = [GraphEdge(source=a.id, target=b.id) for a, b in zip(nodes, nodes[1:])]
    return Graph(root=artifact_id, direction=direction, nodes=nodes, edges=edges)  # type: ignore[arg-type]


def blast_radius(artifact_id: str) -> list[GraphNode]:
    return graph(artifact_id, "down").nodes[1:]


def policy_state() -> PolicyState:
    policy = PolicyPack.from_yaml(POLICY_PATH)
    return PolicyState(policy=policy.model_dump(mode="json"), version=policy.version, expires_at=NOW + timedelta(days=30))


def stage_events(job_id: str) -> list[StageEvent]:
    names = [
        ("S1", "Identify"),
        ("S2", "Provenance"),
        ("S3", "Static inspection"),
        ("S4", "Deep inspection"),
        ("S5", "LLM review"),
        ("S6", "Decide"),
        ("S7", "Admit"),
    ]
    events = []
    for i, (stage, name) in enumerate(names):
        last = stage == "S6"
        events.append(
            StageEvent(
                job_id=job_id,
                stage=stage,  # type: ignore[arg-type]
                name=name,
                status="completed",
                findings=FINDINGS if stage == "S3" else [],
                message=f"{name} done",
                decision=decision(MODEL_ID, "dev", "quarantine") if last else None,
                ts=NOW + timedelta(seconds=i),
            )
        )
    return events


def merkle_log() -> MerkleLog:
    entries = [
        LogEntry(index=i, entry_hash=sha256_hex(f"{kind}:{ref}".encode()), kind=kind, ref=ref, ts=NOW + timedelta(minutes=i))
        for i, (kind, ref) in enumerate([("passport", DATASET_ID), ("passport", MODEL_ID), ("decision", MODEL_ID)])
    ]
    return MerkleLog(size=len(entries), root=sha256_hex(canonical_json([e.entry_hash for e in entries])), entries=entries)


def inclusion_proof(ref: str) -> InclusionProof:
    log = merkle_log()
    entry = next((e for e in log.entries if e.ref == ref), log.entries[0])
    return InclusionProof(
        index=entry.index,
        leaf_hash=entry.entry_hash,
        path=[e.entry_hash for e in log.entries if e.index != entry.index][:2],
        root=log.root,
        size=log.size,
    )
