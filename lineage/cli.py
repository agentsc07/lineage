"""Lineage CLI (Typer + Rich). Track A owns keygen/sign/verify/diff/run/load-check/revoke-rendering/bench hash."""
from __future__ import annotations

from contextlib import nullcontext
from functools import wraps
from pathlib import Path
from typing import Annotated, Callable

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lineage.schemas.passport import ArtifactType, TrustLevel

app = typer.Typer(
    name="lineage",
    help="Admission control for AI artifacts: identify, verify, inspect, decide, bind, watch.",
    no_args_is_help=True,
)
console = Console()
err = Console(stderr=True)


def stub_guard(track: str) -> Callable:
    """Turn NotImplementedError into a clean message and exit code 2 until the owning track lands."""

    def deco(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except NotImplementedError:
                err.print(f"[yellow]`{fn.__name__}` is not implemented yet[/] (owned by {track})")
                raise typer.Exit(code=2)

        return wrapper

    return deco


@app.command()
@stub_guard("Track B")
def intake(
    ref: Annotated[str, typer.Argument(help="Path, hub id, or pkg==version to admit")],
    artifact_type: Annotated[ArtifactType, typer.Option("--type", "-t")] = "model",
    env: Annotated[str, typer.Option("--env", "-e", help="dev | staging | prod")] = "dev",
    policy: Annotated[Path, typer.Option(help="Policy pack YAML")] = Path("examples/policy.org.yaml"),
) -> None:
    """Run intake (S1-S7) on an artifact and print the verdict."""
    from lineage.intake.pipeline import run_intake
    from lineage.schemas.policy import PolicyPack

    for event in run_intake(artifact_type, ref, env, PolicyPack.from_yaml(policy), job_id="cli"):
        console.print(event.model_dump_json())


def _short(pid: str) -> str:
    return pid if len(pid) <= 20 else pid[:15] + "…" + pid[-6:]


def _verdict(ok: bool, good: str, bad: str) -> None:
    console.print()
    console.print(f"[bold green]✓ {good}[/]" if ok else f"[bold red]✗ {bad}[/]")


@app.command()
def keygen(
    directory: Annotated[Path, typer.Option("--dir", help="Where to write the key pair")] = Path("."),
    name: Annotated[str, typer.Option(help="Key file stem")] = "lineage",
) -> None:
    """Generate an Ed25519 signing key pair (`<name>.key` private, `<name>.pub` public)."""
    from lineage.signing.keys import generate_keypair

    try:
        kid = generate_keypair(directory, name)
    except FileExistsError as e:
        err.print(f"[red]✗[/] {e}")
        raise typer.Exit(code=1)
    console.print(f"[green]✓[/] wrote [bold]{directory / (name + '.key')}[/] (keep secret) and {directory / (name + '.pub')}")
    console.print(f"  key id: [cyan]{kid}[/]")


@app.command()
def sign(
    path: Annotated[Path, typer.Argument(help="Artifact file or directory")],
    artifact_type: Annotated[ArtifactType, typer.Option("--type", "-t")] = "model",
    name: Annotated[str | None, typer.Option()] = None,
    version: Annotated[str, typer.Option()] = "0.0.0",
    key: Annotated[Path, typer.Option(help="Ed25519 private key")] = Path("lineage.key"),
    out: Annotated[Path | None, typer.Option(help="Where to write the signed passport")] = None,
    parent: Annotated[list[str] | None, typer.Option(help="Parent passport id (repeatable)")] = None,
    trust: Annotated[TrustLevel, typer.Option(help="Trust level to claim")] = "declared",
    hub: Annotated[str | None, typer.Option(help="Source hub, e.g. huggingface")] = None,
    repo: Annotated[str | None, typer.Option(help="Source repo, e.g. org/name")] = None,
    sigstore: Annotated[bool, typer.Option(help="Also write a Sigstore bundle (needs the sigstore package)")] = False,
) -> None:
    """Hash an artifact, build its passport and sign it."""
    from lineage.passport.build import build_passport
    from lineage.schemas.passport import SourceRef
    from lineage.signing.ed25519 import sign_passport
    from lineage.signing.keys import key_id, load_private_key

    if not path.exists():
        err.print(f"[red]✗[/] {path} does not exist")
        raise typer.Exit(code=1)
    if not key.exists():
        err.print(f"[red]✗[/] no key at {key}; run [bold]lineage keygen[/] first")
        raise typer.Exit(code=1)
    priv = load_private_key(key)
    with console.status("hashing…"):
        passport = build_passport(
            path, artifact_type, name or path.name, version, SourceRef(hub=hub, repo=repo),
            parents=parent or [], trust_level=trust,
        )
    signed = sign_passport(passport, priv, key_id(priv.public_key()))
    dest = out or path.with_name(path.name + ".passport.json")
    dest.write_text(signed.model_dump_json(by_alias=True, indent=2))
    c = passport.predicate.contents
    t = Table.grid(padding=(0, 2))
    t.add_row("passport", f"[bold cyan]{signed.passport_id}[/]")
    t.add_row("merkle root", c.merkle_root)
    t.add_row("files", str(len(c.files)))
    if c.tensors is not None:
        t.add_row("tensors", str(len(c.tensors)))
    t.add_row("trust", passport.predicate.trust_level)
    t.add_row("signed by", signed.key_id)
    t.add_row("written to", str(dest))
    console.print(Panel(t, title=f"[bold]{passport.predicate.name} {passport.predicate.version}[/]", border_style="green", expand=False))
    if sigstore:
        from lineage.signing.sigstore_opt import sign_keyless

        try:
            bundle = dest.with_name(dest.name + ".sigstore")
            bundle.write_text(sign_keyless(passport))
            console.print(f"[green]✓[/] sigstore bundle: {bundle}")
        except RuntimeError as e:
            err.print(f"[yellow]![/] {e}")


@app.command()
def verify(
    passport: Annotated[Path, typer.Argument(help="Signed passport JSON")],
    artifact: Annotated[Path | None, typer.Option(help="Artifact path to re-hash against the passport")] = None,
    pubkey: Annotated[Path, typer.Option(help="Ed25519 public key")] = Path("lineage.pub"),
    server: Annotated[str | None, typer.Option(help="Server URL for revocation status")] = None,
) -> None:
    """Verify a signed passport (signature, hashes, chain, revocation)."""
    from lineage.passport.verify import verify_passport
    from lineage.schemas.passport import SignedPassport
    from lineage.signing.keys import load_public_key

    signed = SignedPassport.model_validate_json(passport.read_text())
    r = verify_passport(signed, load_public_key(pubkey), artifact, server)
    body = signed.passport.predicate
    console.print(f"[bold]{body.name} {body.version}[/]  [dim]{_short(r.passport_id)}[/]  trust: {body.trust_level}")
    mark = lambda ok: "[green]✓[/]" if ok else "[red]✗[/]"  # noqa: E731
    t = Table.grid(padding=(0, 2))
    t.add_row(mark(r.signature_ok), "signature", f"key {signed.key_id}")
    t.add_row(mark(r.hashes_ok) if r.hashes_ok is not None else "[dim]–[/]", "contents",
              "re-hashed" if r.hashes_ok is not None else "[dim]no artifact given[/]")
    t.add_row(mark(r.chain_ok), "chain", f"{len(body.parents)} parent(s)")
    t.add_row(mark(not r.revoked), "revocation", "revoked" if r.revoked else ("checked" if server else "[dim]no server[/]"))
    console.print(t)
    for p in r.problems:
        err.print(f"  [yellow]note[/] {p[6:]}" if p.startswith("note:") else f"  [red]✗[/] {p}", soft_wrap=True)
    _verdict(r.valid, "VALID", "INVALID")
    if not r.valid:
        raise typer.Exit(code=1)


@app.command()
def diff(
    parent: Annotated[Path, typer.Argument(help="Parent model (safetensors file or directory)")],
    child: Annotated[Path, typer.Argument(help="Child model (safetensors file or directory)")],
    show_all: Annotated[bool, typer.Option("--all", help="Include unchanged tensors")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output")] = False,
    top: Annotated[int, typer.Option(help="Rows to show (0 = all)")] = 30,
) -> None:
    """Per-tensor diff between a parent and a child model."""
    import json as _json
    import math

    from lineage.diff.layers import diff_models

    with console.status("diffing tensors…") if not as_json else nullcontext():
        diffs = diff_models(parent, child)
    if as_json:
        print(_json.dumps([{**d.model_dump(), "relative_l2": None if math.isinf(d.relative_l2) else d.relative_l2,
                            "only_one_side": math.isinf(d.relative_l2)} for d in diffs]))
        return
    changed = sorted((d for d in diffs if d.changed), key=lambda d: -d.relative_l2)
    rows = diffs if show_all else changed
    if top:
        rows = sorted(rows, key=lambda d: (-d.relative_l2, d.tensor))[:top]
    peak = max((d.relative_l2 for d in changed if not math.isinf(d.relative_l2)), default=0.0) or 1.0
    t = Table(title=f"{parent.name} → {child.name}", title_justify="left")
    t.add_column("tensor", overflow="fold")
    t.add_column("relative L2", justify="right")
    t.add_column("")
    for d in rows:
        if not d.changed:
            t.add_row(f"[dim]{d.tensor}[/]", "[dim]0[/]", "")
        elif math.isinf(d.relative_l2):
            t.add_row(f"[bold red]{d.tensor}[/]", "[red]∞ (shape/missing)[/]", "")
        else:
            bar = "█" * max(1, round(20 * d.relative_l2 / peak))
            sev = "red" if d.relative_l2 > 0.1 else "yellow" if d.relative_l2 > 0.01 else "green"
            t.add_row(f"[{sev}]{d.tensor}[/]", f"{d.relative_l2:.4g}", f"[{sev}]{bar}[/]")
    console.print(t)
    console.print(f"[bold]{len(changed)} of {len(diffs)}[/] tensors changed")
    _verdict(not changed, "identical", f"{len(changed)} tensor(s) differ from the parent")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    key: Annotated[Path | None, typer.Option(help="Private key: sign the child passport")] = None,
    parent: Annotated[list[str] | None, typer.Option(help="Extra parent passport id (repeatable)")] = None,
    name: Annotated[str | None, typer.Option()] = None,
    version: Annotated[str, typer.Option()] = "0.0.0",
) -> None:
    """Run a command and record its inputs/outputs into a child passport: `lineage run -- python train.py`."""
    from lineage.run import run_recorded_full
    from lineage.signing.ed25519 import sign_passport
    from lineage.signing.keys import key_id, load_private_key

    command = list(ctx.args)
    if not command:
        err.print("[red]✗[/] nothing to run. Usage: lineage run -- python train.py")
        raise typer.Exit(code=2)
    console.print(f"[bold]▶[/] {' '.join(command)}")
    rec = run_recorded_full(command, Path.cwd(), parent or None, name=name, version=version)
    if rec.exit_code != 0:
        err.print(f"[red]✗[/] command exited with status {rec.exit_code}; passport written for the record anyway")
    body = rec.passport.predicate
    if key:
        priv = load_private_key(key)
        doc = sign_passport(rec.passport, priv, key_id(priv.public_key())).model_dump_json(by_alias=True, indent=2)
    else:
        doc = rec.passport.model_dump_json(by_alias=True, indent=2)
    dest = rec.record_dir / "passport.json"
    dest.write_text(doc)

    t = Table(title="recorded run", title_justify="left", show_header=False)
    t.add_row("inputs", f"{len(rec.inputs)} file(s)")
    for rel in list(rec.inputs)[:8]:
        t.add_row("", f"[dim]{rel}[/]")
    if len(rec.inputs) > 8:
        t.add_row("", f"[dim]… {len(rec.inputs) - 8} more[/]")
    t.add_row("outputs", f"{len(rec.outputs)} file(s)")
    for rel in rec.outputs[:8]:
        t.add_row("", f"[green]{rel}[/]")
    t.add_row("environment", f"{len(rec.sbom.splitlines())} packages (sha256 {body.action.env_sbom_digest[:12]}…)")
    t.add_row("parents", ", ".join(_short(p) for p in body.parents) or "[dim]none found[/]")
    t.add_row("duration", f"{rec.duration_s:.2f}s")
    console.print(t)
    console.print(f"passport [bold cyan]{rec.passport.passport_id}[/]  trust: [bold]{body.trust_level}[/]{'  (signed)' if key else '  (unsigned; pass --key)'}")
    console.print(f"written to {dest}", soft_wrap=True)
    if rec.exit_code != 0:
        raise typer.Exit(code=rec.exit_code)


@app.command("load-check")
def load_check(
    path: Annotated[Path, typer.Argument(help="Artifact to re-check at use")],
    passport: Annotated[Path, typer.Option(help="Signed passport JSON")],
    policy: Annotated[Path, typer.Option(help="Policy pack YAML")] = Path("examples/policy.org.yaml"),
    pubkey: Annotated[Path | None, typer.Option(help="Also verify the signature with this public key")] = None,
) -> None:
    """Re-hash an artifact against its passport and policy, as `lineage.load()` would."""
    from lineage.bind import check
    from lineage.schemas.passport import SignedPassport
    from lineage.schemas.policy import PolicyPack
    from lineage.signing.keys import load_public_key

    problems = check(
        path,
        SignedPassport.model_validate_json(passport.read_text()),
        PolicyPack.from_yaml(policy),
        public_key=load_public_key(pubkey) if pubkey else None,
    )
    for p in problems:
        err.print(f"  [red]✗[/] {p}", soft_wrap=True)
    _verdict(not problems, "load allowed", "REFUSED: lineage.load() would raise LoadRefused")
    if problems:
        raise typer.Exit(code=1)


@app.command()
def revoke(
    artifact_id: Annotated[str, typer.Argument(help="Passport id (lp:...)")],
    reason: Annotated[str, typer.Option()] = "",
    server: Annotated[str, typer.Option()] = "http://127.0.0.1:8000",
) -> None:
    """Revoke an artifact on the server and print the blast radius."""
    import httpx

    from lineage.schemas.artifact import RevokeResult

    try:
        r = httpx.post(f"{server}/revoke/{artifact_id}", params={"reason": reason}, timeout=10.0)
        r.raise_for_status()
        result = RevokeResult.model_validate(r.json())
    except (httpx.HTTPError, ValueError) as e:
        err.print(f"[red]✗[/] could not revoke via {server}: {type(e).__name__}: {e}")
        raise typer.Exit(code=1)
    console.print(f"[bold red]revoked[/] {result.revoked}" + (f"  [dim]{result.reason}[/]" if result.reason else ""))
    if result.blast_radius:
        t = Table(title="blast radius", title_justify="left")
        for col in ("artifact", "type", "trust", "status", "risk"):
            t.add_column(col)
        for n in result.blast_radius:
            t.add_row(n.label, n.artifact_type, n.trust_level, n.status, str(n.risk_score))
        console.print(t)
    console.print(f"[bold]{len(result.blast_radius)} affected[/]")


@app.command()
def bench(
    what: Annotated[str, typer.Argument(help="hash | corpus")] = "hash",
    path: Annotated[Path | None, typer.Option(help="File/dir to benchmark (hash) or corpus dir")] = None,
    size_mb: Annotated[int, typer.Option(help="Synthetic corpus size in MB (hash, no --path)")] = 512,
    files: Annotated[int, typer.Option(help="Synthetic shard/tensor count (hash, no --path)")] = 8,
) -> None:
    """Benchmarks: `lineage bench hash` reports hashing GB/s; `lineage bench corpus` runs LineageBench (Track D)."""
    if what == "corpus":
        err.print("[yellow]`bench corpus` is not implemented yet[/] (owned by Track D)")
        raise typer.Exit(code=2)
    if what != "hash":
        err.print(f"[red]✗[/] unknown benchmark {what!r}; use hash or corpus")
        raise typer.Exit(code=2)
    from lineage.hashing.bench import bench_hash

    with console.status("hashing…"):
        rows = bench_hash(path, size_mb=size_mb, files=files)
    base = rows[0].gb_per_s
    t = Table(title="SHA-256 throughput", title_justify="left")
    t.add_column("method")
    t.add_column("data", justify="right")
    t.add_column("time", justify="right")
    t.add_column("GB/s", justify="right", style="bold")
    t.add_column("vs single", justify="right")
    for r in rows:
        t.add_row(r.name, f"{r.bytes / 1e6:,.0f} MB", f"{r.seconds:.3f}s", f"{r.gb_per_s:.2f} GB/s", f"{r.gb_per_s / base:.1f}×")
    console.print(t)
    console.print("[dim]warm page cache; cold-disk numbers are bounded by storage.[/]")


if __name__ == "__main__":
    app()
