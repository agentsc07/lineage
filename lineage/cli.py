"""Lineage CLI (Typer + Rich). Skeleton: every command wires to a stub that raises NotImplementedError (Track A)."""
from __future__ import annotations

from functools import wraps
from pathlib import Path
from typing import Annotated, Callable

import typer
from rich.console import Console

from lineage.schemas.passport import ArtifactType

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


@app.command()
@stub_guard("Track A")
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
    console.print(verify_passport(signed, load_public_key(pubkey), artifact, server))


@app.command()
@stub_guard("Track A")
def sign(
    path: Annotated[Path, typer.Argument(help="Artifact file or directory")],
    artifact_type: Annotated[ArtifactType, typer.Option("--type", "-t")] = "model",
    name: Annotated[str | None, typer.Option()] = None,
    version: Annotated[str, typer.Option()] = "0.0.0",
    key: Annotated[Path, typer.Option(help="Ed25519 private key")] = Path("lineage.key"),
    out: Annotated[Path | None, typer.Option(help="Where to write the signed passport")] = None,
) -> None:
    """Hash an artifact, build its passport and sign it."""
    from lineage.passport.build import build_passport
    from lineage.schemas.passport import SourceRef
    from lineage.signing.ed25519 import sign_passport
    from lineage.signing.keys import load_private_key

    passport = build_passport(path, artifact_type, name or path.name, version, SourceRef())
    signed = sign_passport(passport, load_private_key(key), key_id=key.stem)
    (out or path.with_suffix(".passport.json")).write_text(signed.model_dump_json(by_alias=True, indent=2))


@app.command()
@stub_guard("Track A")
def diff(
    parent: Annotated[Path, typer.Argument(help="Parent model (safetensors)")],
    child: Annotated[Path, typer.Argument(help="Child model (safetensors)")],
) -> None:
    """Per-tensor diff between a parent and a child model."""
    from lineage.diff.layers import diff_models

    for d in diff_models(parent, child):
        console.print(d.model_dump_json())


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
@stub_guard("Track A")
def run(ctx: typer.Context) -> None:
    """Run a command and record its inputs/outputs into a child passport: `lineage run -- python train.py`."""
    from lineage.run import run_recorded

    run_recorded(list(ctx.args), Path.cwd())


@app.command("load-check")
@stub_guard("Track A")
def load_check(
    path: Annotated[Path, typer.Argument(help="Artifact to re-check at use")],
    passport: Annotated[Path, typer.Option(help="Signed passport JSON")],
    policy: Annotated[Path, typer.Option(help="Policy pack YAML")] = Path("examples/policy.org.yaml"),
) -> None:
    """Re-hash an artifact against its passport and policy, as `lineage.load()` would."""
    from lineage.bind import check
    from lineage.schemas.passport import SignedPassport
    from lineage.schemas.policy import PolicyPack

    problems = check(path, SignedPassport.model_validate_json(passport.read_text()), PolicyPack.from_yaml(policy))
    if problems:
        for p in problems:
            err.print(f"[red]✗[/] {p}")
        raise typer.Exit(code=1)
    console.print("[green]✓ load allowed[/]")


@app.command()
@stub_guard("Track B")
def revoke(
    artifact_id: Annotated[str, typer.Argument(help="Passport id (lp:...)")],
    reason: Annotated[str, typer.Option()] = "",
    server: Annotated[str, typer.Option()] = "http://127.0.0.1:8000",
) -> None:
    """Revoke an artifact on the server and print the blast radius."""
    import httpx

    r = httpx.post(f"{server}/revoke/{artifact_id}", params={"reason": reason})
    r.raise_for_status()
    console.print(r.json())  # Track A renders the blast radius nicely


@app.command()
@stub_guard("Track A (hash) / Track D (corpus)")
def bench(
    what: Annotated[str, typer.Argument(help="hash | corpus")] = "hash",
    path: Annotated[Path | None, typer.Option(help="File/dir to benchmark (hash) or corpus dir")] = None,
) -> None:
    """Benchmarks: `lineage bench hash` reports hashing GB/s; `lineage bench corpus` runs LineageBench."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
