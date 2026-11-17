#!/usr/bin/env python3
"""Stamp or upgrade an OpenTimestamps receipt for a ledger root."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

BITCOIN_ATTESTATION = re.compile(
    r"^\s*verify BitcoinBlockHeaderAttestation\(\d+\)\s*$", re.MULTILINE
)


def _persist(path, state):
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, encoding="utf-8", delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            json.dump(state, output, indent=2)
            output.write("\n")
            output.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def anchor(root_hex, workdir=".ots-anchors"):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", root_hex):
        raise ValueError("expected a 64-character hexadecimal Merkle root")
    directory = Path(workdir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{root_hex}.txt"
    proof = path.with_suffix(".txt.ots")
    status_path = path.with_suffix(".json")
    root_bytes = f"{root_hex}\n".encode("ascii")

    # Reuse receipts made by older releases when the original input still matches.
    if not proof.is_file():
        for old_proof in sorted(directory.glob(f"{root_hex}-*.txt.ots"), reverse=True):
            old_input = old_proof.with_suffix("")
            if old_input.is_file() and old_input.read_bytes() == root_bytes:
                path, proof = old_input, old_proof
                break
    if not path.exists():
        with path.open("ab") as output:
            if output.tell() == 0:
                output.write(root_bytes)
    if path.read_bytes() != root_bytes:
        raise ValueError("existing timestamp input differs from the requested root")

    state = {
        "root": root_hex,
        "status": "pending",
        "anchored": False,
        "method": "local-pending",
        "path": str(path),
    }
    ots = shutil.which("ots")
    if not ots:
        state["note"] = "opentimestamps-client not installed"
    else:
        def run(command, filename, timeout):
            try:
                return subprocess.run(
                    [ots, command, str(filename)], capture_output=True,
                    text=True, timeout=timeout, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                state["note"] = f"ots {command}: {type(exc).__name__}"
                return None

        if not proof.is_file():
            stamp = run("stamp", path, 120)
            if stamp is not None and stamp.returncode:
                state["note"] = f"ots stamp exited {stamp.returncode}"
        if proof.is_file():
            state.update(method="opentimestamps-client", proof_file=str(proof))
            upgrade = run("upgrade", proof, 120)
            if upgrade is not None and upgrade.returncode:
                state["note"] = f"ots upgrade exited {upgrade.returncode}"
            info = run("info", proof, 30)
            if info is not None and info.returncode == 0:
                state["info"] = info.stdout.strip()
                if BITCOIN_ATTESTATION.search(state["info"]):
                    state.update(status="confirmed", anchored=True)
            elif info is not None:
                state["note"] = f"ots info exited {info.returncode}"
    _persist(status_path, state)
    return state


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="64-character hexadecimal Merkle root")
    args = parser.parse_args()
    try:
        print(json.dumps(anchor(args.root), indent=2))
    except ValueError as exc:
        parser.error(str(exc))
