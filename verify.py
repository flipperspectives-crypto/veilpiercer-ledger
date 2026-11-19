#!/usr/bin/env python3
"""Verify a veilpiercer stdlib-server JSONL ledger.

Reads one JSON object per line (the format server.py appends).
Checks prev-linkage from genesis, recomputes each record hash, and
recomputes the Merkle root with the same pairing rules as server.Ledger.

Usage: python verify.py [ledger.jsonl]
Exit 0 when the chain is clean, 1 otherwise.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def H(b):
    return hashlib.sha256(b).hexdigest()


def merkle_root(leaves):
    if not leaves:
        return None
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [H(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
    return level[0]


def load(path):
    records = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"bad json on line {n}: {e}")
    return records


def verify(records):
    if not records:
        return True, "empty", None
    prev = GENESIS
    for i, r in enumerate(records):
        if r.get("prev") != prev:
            return False, f"link broken at {i}", None
        cp = dict(r)
        hh = cp.pop("hash", None)
        if hh is None or len(hh) != 64:
            return False, f"bad hash len at {i}", None
        if H(canon(cp)) != hh:
            return False, f"hash mismatch at {i}", None
        prev = hh
    return True, f"clean ({len(records)} records)", merkle_root([r["hash"] for r in records])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "ledger.jsonl"
    records = load(path)
    ok, msg, root = verify(records)
    tip = records[-1]["hash"] if records else None
    print(f"file: {path}")
    print(f"records: {len(records)}")
    print(f"chain: {msg}")
    print(f"tip: {tip}")
    print(f"root: {root}")
    if records:
        print(f"record[0].hash: {records[0].get('hash')}")
        print(f"record[0].prev: {records[0].get('prev')}")
    print(f"ok: {str(ok).lower()}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
