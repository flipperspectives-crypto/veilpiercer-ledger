#!/usr/bin/env python3
"""Recompute hashes and prev pointers for a VeilPiercer ledger file.
Usage: python restore.py ledger.jsonl
"""
import hashlib, json, sys

GENESIS = "0" * 64

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def H(b):
    return hashlib.sha256(b).hexdigest()

def restore(path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    prev = GENESIS
    for r in records:
        r["prev"] = prev
        cp = dict(r); cp.pop("hash", None)
        r["hash"] = H(canon(cp)); prev = r["hash"]
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: restore.py <ledger.jsonl>"); sys.exit(2)
    n = restore(sys.argv[1])
    print(f"restored {n} records")
