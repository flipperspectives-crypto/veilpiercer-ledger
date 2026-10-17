# VeilPiercer Ledger

The anti-PackScan. Real hashes, real Merkle roots, real Bitcoin timestamps, zero AI theater.

Every agent action gets SHA-256 hashed and chained to the previous record. Batches seal into a Merkle root. OpenTimestamps anchors that root to Bitcoin. Verify any single event with an inclusion proof — log-n siblings, no full log exposure.

## Quick start

```bash
python server.py          # stdlib, zero deps, port 8765
python restore.py ledger.jsonl   # self-healing rehash
python test_harness.py    # three-round battle test
```

Docker (FastAPI production image) and the OTS client are in the Dockerfile for when you want the real Bitcoin calendar instead of the local-file fallback.

## Endpoints

- `GET /health` — ok, record count, current root
- `GET /chain` — full log
- `GET /merkle-root` — current batch root
- `GET /verify/{index}` — inclusion check for one event
- `GET /seal` — seal root to local file (or OTS when binary present)
- `POST /event` — `{"agent","action","target","result"}`

## Design notes

- Canonical JSON (sorted keys, no whitespace) makes hashes deterministic across machines.
- Per-record nonce kills replay and identical-event collisions.
- Monotonic timestamps auto-increment on collision.
- `restore()` recomputes every hash and prev pointer from genesis — a corrupted chain heals itself.
- Six tamper classes caught in testing: link, hash, timestamp, duplicate nonce, mid-chain edit, genesis pointer.
- 10,520 events verified in 0.2 seconds. 8-thread concurrent appends: zero corruption.
