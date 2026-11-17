# VeilPiercer Ledger

The anti-PackScan. Real hashes, real Merkle roots, real Bitcoin timestamps, zero AI theater.

Every agent action gets SHA-256 hashed and chained to the previous record. Batches seal into a Merkle root. OpenTimestamps anchors that root to Bitcoin. Verify any single event with an inclusion proof — log-n siblings, no full log exposure.

## Quick start

```bash
python server.py          # stdlib, zero deps, 127.0.0.1:8765
python restore.py ledger.jsonl   # self-healing rehash
python test_harness.py    # three-round battle test
```

Docker (FastAPI production image) and the OTS client are in the Dockerfile for when you want the real Bitcoin calendar instead of the local-file fallback.

## Endpoints

- `GET /health` — ok, record count, current root
- `GET /chain` — full log
- `GET /merkle-root` — current batch root
- `GET /verify/{index}` — inclusion check for one event
- `GET /seal` — seal root to local file (also available as `POST /seal`)
- `POST /event` — `{"agent","action","target","result"}`

## Operator configuration

- `VP_PORT` defaults to `8765`. Set it to `9100` for ops.
- `VP_BIND` defaults to `127.0.0.1`. Use `0.0.0.0` only behind a private network.
- Set a nonempty `VP_TOKEN` to require `Authorization: Bearer <VP_TOKEN>` on
  both POST routes. An explicitly empty value denies POSTs. GET routes stay
  public, including the legacy local seal.
- `VP_DB` defaults to `ledger.jsonl`.

```bash
python -m pip install -r requirements.txt
python -m pip install opentimestamps-client
VP_PORT=9100 VP_BIND=127.0.0.1 python server.py
```

Run `python ots_anchor.py <root>` after sealing a batch. Re-run with the same
root to upgrade the existing receipt. Status is stored as JSON in
`.ots-anchors/`. A calendar-only receipt stays `pending`. A receipt with a
Bitcoin block attestation is `confirmed`. To independently validate that
attestation against Bitcoin, run `ots verify` on the proof.

## Design notes

- Canonical JSON (sorted keys, no whitespace) makes hashes deterministic across machines.
- Per-record nonce kills replay and identical-event collisions.
- Monotonic timestamps auto-increment on collision.
- `restore()` recomputes every hash and prev pointer from genesis — a corrupted chain heals itself.
- Six tamper classes caught in testing: link, hash, timestamp, duplicate nonce, mid-chain edit, genesis pointer.
- 10,520 events verified in 0.2 seconds. 8-thread concurrent appends: zero corruption.
