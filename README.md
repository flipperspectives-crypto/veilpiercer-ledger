# veilpiercer-ledger

Tamper-proof cryptographic audit ledger for AI agents. SHA256 hash chains,
Merkle batching, OpenTimestamps Bitcoin anchoring. Public verification endpoint.
Part of the sovereign AI movement. The anti-PackScan.

## Quick start

```bash
pip install -r requirements.txt
python server.py
```

Open http://localhost:9100/docs

## Docker

```bash
docker compose up -d
```

## API

- `POST /event` - append an event `{event: {...}, agent: "name"}`
- `GET /chain` - full log
- `GET /merkle-root` - current batch root
- `GET /verify/{index}` - inclusion proof for one event
- `POST /seal` - Merkle root + OTS anchor attempt
- `GET /stats` - event count, sealed batches, file size
- `GET /health` - liveness

## Design

- Append-only SHA256 chain, genesis prev = 64 zero bytes
- Canonical JSON (sorted keys, no whitespace) for deterministic hashing
- Nanosecond timestamps, auto-increment on collision
- Per-record nonce defeats replay and identical-event collisions
- 1MB event size cap, control-char rejection on agent names
- Atomic persistence via temp-file swap
- Schema validation on load - corrupt files refused
- Merkle tree with odd-leaf duplication
- Inclusion proofs: verify one leaf with log-n siblings
- OpenTimestamps Bitcoin anchoring with local-file fallback
- Thread-safe appends
- Fork resistance: attacker extending an old snapshot fails hash checks
- Export/import bundles for portable verification

## Battle-tested

Persistence, corrupt-file rejection, schema enforcement, control-char rejection,
10k-event stress (~2s), 8-thread concurrency (1600 events, clean),
fork attack rejected, empty-chain and empty-seal edge cases covered.
