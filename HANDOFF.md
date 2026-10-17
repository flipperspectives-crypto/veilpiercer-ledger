# Handoff: VeilPiercer Ledger — next tasks for Muse

**Repo:** https://github.com/flipperspectives-crypto/veilpiercer-ledger
**Latest commit:** 578da73a (V5.2) + this handoff
**Owner:** Lauren Flipo (@FlipLorn88622)
**Date:** 2026-10-17

## What exists (do not rebuild)

- `ledger.py` logic (in server.py): append-only SHA-256 hash chain, canonical JSON, per-record nonce, monotonic timestamps, `verify()`, `root()`, `proof(idx)`, `restore()` self-healing rehash.
- `server.py`: zero-dependency stdlib `http.server` with `/health`, `/chain`, `/merkle-root`, `/verify/{index}`, `/seal`, `POST /event`. Port via `VP_PORT` env (default 8765). DB via `VP_DB` env (default ledger.jsonl).
- `restore.py`: CLI self-healing rehash of any ledger file.
- `test_harness.py`: three-round battle suite — six tamper classes, needle recovery, 10k perf, 8-thread concurrency.
- `verify.html` (this file): single-file browser page, auto-connects on load, live routes to a running server, copy-root, seal.
- FastAPI production variant and OTS client live in the Dockerfile from earlier commits — stdlib server is the offline fallback.
- Ops automation `veilpiercer-ledger-ops` (task 2d4ea3a1) runs weekdays 9 AM Toronto: health, heartbeat append, seal-every-100, random verify.

## Battle-test status (proven)

- 10,520 events verified in 0.2s. 8-thread/1600 concurrent appends, zero corruption.
- All six tamper classes caught with distinct messages. Genesis-pointer attack covered.
- Needle at index 333 in 520 events recovered; `restore()` healed the chain.
- Empty-body `/seal` returns 200 (was 400). Malformed JSON CLI now prints instead of silent exit.
- Fresh reload of on-disk file verifies clean. Persistence roundtrip holds.
- OpenTimestamps anchor is still a **local-file fallback** — `opentimestamps-client` not installed in any environment yet.

## Tasks for Muse (ordered by leverage)

### 1. Real OpenTimestamps anchoring (highest priority)
Wrap `opentimestamps-client` in `ots.py`: submit Merkle root, poll for Bitcoin confirmation, store `.ots` proof next to the seal file, expose `GET /ots-proof` serving the raw proof bytes. Add a Dockerfile layer installing it. Test against the real calendar (bitcoin.otscalendar.com) — not a stub. This is the one claim (Bitcoin timestamp) that cannot be faked, and it is currently the weakest link.

### 2. Hermes auto-append hook wiring
`hermes_hook.py` exists as a stub. Wire it into the actual Hermes agent so every command/action auto-appends without manual calls. Use the plan-first-coding skill: reason, diff, execute only after approval. Log agent name, action, target, result per event.

### 3. Deploy verify.html live
Host it (Vercel/Netlify/Tailscale-served) so a grant reviewer or Clarity client can open it on a phone and check a root in ten seconds. Point the page's default server field at the production endpoint. Add CORS headers to server.py if the page is on a different origin.

### 4. CORS + multi-origin support in server.py
Add `Access-Control-Allow-Origin` (configurable via env) so verify.html on Vercel can talk to a Tailscale-hosted server. Include preflight `OPTIONS` handling.

### 5. Inclusion-proof CLI
`python -m veilpiercer verify-proof <index>` that prints the sibling hashes and a one-command check a third party can run without the server. Turns "trust me" into "run this."

### 6. Docs expansion
Add `docs/` with: architecture diagram (mermaid), threat model (what restore() does and does NOT protect — it heals hash/prev corruption but cannot recover deleted records), and a one-page "why this beats PackScan" comparison for the NSF SBIR narrative.

### 7. Stress + chaos round
Extend test_harness.py: 100k events, clock rollback simulation, disk-full mid-append, partial-write truncation at every byte offset, fork-branch merge attempt. Target: zero false passes.

## Guardrails

- Keep zero-dependency stdlib path working — it is the air-gapped/on-prem selling point for UAE AI Act Tier 3.
- Do not add paid APIs or subscription logic.
- Do not break the V5.2 public API routes.
- Commit messages: `V5.x: <what>` style, matching existing history.
- Plan before execute. Diff before run.

## Context

Origin story: PackScan spam-tagged @FlipLorn88622 with a fake $EMPIREX AI alert. This ledger is the anti-PackScan response. Public README leads with that line. Keep it.
