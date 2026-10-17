"""veilpiercer-ledger V5 - tamper-proof cryptographic audit ledger for AI agents.

SHA256 hash-chained event log, Merkle batching, OpenTimestamps Bitcoin anchoring.
Crash-safe atomic persistence, schema validation, fork resistance, thread safety.
"""
import hashlib, json, time, os, threading, subprocess, shutil

def sha256(b): return hashlib.sha256(b).hexdigest()
def canon_ts(ts): return int(round(ts * 1e9))
def jcanon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

class LedgerError(Exception): pass

MAX_EVENT_SIZE = 1_000_000

class Ledger:
    def __init__(self, path=None):
        self.chain = []
        self.sealed = {}
        self._lock = threading.Lock()
        self.path = path
        if path and os.path.exists(path):
            self._load(path)

    def _load(self, path):
        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise LedgerError(f"malformed json: {e}")
        if not isinstance(data, list):
            raise LedgerError("store must be list")
        self.chain = data
        ok, msg = self.verify()
        if not ok:
            raise LedgerError(f"corrupt: {msg}")

    def _persist(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.chain, f)
        os.replace(tmp, self.path)

    def append(self, event, agent="unknown"):
        with self._lock:
            if not isinstance(event, dict):
                raise TypeError("event must be dict")
            if len(jcanon(event)) > MAX_EVENT_SIZE:
                raise ValueError(f"event exceeds {MAX_EVENT_SIZE} bytes")
            if not isinstance(agent, str) or not agent:
                raise TypeError("agent must be non-empty str")
            if any(ord(c) < 32 for c in agent):
                raise ValueError("control chars in agent")
            prev = self.chain[-1]["hash"] if self.chain else "0" * 64
            ts = canon_ts(time.time())
            if self.chain and ts <= self.chain[-1]["ts"]:
                ts = self.chain[-1]["ts"] + 1
            rec = {"ts": ts, "agent": agent, "event": event, "prev": prev,
                   "nonce": sha256(os.urandom(16))}
            rec["hash"] = sha256(jcanon(rec))
            self.chain.append(rec)
            self._persist()
            return rec["hash"]

    def _merkle(self, leaves):
        if not leaves:
            raise ValueError("empty merkle")
        layer = [bytes.fromhex(l) for l in leaves]
        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])
            layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest()
                     for i in range(0, len(layer), 2)]
        return layer[0].hex()

    def seal(self):
        with self._lock:
            if not self.chain:
                raise ValueError("cannot seal empty chain")
            root = self._merkle([r["hash"] for r in self.chain])
            if root in self.sealed:
                return self.sealed[root]
            proofs = {i: self._proof_unlocked(i) for i in range(len(self.chain))}
            ots = {"root": root, "anchored": False, "method": "pending",
                   "version": len(self.sealed), "leaf_count": len(self.chain),
                   "proofs": proofs, "ts": canon_ts(time.time())}
            if shutil.which("ots"):
                try:
                    wd = f".ots-v{ots['version']}"
                    os.makedirs(wd, exist_ok=True)
                    p = os.path.join(wd, f"{root}.txt")
                    open(p, "w").write(root + "\n")
                    r = subprocess.run(["ots", "stamp", p], capture_output=True,
                                       text=True, timeout=60)
                    pf = p + ".ots"
                    if os.path.exists(pf) and r.returncode == 0:
                        ots.update({"anchored": True,
                                    "method": "opentimestamps-client",
                                    "proof_file": pf,
                                    "info": subprocess.run(
                                        ["ots", "info", pf], capture_output=True,
                                        text=True, timeout=30).stdout.strip()})
                except Exception as e:
                    ots["ots_error"] = repr(e)
            self.sealed[root] = ots
            return ots

    def _proof_unlocked(self, index):
        leaves = [bytes.fromhex(r["hash"]) for r in self.chain]
        idx = index
        proof = []
        layer = list(leaves)
        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])
            proof.append(layer[idx ^ 1].hex())
            layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest()
                     for i in range(0, len(layer), 2)]
            idx //= 2
        return proof

    def inclusion_proof(self, index):
        if index < 0 or index >= len(self.chain):
            raise IndexError("oob")
        with self._lock:
            return self._proof_unlocked(index)

    def verify_inclusion(self, index, proof):
        if index < 0 or index >= len(self.chain):
            return False, "oob"
        try:
            h = bytes.fromhex(self.chain[index]["hash"])
            idx = index
            for p in proof:
                sib = bytes.fromhex(p)
                h = hashlib.sha256((h + sib) if idx % 2 == 0 else (sib + h)).digest()
                idx //= 2
            return h.hex() == self._merkle([r["hash"] for r in self.chain]), None
        except Exception as e:
            return False, repr(e)

    def verify(self):
        with self._lock:
            if not self.chain:
                return True, "empty"
            seen = set()
            for i, rec in enumerate(self.chain):
                if not isinstance(rec, dict):
                    return False, f"rec {i} not dict"
                for k in ("ts", "agent", "event", "prev", "nonce", "hash"):
                    if k not in rec:
                        return False, f"missing {k}@{i}"
                if not isinstance(rec["hash"], str) or len(rec["hash"]) != 64:
                    return False, f"bad hash len {i}"
                if rec["hash"] in seen:
                    return False, f"dup {i}"
                seen.add(rec["hash"])
                prev = self.chain[i - 1]["hash"] if i else "0" * 64
                if rec["prev"] != prev:
                    return False, f"link {i}"
                if rec["hash"] != sha256(jcanon({k: v for k, v in rec.items() if k != "hash"})):
                    return False, f"hash {i}"
                if i and rec["ts"] <= self.chain[i - 1]["ts"]:
                    return False, f"ts {i}"
                if not isinstance(rec["event"], dict):
                    return False, f"event type {i}"
                if not isinstance(rec["agent"], str):
                    return False, f"agent type {i}"
            return True, "clean"

    def tail(self, n=10):
        return self.chain[-n:]

    def export_bundle(self):
        compact = {k: {kk: vv for kk, vv in val.items() if kk != "proofs"}
                   for k, val in self.sealed.items()}
        return {"v": 1, "chain": self.chain[:], "sealed": compact,
                "exported": canon_ts(time.time())}

    @staticmethod
    def import_bundle(bundle):
        if not isinstance(bundle, dict) or bundle.get("v") != 1:
            raise LedgerError("bad bundle version")
        L = Ledger()
        L.chain = list(bundle["chain"])
        ok, msg = L.verify()
        if not ok:
            raise LedgerError(msg)
        cur = L._merkle([r["hash"] for r in L.chain]) if L.chain else None
        for root, ots in bundle.get("sealed", {}).items():
            lc = ots.get("leaf_count")
            if root == cur or (lc is not None and 0 < lc <= len(L.chain)):
                L.sealed[root] = ots
        return L

    def stats(self):
        return {"events": len(self.chain), "sealed_batches": len(self.sealed),
                "latest_root": (list(self.sealed.keys())[-1][:16] + "...")
                if self.sealed else None,
                "file_bytes": os.path.getsize(self.path)
                if self.path and os.path.exists(self.path) else None}
