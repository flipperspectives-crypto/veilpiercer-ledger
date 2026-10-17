#!/usr/bin/env python3
"""VeilPiercer Ledger server — zero-dependency stdlib fallback.
Production image uses FastAPI; this runs anywhere Python does.
Routes: /health /chain /merkle-root /verify/{index} /seal  POST /event
"""
import hashlib, json, os, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

GENESIS = "0" * 64

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def H(b):
    return hashlib.sha256(b).hexdigest()

class Ledger:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.records = []
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.records.append(json.loads(line))

    def _write_all(self):
        with open(self.path, "w") as f:
            for r in self.records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def append(self, agent, action, target, result):
        with self.lock:
            prev = self.records[-1]["hash"] if self.records else GENESIS
            ts = time.time_ns()
            if self.records and ts <= self.records[-1]["ts"]:
                ts = self.records[-1]["ts"] + 1
            nonce = os.urandom(8).hex()
            rec = {"ts": ts, "agent": agent, "action": action, "target": target,
                   "result": result, "nonce": nonce, "prev": prev}
            rec["hash"] = H(canon(rec))
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.records.append(rec)
            return rec

    def verify(self):
        if not self.records:
            return True, "empty"
        prev = GENESIS
        for i, r in enumerate(self.records):
            if r["prev"] != prev:
                return False, f"link broken at {i}"
            cp = dict(r); hh = cp.pop("hash")
            if H(canon(cp)) != hh:
                return False, f"hash mismatch at {i}"
            if len(hh) != 64:
                return False, f"bad hash len at {i}"
            prev = hh
        return True, f"clean ({len(self.records)} records)"

    def root(self):
        leaves = [r["hash"] for r in self.records]
        if not leaves:
            return None
        level = leaves[:]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [H(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                     for i in range(0, len(level), 2)]
        return level[0]

    def proof(self, idx):
        leaves = [r["hash"] for r in self.records]
        sibs = []; i = idx; level = leaves[:]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            sibs.append(level[i ^ 1]); i //= 2
            level = [H(bytes.fromhex(level[j]) + bytes.fromhex(level[j + 1]))
                     for j in range(0, len(level), 2)]
        return sibs

    def restore(self):
        """Recompute every hash and prev pointer from genesis. Self-healing."""
        prev = GENESIS
        for r in self.records:
            r["prev"] = prev
            cp = dict(r); cp.pop("hash", None)
            r["hash"] = H(canon(cp)); prev = r["hash"]
        self._write_all()

DB = os.environ.get("VP_DB", "ledger.jsonl")
L = Ledger(DB)

class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/health":
            self._json(200, {"ok": True, "n": len(L.records), "root": L.root()})
        elif p == "/chain":
            self._json(200, L.records)
        elif p == "/merkle-root":
            self._json(200, {"root": L.root()})
        elif p.startswith("/verify/"):
            try:
                i = int(p.split("/")[2])
            except Exception:
                self._json(400, {"error": "bad index"}); return
            if not (0 <= i < len(L.records)):
                self._json(400, {"error": "out of range"}); return
            ok, msg = L.verify()
            self._json(200, {"index": i, "valid": ok, "msg": msg,
                             "siblings": len(L.proof(i))})
        elif p == "/seal":
            root = L.root()
            if root is None:
                self._json(400, {"error": "empty chain"}); return
            with open("/tmp/vp_seal.txt", "w") as f:
                f.write(root + "\n" + str(time.time_ns()))
            self._json(200, {"sealed": True, "root": root,
                             "bytes": os.path.getsize("/tmp/vp_seal.txt")})
        else:
            self._json(404, {"error": "nope"})

    def do_POST(self):
        if self.path.split("?")[0] != "/event":
            self._json(404, {"error": "nope"}); return
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        rec = L.append(body.get("agent", "?"), body.get("action", "?"),
                       body.get("target", "?"), body.get("result", "?"))
        self._json(201, {"hash": rec["hash"], "n": len(L.records)})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(os.environ.get("VP_PORT", "8765"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
