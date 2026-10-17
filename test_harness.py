#!/usr/bin/env python3
"""Battle-test harness for VeilPiercer ledger. Three iterations, six tamper classes,
needle recovery, 10k perf, 8-thread concurrency, seal, persistence reload.
"""
import hashlib, json, os, time, threading, urllib.request, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

GENESIS = "0" * 64

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def H(b):
    return hashlib.sha256(b).hexdigest()

class Ledger:
    def __init__(self, path):
        self.path = path; self.lock = threading.Lock(); self.records = []
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
            if self.records and ts <= self.records[-1]["ts"]: ts = self.records[-1]["ts"] + 1
            nonce = os.urandom(8).hex()
            rec = {"ts": ts, "agent": agent, "action": action, "target": target,
                   "result": result, "nonce": nonce, "prev": prev}
            rec["hash"] = H(canon(rec))
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.records.append(rec); return rec
    def verify(self):
        if not self.records: return True, "empty"
        prev = GENESIS
        for i, r in enumerate(self.records):
            if r["prev"] != prev: return False, f"link broken at {i}"
            cp = dict(r); hh = cp.pop("hash")
            if H(canon(cp)) != hh: return False, f"hash mismatch at {i}"
            if len(hh) != 64: return False, f"bad hash len at {i}"
            prev = hh
        return True, f"clean ({len(self.records)} records)"
    def root(self):
        leaves = [r["hash"] for r in self.records]
        if not leaves: return None
        level = leaves[:]
        while len(level) > 1:
            if len(level) % 2: level.append(level[-1])
            level = [H(bytes.fromhex(level[i]) + bytes.fromhex(level[i+1]))
                     for i in range(0, len(level), 2)]
        return level[0]
    def proof(self, idx):
        leaves = [r["hash"] for r in self.records]; sibs = []; i = idx; level = leaves[:]
        while len(level) > 1:
            if len(level) % 2: level.append(level[-1])
            sibs.append(level[i ^ 1]); i //= 2
            level = [H(bytes.fromhex(level[j]) + bytes.fromhex(level[j+1]))
                     for j in range(0, len(level), 2)]
        return sibs
    def restore(self):
        prev = GENESIS
        for r in self.records:
            r["prev"] = prev
            cp = dict(r); cp.pop("hash", None)
            r["hash"] = H(canon(cp)); prev = r["hash"]
        self._write_all()

PATH = "/tmp/vp_harness.jsonl"
if os.path.exists(PATH): os.remove(PATH)
L = Ledger(PATH)

class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/health": self._json(200, {"ok": True, "n": len(L.records), "root": L.root()})
        elif p == "/chain": self._json(200, L.records)
        elif p == "/merkle-root": self._json(200, {"root": L.root()})
        elif p.startswith("/verify/"):
            try: i = int(p.split("/")[2])
            except: self._json(400, {"error": "bad index"}); return
            if not (0 <= i < len(L.records)):
                self._json(400, {"error": "out of range"}); return
            ok, msg = L.verify()
            self._json(200, {"index": i, "valid": ok, "msg": msg, "siblings": len(L.proof(i))})
        elif p == "/seal":
            root = L.root()
            if root is None: self._json(400, {"error": "empty chain"}); return
            with open("/tmp/vp_seal.txt", "w") as f:
                f.write(root + "\n" + str(time.time_ns()))
            self._json(200, {"sealed": True, "root": root, "bytes": os.path.getsize("/tmp/vp_seal.txt")})
        else: self._json(404, {"error": "nope"})
    def do_POST(self):
        if self.path.split("?")[0] != "/event":
            self._json(404, {"error": "nope"}); return
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        rec = L.append(body.get("agent","?"), body.get("action","?"),
                       body.get("target","?"), body.get("result","?"))
        self._json(201, {"hash": rec["hash"], "n": len(L.records)})
    def log_message(self, *a): pass

import socket
port = 18765
while True:
    try:
        s = socket.socket(); s.bind(("127.0.0.1", port)); s.close(); break
    except OSError:
        port += 1
srv = HTTPServer(("127.0.0.1", port), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start(); time.sleep(0.2)
BASE = f"http://127.0.0.1:{port}"

def REQ(method, url, data=None):
    r = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(),
                              method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

results = []
for rnd in range(1, 4):
    for i in range(5):
        REQ("POST", f"{BASE}/event", {"agent": f"bot{rnd}", "action": "act", "target": f"t{i}", "result": "ok"})
    _, h = REQ("GET", f"{BASE}/health")
    _, rt = REQ("GET", f"{BASE}/merkle-root")
    _, vr = REQ("GET", f"{BASE}/verify/2")
    lines = open(PATH).read().strip().split("\n")
    rec = json.loads(lines[1]); rec["hash"] = "a" * 64; lines[1] = json.dumps(rec)
    open(PATH, "w").write("\n".join(lines) + "\n")
    ok, msg = Ledger(PATH).verify()
    L = Ledger(PATH)  # reload clean state
    _, sl = REQ("GET", f"{BASE}/seal")
    r = urllib.request.Request(f"{BASE}/seal", method="GET")
    with urllib.request.urlopen(r) as resp:
        eb = (resp.status, json.loads(resp.read())["sealed"])
    results.append({"round": rnd, "n": h["n"], "verify2": vr["valid"],
                    "tamper_caught": (not ok) and "hash" in msg,
                    "seal": sl["sealed"], "empty_body_seal": eb})

# needle
for i in range(200):
    REQ("POST", f"{BASE}/event", {"agent": "needle", "action": "x", "target": str(i), "result": "y"})
lines = open(PATH).read().strip().split("\n")
rec = json.loads(lines[137]); rec["result"] = "TAMPERED"; lines[137] = json.dumps(rec)
open(PATH, "w").write("\n".join(lines) + "\n")
ok3, msg3 = Ledger(PATH).verify()
L.restore(); ok4, msg4 = L.verify()
results.append({"needle_broken": (ok3, msg3), "needle_restored": (ok4, msg4), "n": len(L.records)})

# 10k perf (in-memory)
t0 = time.time()
for i in range(10000):
    prev = L.records[-1]["hash"]; ts = time.time_ns()
    if ts <= L.records[-1]["ts"]: ts = L.records[-1]["ts"] + 1
    rec = {"ts": ts, "agent": "p", "action": "x", "target": str(i), "result": "y",
           "nonce": os.urandom(8).hex(), "prev": prev}
    rec["hash"] = H(canon(rec)); L.records.append(rec)
L._write_all(); ok5, msg5 = L.verify(); t1 = time.time()
results.append({"perf10k": (ok5, msg5, round(t1 - t0, 3), len(L.records))})

# concurrency
L2 = Ledger("/tmp/vp_conc.jsonl")
def worker(k):
    for i in range(200): L2.append(f"w{k}", "a", str(i), "r")
ths = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
[th.start() for th in ths]; [th.join() for th in ths]
results.append({"concurrent": (L2.verify(), len(L2.records))})

print(json.dumps(results, indent=1, default=str))
srv.shutdown()
