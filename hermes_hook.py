#!/usr/bin/env python3
"""hermes_hook.py - auto-append every Hermes action to veilpiercer-ledger.

Drop this in ~/.hermes/hooks/ or call it from any agent command.
Usage: hermes_hook.py <agent> <action> <target> [result_json]
Env: LEDGER_URL (default http://localhost:9100)
"""
import json, os, sys, urllib.request

LEDGER_URL = os.environ.get("LEDGER_URL", "http://localhost:9100").rstrip("/")

def append(agent, action, target, result=None):
    event = {"action": action, "target": target}
    if result is not None:
        event["result"] = result
    body = json.dumps({"event": event, "agent": agent}).encode()
    req = urllib.request.Request(
        f"{LEDGER_URL}/event", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        sys.stderr.write(f"veilpiercer-ledger unreachable: {e}\n")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("usage: hermes_hook.py <agent> <action> <target> [result_json]")
        sys.exit(2)
    agent, action, target = sys.argv[1], sys.argv[2], sys.argv[3]
    result = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
    out = append(agent, action, target, result)
    if out:
        print(out.get("hash", "ok")[:16])
