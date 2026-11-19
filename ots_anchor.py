#!/usr/bin/env python3
"""ots_anchor.py - real OpenTimestamps Bitcoin anchoring for veilpiercer-ledger.

Tries the ots CLI. Falls back to saving the root locally with a clear
'pending' status so nothing is lost. Run: ots_anchor.py <merkle_root_hex>
Or import: from ots_anchor import anchor; anchor(root)
"""
import json, os, shutil, subprocess, sys, time

def anchor(root_hex, workdir=".ots-anchors"):
    os.makedirs(workdir, exist_ok=True)
    path = os.path.join(workdir, f"{root_hex}-{int(time.time())}.txt")
    with open(path, "w") as f:
        f.write(root_hex + "\n")
    ots = shutil.which("ots")
    if not ots:
        return {"root": root_hex, "anchored": False, "method": "local-pending",
                "path": path, "note": "opentimestamps-client not installed"}
    try:
        r = subprocess.run([ots, "stamp", path], capture_output=True,
                           text=True, timeout=120)
        pf = path + ".ots"
        if os.path.exists(pf) and r.returncode == 0:
            info = subprocess.run([ots, "info", pf], capture_output=True,
                                  text=True, timeout=30).stdout.strip()
            return {"root": root_hex, "anchored": True,
                    "method": "opentimestamps-client", "proof_file": pf,
                    "info": info, "path": path}
        return {"root": root_hex, "anchored": False, "method": "local-pending",
                "path": path, "ots_stderr": r.stderr.strip()[:300]}
    except Exception as e:
        return {"root": root_hex, "anchored": False, "method": "local-pending",
                "path": path, "ots_error": repr(e)}

if __name__ == "__main__":
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64:
        print("usage: ots_anchor.py <64-char-merkle-root-hex>")
        sys.exit(2)
    print(json.dumps(anchor(sys.argv[1]), indent=1))
