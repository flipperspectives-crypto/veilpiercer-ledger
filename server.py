"""FastAPI server for veilpiercer-ledger V5."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ledger import Ledger
import uvicorn

app = FastAPI(title="veilpiercer-ledger", version="5.0")
ledger = Ledger("ledger.json")

class EventIn(BaseModel):
    event: dict
    agent: str = "unknown"

@app.post("/event")
def post_event(body: EventIn):
    try:
        h = ledger.append(body.event, body.agent)
        return {"hash": h}
    except (TypeError, ValueError) as e:
        raise HTTPException(400, str(e))

@app.get("/chain")
def get_chain():
    return ledger.chain

@app.get("/merkle-root")
def get_root():
    if not ledger.chain:
        return {"root": None}
    return {"root": ledger._merkle([r["hash"] for r in ledger.chain])}

@app.get("/verify/{index}")
def verify_index(index: int):
    try:
        proof = ledger.inclusion_proof(index)
        ok, _ = ledger.verify_inclusion(index, proof)
        return {"index": index, "valid": ok, "proof_len": len(proof)}
    except IndexError:
        raise HTTPException(404, "index oob")

@app.post("/seal")
def do_seal():
    try:
        return ledger.seal()
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/stats")
def get_stats():
    return ledger.stats()

@app.get("/health")
def health():
    return {"status": "ok", "events": len(ledger.chain)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9100)
