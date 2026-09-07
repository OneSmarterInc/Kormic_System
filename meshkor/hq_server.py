from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from kormic.registry.distributed import CentralRegistryAuthority
from kormic.crypto.software import SoftwareKeyCustody

app = FastAPI(title="MeshKor HQ")

# Initialize HQ State (Software custody for first customer launch)
keys = SoftwareKeyCustody()
keys.generate_epoch_key(1)
central = CentralRegistryAuthority(keys)

class SpendNonceRequest(BaseModel):
    nonce: str

import dataclasses
import secrets
import json

# In-memory session tracking
admin_challenges = {}
active_admin_sessions = {}

@app.get("/snapshot")
def get_snapshot():
    snap = central.snapshot()
    return dataclasses.asdict(snap)

@app.get("/admin/challenge")
def get_admin_challenge():
    challenge = secrets.token_hex(32)
    admin_challenges[challenge] = True
    return {"challenge": challenge}

class AdminAuthRequest(BaseModel):
    challenge: str
    signature_hex: str
    pub_key_pem: str

@app.post("/admin/auth")
def admin_auth(req: AdminAuthRequest):
    if req.challenge not in admin_challenges:
        return {"error": "Invalid challenge"}
    
    # Real Cryptographic Verification of YubiKey Signature
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        
        pub_key = load_pem_public_key(req.pub_key_pem.encode('utf-8'))
        pub_key.verify(
            bytes.fromhex(req.signature_hex), 
            req.challenge.encode('utf-8'), 
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        return {"error": f"Hardware Signature Cryptographically Invalid: {str(e)}"}
        
    del admin_challenges[req.challenge]
    session_token = secrets.token_hex(16)
    active_admin_sessions[session_token] = True
    return {"session_token": session_token}

import meshkor.hq_db as db

@app.on_event("startup")
def startup_event():
    db.init_db()
    # Pre-populate some dummy agents for the UI if the DB is empty (just so they have something to test without enrolling new agents yet)
    if not db.get_all_twins():
        db.add_twin("KMC.AGNT.demo.001", {}, "encrypted_aes_payload_123")
        db.add_twin("KMC.AGNT.demo.002", {}, "encrypted_aes_payload_456")
        db.flag_suspect("KMC.AGNT.suspect.001", "Anomalous Database Query Volume")

@app.get("/admin/twins")
def list_twins(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    return {"twins": db.get_all_twins()}

@app.get("/admin/agents")
def list_active_agents(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    return {"agents": db.get_active_agents()}

@app.get("/admin/suspects")
def list_suspected_agents(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    return {"suspects": db.get_suspects()}

@app.post("/admin/revoke")
def revoke_agent(req: dict):
    if req.get("token") not in active_admin_sessions: return {"error": "Unauthorized."}
    ain = req.get('ain')
    # 1. Update Database
    db.revoke_agent_db(ain)
    # 2. Inform Central Registry (so the next Snapshot includes the revocation)
    central.revoke_agent(ain)
    return {"status": f"Agent {ain} successfully revoked and broadcasted to Sidecars."}

@app.post("/admin/unblock")
def unblock_agent(req: dict):
    if req.get("token") not in active_admin_sessions: return {"error": "Unauthorized."}
    ain = req.get('ain')
    # Update Database
    db.unblock_agent_db(ain)
    # Remove from central registry revocations if it was there
    if ain in central.revoked_agents:
        central.revoked_agents.remove(ain)
        central.version += 1
    return {"status": f"Agent {ain} successfully unblocked and restored."}

@app.post("/spend_nonce")
def spend_nonce(req: SpendNonceRequest):
    central.spend_nonce(req.nonce)
    return {"status": "ok"}

@app.get("/admin/twins/{ain}/download")
def download_twin(ain: str, token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    payload = db.get_encrypted_twin(ain)
    if not payload:
        return {"error": "Twin not found."}
    return {"encrypted_payload": payload}

@app.get("/root_key")
def get_root_key():
    return {"root_pub": keys.get_root_public_key().hex()}

class EnrollRequest(BaseModel):
    agent_type: str
    entity_ref: str
    instance: str
    real_world_id: str
    manifest: dict
    agent_pub_key: str = ""

@app.post("/enroll")
def enroll_agent(req: EnrollRequest):
    # HQ signs the birth record locally, holding the private key safely in the cloud
    from kormic.manager import AgentManager
    from kormic.storage.memory import MemoryRecordStore
    from kormic.models.identity import Pedigree
    
    # We use a temporary MemoryRecordStore just to run the generation logic.
    # We don't persist it in HQ memory because the sidecar owns the operational history.
    temp_manager = AgentManager(keys, MemoryRecordStore(), default_epoch=1, registry_reader=central)
    ain, _ = temp_manager.register_new_agent(
        req.agent_type, req.entity_ref, req.instance, req.real_world_id, req.manifest, agent_pub_key=req.agent_pub_key
    )
    
    # Extract the signed pedigree to send back
    pedigree_dict = temp_manager.record_store.get(ain)
    return {"ain": ain, "pedigree": pedigree_dict}

def start_hq(port: int = 8080):
    uvicorn.run("meshkor.hq_server:app", host="0.0.0.0", port=port, reload=False)

if __name__ == '__main__':
    start_hq()
