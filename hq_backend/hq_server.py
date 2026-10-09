from fastapi import FastAPI, Header, HTTPException
import os
import logging
import asyncio
from pydantic import BaseModel
import uvicorn
import dataclasses
import secrets
import json

from kormic.registry.distributed import CentralRegistryAuthority
from kormic.crypto.software import SoftwareKeyCustody

import hq_backend.hq_db as db

KORMIC_DEPLOYMENT_MODE = os.getenv("KORMIC_DEPLOYMENT_MODE", "production")
VALID_API_KEY = os.getenv("MESHKOR_API_KEY")

if not VALID_API_KEY:
    if KORMIC_DEPLOYMENT_MODE == "development":
        VALID_API_KEY = "default-dev-key"
        logging.warning("MESHKOR_API_KEY is unset. Running in development mode with default key. DO NOT USE IN PRODUCTION.")
    else:
        raise RuntimeError("CRITICAL: MESHKOR_API_KEY is not set. Refusing to start in production mode.")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    await db.init_db()
    if os.getenv("DEV_MODE") == "1":
        twins = await db.get_all_twins()
        if not twins:
            await db.add_twin("KMC.AGNT.demo.001", {}, "encrypted_aes_payload_123")
            await db.add_twin("KMC.AGNT.demo.002", {}, "encrypted_aes_payload_456")
            await db.flag_suspect("KMC.AGNT.suspect.001", "Anomalous Database Query Volume")
    yield
    await db.close_pool()

app = FastAPI(title="MeshKor HQ", lifespan=lifespan)

# Initialize HQ State (Software custody for first customer launch)
keys = SoftwareKeyCustody()
keys.generate_epoch_key(1)
central = CentralRegistryAuthority(keys)

class SpendNonceRequest(BaseModel):
    nonce: str

# In-memory session tracking
admin_challenges = {}
active_admin_sessions = {}

@app.get("/snapshot")
async def get_snapshot():
    snap = central.snapshot()
    return dataclasses.asdict(snap)

@app.get("/admin/challenge")
async def get_admin_challenge():
    challenge = secrets.token_hex(32)
    admin_challenges[challenge] = True
    return {"challenge": challenge}

class AdminAuthRequest(BaseModel):
    challenge: str
    signature_hex: str
    pub_key_pem: str

@app.post("/admin/auth")
async def admin_auth(req: AdminAuthRequest):
    if req.challenge not in admin_challenges:
        return {"error": "Invalid challenge"}
    
    # Real Cryptographic Verification of YubiKey Signature
    def verify_sig():
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        pub_key = load_pem_public_key(req.pub_key_pem.encode('utf-8'))
        pub_key.verify(
            bytes.fromhex(req.signature_hex), 
            req.challenge.encode('utf-8'), 
            ec.ECDSA(hashes.SHA256())
        )
        
    try:
        await asyncio.to_thread(verify_sig)
    except Exception as e:
        return {"error": f"Hardware Signature Cryptographically Invalid: {str(e)}"}
        
    del admin_challenges[req.challenge]
    session_token = secrets.token_hex(16)
    active_admin_sessions[session_token] = True
    return {"session_token": session_token}

@app.get("/admin/twins")
async def list_twins(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    twins = await db.get_all_twins()
    return {"twins": twins}

@app.get("/admin/agents")
async def list_active_agents(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    agents = await db.get_active_agents()
    return {"agents": agents}

@app.get("/admin/suspects")
async def list_suspected_agents(token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    suspects = await db.get_suspects()
    return {"suspects": suspects}

@app.post("/admin/revoke")
async def revoke_agent(req: dict):
    if req.get("token") not in active_admin_sessions: return {"error": "Unauthorized."}
    ain = req.get('ain')
    # 1. Update Database
    await db.revoke_agent_db(ain)
    # 2. Inform Central Registry (so the next Snapshot includes the revocation)
    central.revoke_agent(ain)
    return {"status": f"Agent {ain} successfully revoked and broadcasted to Sidecars."}

@app.post("/admin/unblock")
async def unblock_agent(req: dict):
    if req.get("token") not in active_admin_sessions: return {"error": "Unauthorized."}
    ain = req.get('ain')
    # Update Database
    await db.unblock_agent_db(ain)
    # Remove from central registry revocations if it was there
    if ain in central.revoked_agents:
        central.revoked_agents.remove(ain)
        central.version += 1
    return {"status": f"Agent {ain} successfully unblocked and restored."}

@app.post("/spend_nonce")
async def spend_nonce(req: SpendNonceRequest):
    central.spend_nonce(req.nonce)
    return {"status": "ok"}

@app.get("/admin/twins/{ain}/download")
async def download_twin(ain: str, token: str):
    if token not in active_admin_sessions: return {"error": "Unauthorized."}
    payload = await db.get_encrypted_twin(ain)
    if not payload:
        return {"error": "Twin not found."}
    return {"encrypted_payload": payload}

@app.get("/root_key")
async def get_root_key():
    return {"root_pub": keys.get_root_public_key().hex()}

class EnrollRequest(BaseModel):
    agent_type: str
    entity_ref: str
    instance: str
    real_world_id: str
    manifest: dict
    constitution_hash: str = None
    agent_pub_key: str = ""

@app.post("/enroll")
async def enroll_agent(req: EnrollRequest, authorization: str = Header(None)):
    if authorization != f"Bearer {VALID_API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid Deployment Credential")
    
    # Finding C: Merge constitution_hash into manifest so it is cryptographically sealed
    if req.constitution_hash:
        req.manifest["constitution_hash"] = req.constitution_hash
        
    def generate_birth_record():
        from kormic.manager import AgentManager
        from kormic.storage.sqlite import SQLiteRecordStore
        
        # We use a temporary MemoryRecordStore just to run the generation logic.
        temp_manager = AgentManager(keys, SQLiteRecordStore(":memory:"), default_epoch=1, registry_reader=central)
        ain, _ = temp_manager.register_new_agent(
            req.agent_type, req.entity_ref, req.instance, req.real_world_id, req.manifest, agent_pub_key=req.agent_pub_key
        )
        return ain, temp_manager.record_store.get(ain)

    ain, pedigree_dict = await asyncio.to_thread(generate_birth_record)
    await db.add_twin(ain, req.manifest, json.dumps(pedigree_dict))
    return {"ain": ain, "pedigree": pedigree_dict}

class EventRecord(BaseModel):
    ain: str
    event_description: str
    event_hash: str = None

@app.post('/record_event')
async def record_event_route(req: EventRecord, authorization: str = Header(None)):
    if authorization != f"Bearer {VALID_API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid Deployment Credential")
    
    # Finding A: Store hash, never data
    details = {"event_hash": req.event_hash} if req.event_hash else {}
    await db.log_event(req.ain, req.event_description, details)
    return {'status': 'ok'}

@app.get('/admin/logs')
async def get_admin_logs(token: str):
    if token not in active_admin_sessions: return {'error': 'Unauthorized.'}
    logs = await db.get_events()
    return {'logs': logs}

def start_hq(port: int = 8080):
    uvicorn.run("hq_backend.hq_server:app", host="0.0.0.0", port=port, reload=False)

if __name__ == '__main__':
    start_hq()
