from fastapi import FastAPI, Header, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
import os
import logging
import asyncio
from pydantic import BaseModel
import uvicorn
import dataclasses
import secrets
import json
import hashlib
import time

from kormic.registry.distributed import CentralRegistryAuthority
from kormic.crypto.software import SoftwareKeyCustody
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.behavior import BehaviorConfig

import hq_backend.hq_db as db

KORMIC_DEPLOYMENT_MODE = os.getenv("KORMIC_DEPLOYMENT_MODE", "production")
VALID_API_KEY = os.getenv("MESHKOR_API_KEY", "Meshkor-2026")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    await db.init_db()
    yield
    await db.close_pool()

app = FastAPI(title="MeshKor Enterprise HQ", lifespan=lifespan)

# Enable CORS for Customer Web Dashboard & Admin Panel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize HQ State (Software custody / Epoch Signing Root)
keys = SoftwareKeyCustody()
keys.generate_epoch_key(1)
central = CentralRegistryAuthority(keys)

# Initialize Real Behavior Monitor for Anomaly Detection
behavior_config = BehaviorConfig(
    accuracy_flag_threshold=0.8,
    accuracy_halt_threshold=0.5,
    overconfidence_flag_threshold=0.2,
    overconfidence_halt_threshold=0.4,
    guardrail_hit_flag_threshold=0.1,
    guardrail_hit_halt_threshold=0.3,
    latency_drift_flag_multiplier=1.5,
    latency_drift_halt_multiplier=3.0
)
behavior_monitor = BehaviorMonitor(config=behavior_config)

# In-memory session tracking
admin_challenges = {}
active_admin_sessions = {}

# --- Authentication Helpers ---

async def authenticate_api_key(authorization: str = Header(None)) -> dict:
    """Authenticates API keys dynamically from the PostgreSQL organizations table."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    raw_key = authorization.split("Bearer ", 1)[1].strip()
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    
    org = await db.get_org_by_api_key_hash(key_hash)
    if not org or org.get("status") != "active":
        # Backward compatibility fallback
        if VALID_API_KEY and raw_key == VALID_API_KEY:
            return {"org_id": "org_kormic", "name": "Kormic Education Technologies", "tier": "advisory"}
        raise HTTPException(status_code=401, detail="Invalid API Key or Inactive Organization")
    return org

def get_session(token: str = None, authorization: str = Header(None)) -> dict:
    """Resolves and validates a session token from query param or header."""
    s_token = token
    if not s_token and authorization and authorization.startswith("Bearer "):
        s_token = authorization.split("Bearer ", 1)[1].strip()
    if not s_token or s_token not in active_admin_sessions:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or expired session.")
    return active_admin_sessions[s_token]

# --- Core Cryptographic & Registry Endpoints ---

@app.get("/snapshot")
async def get_snapshot():
    snap = central.snapshot()
    return dataclasses.asdict(snap)

@app.get("/root_key")
async def get_root_key():
    return {"root_pub": keys.get_root_public_key().hex()}

class SpendNonceRequest(BaseModel):
    nonce: str

@app.post("/spend_nonce")
async def spend_nonce(req: SpendNonceRequest):
    central.spend_nonce(req.nonce)
    return {"status": "ok"}

# --- Public Auth APIs for Customer Organization Portal ---

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

@app.post("/api/v1/auth/signup")
async def signup_org(req: SignupRequest):
    existing = await db.get_org_by_email(req.email)
    if existing:
        raise HTTPException(status_code=400, detail="An organization with this email already exists.")
    
    org_id = f"org_{secrets.token_hex(6)}"
    api_key = f"mk_live_{secrets.token_hex(20)}"
    api_key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    password_hash = hashlib.sha256(req.password.encode('utf-8')).hexdigest()
    
    await db.create_organization(
        org_id=org_id,
        name=req.name,
        admin_email=req.email,
        password_hash=password_hash,
        api_key_hash=api_key_hash,
        tier="advisory"
    )
    return {
        "status": "ok",
        "org_id": org_id,
        "name": req.name,
        "api_key": api_key, # Returned once for developer to copy
        "tier": "advisory"
    }

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/v1/auth/login")
async def login_org(req: LoginRequest):
    org = await db.get_org_by_email(req.email)
    if not org:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    password_hash = hashlib.sha256(req.password.encode('utf-8')).hexdigest()
    if org["password_hash"] != password_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if org["status"] != "active":
        raise HTTPException(status_code=403, detail="Organization account is suspended.")
    
    session_token = secrets.token_hex(24)
    active_admin_sessions[session_token] = {
        "role": "ORG_ADMIN",
        "org_id": org["org_id"],
        "name": org["name"]
    }
    return {
        "session_token": session_token,
        "org_id": org["org_id"],
        "name": org["name"],
        "tier": org["tier"]
    }

# --- Customer Organization Portal Endpoints (/api/v1/org/*) ---

@app.get("/api/v1/org/overview")
async def get_org_overview(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    org_id = session.get("org_id")
    stats = await db.get_org_stats(org_id)
    org_info = await db.get_org_by_id(org_id)
    return {"stats": stats, "organization": org_info}

@app.get("/api/v1/org/twins")
async def get_org_twins(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    twins = await db.get_all_twins(org_id=session.get("org_id"))
    return {"twins": twins}

@app.get("/api/v1/org/suspects")
async def get_org_suspects(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    suspects = await db.get_suspects(org_id=session.get("org_id"))
    return {"suspects": suspects}

@app.get("/api/v1/org/logs")
async def get_org_logs(token: str = None, authorization: str = Header(None), limit: int = 50):
    session = get_session(token, authorization)
    logs = await db.get_events(org_id=session.get("org_id"), limit=limit)
    return {"logs": logs}

@app.get("/api/v1/org/quickstart")
async def get_org_quickstart(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    org_id = session.get("org_id")
    return {
        "org_id": org_id,
        "env_example": f"MESHKOR_ORG_ID={org_id}\nMESHKOR_API_KEY=<your-copied-api-key>\nMESHKOR_HQ_URL=http://44.193.27.158:8080",
        "python_snippet": (
            "from meshkor.integrations.kormic import KormicMeshKorIntegration\n\n"
            "meshkor = KormicMeshKorIntegration()\n"
            "# Automatically loads MESHKOR_ORG_ID and MESHKOR_API_KEY from environment\n"
            "ain = meshkor.enroll_agent(agent_class='STU', instance_ref='student_01', manifest={...})\n"
        )
    }

# --- Runtime Sidecar & Agent Endpoints ---

class EnrollRequest(BaseModel):
    agent_type: str
    entity_ref: str
    instance: str
    real_world_id: str
    manifest: dict
    constitution_hash: str = None
    agent_pub_key: str = ""

@app.post("/enroll")
async def enroll_agent(req: EnrollRequest, org: dict = Depends(authenticate_api_key)):
    if req.constitution_hash:
        req.manifest["constitution_hash"] = req.constitution_hash
        
    def generate_birth_record():
        from kormic.manager import AgentManager
        from kormic.storage.sqlite import SQLiteRecordStore
        temp_manager = AgentManager(keys, SQLiteRecordStore(":memory:"), default_epoch=1, registry_reader=central)
        ain, _ = temp_manager.register_new_agent(
            req.agent_type, req.entity_ref, req.instance, req.real_world_id, req.manifest, agent_pub_key=req.agent_pub_key
        )
        return ain, temp_manager.record_store.get(ain)

    ain, pedigree_dict = await asyncio.to_thread(generate_birth_record)
    await db.add_twin(ain, req.manifest, json.dumps(pedigree_dict), org_id=org["org_id"], epoch_number=1)
    
    # Returns the organization's active mode ('advisory' vs 'enforced')
    return {
        "ain": ain, 
        "pedigree": pedigree_dict,
        "mode": org.get("tier", "advisory"),
        "epoch": 1
    }

class EventRecord(BaseModel):
    ain: str
    event_description: str
    event_hash: str = None
    metrics: dict = None

@app.post('/record_event')
async def record_event_route(req: EventRecord, org: dict = Depends(authenticate_api_key)):
    details = {"event_hash": req.event_hash} if req.event_hash else {}
    if req.metrics:
        details["metrics"] = req.metrics
        
    await db.log_event(req.ain, req.event_description, details, org_id=org["org_id"])
    
    # Real Behavioral Monitoring & Auto-Quarantine Check
    metrics_to_eval = req.metrics or {}
    # Check for keywords indicating drift or policy breaches
    desc_upper = req.event_description.upper()
    if any(k in desc_upper for k in ["BREACH", "DRIFT", "VIOLATION", "HALT", "ANOMALY"]):
        metrics_to_eval["policy_violation"] = True

    if metrics_to_eval:
        report = behavior_monitor.evaluate(req.ain, metrics_to_eval)
        if report.status in ["FLAG", "HALT"]:
            await db.flag_suspect(req.ain, report.reason, org_id=org["org_id"])
            if report.status == "HALT":
                central.revoke_agent(req.ain)

    return {'status': 'ok'}

# --- Super-Admin Endpoints (Hardware Key / YubiKey Locked) ---

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
    session_token = secrets.token_hex(24)
    # Super-Admin session has unrestricted global visibility
    active_admin_sessions[session_token] = {
        "role": "SUPER_ADMIN",
        "name": "OneSmarter Master Administrator"
    }
    return {"session_token": session_token, "role": "SUPER_ADMIN"}

@app.get("/admin/organizations")
async def list_admin_orgs(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    if session.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Forbidden: Super-Admin access required.")
    orgs = await db.list_all_organizations()
    return {"organizations": orgs}

class TierUpdateRequest(BaseModel):
    tier: str

@app.patch("/admin/organizations/{org_id}/tier")
async def update_org_tier_route(org_id: str, req: TierUpdateRequest, token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    if session.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Forbidden: Super-Admin access required.")
    if req.tier not in ["advisory", "enforced"]:
        raise HTTPException(status_code=400, detail="Invalid tier. Must be 'advisory' or 'enforced'.")
    await db.update_org_tier(org_id, req.tier)
    return {"status": "ok", "org_id": org_id, "tier": req.tier}

@app.get("/admin/twins")
async def list_twins(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    twins = await db.get_all_twins(org_id=org_id)
    return {"twins": twins}

@app.get("/admin/agents")
async def list_active_agents(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    agents = await db.get_active_agents(org_id=org_id)
    return {"agents": agents}

@app.get("/admin/suspects")
async def list_suspected_agents(token: str = None, authorization: str = Header(None)):
    session = get_session(token, authorization)
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    suspects = await db.get_suspects(org_id=org_id)
    return {"suspects": suspects}

@app.post("/admin/revoke")
async def revoke_agent(req: dict):
    session = get_session(token=req.get("token"))
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    ain = req.get('ain')
    
    await db.revoke_agent_db(ain, org_id=org_id)
    central.revoke_agent(ain)
    return {"status": f"Agent {ain} successfully revoked and broadcasted globally."}

@app.post("/admin/unblock")
async def unblock_agent(req: dict):
    session = get_session(token=req.get("token"))
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    ain = req.get('ain')
    
    await db.unblock_agent_db(ain, org_id=org_id)
    if ain in central.revoked_agents:
        central.revoked_agents.remove(ain)
        central.version += 1
    return {"status": f"Agent {ain} successfully unblocked and restored."}

@app.post("/admin/twins/{ain}/wake")
async def wake_twin_route(ain: str, req: dict):
    """Real Twin Resurrection into Epoch 2."""
    session = get_session(token=req.get("token"))
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    
    await db.wake_twin_db(ain, org_id=org_id)
    if ain in central.revoked_agents:
        central.revoked_agents.remove(ain)
        central.version += 1
    return {"status": "ok", "message": f"Agent {ain} successfully resurrected into Epoch 2."}

@app.get("/admin/twins/{ain}/download")
async def download_twin(ain: str, token: str):
    session = get_session(token=token)
    payload = await db.get_encrypted_twin(ain)
    if not payload:
        return {"error": "Twin not found."}
    return {"encrypted_payload": payload}

@app.get('/admin/logs')
async def get_admin_logs(token: str, limit: int = 50):
    session = get_session(token=token)
    org_id = None if session.get("role") == "SUPER_ADMIN" else session.get("org_id")
    logs = await db.get_events(org_id=org_id, limit=limit)
    return {'logs': logs}

def start_hq(port: int = 8080):
    uvicorn.run("hq_backend.hq_server:app", host="0.0.0.0", port=port, reload=False)

if __name__ == '__main__':
    start_hq()
