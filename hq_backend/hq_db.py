import json
import time
import os
import asyncpg

KORMIC_DEPLOYMENT_MODE = os.getenv("KORMIC_DEPLOYMENT_MODE", "production")
DB_URL = os.getenv("MESHKOR_DATABASE_URL")
if not DB_URL:
    if KORMIC_DEPLOYMENT_MODE == "development":
        DB_URL = "postgresql://meshkor:meshkor@localhost:5439/meshkor_hq"
        import logging
        logging.warning("MESHKOR_DATABASE_URL unset. Using local dev HQ database. DO NOT USE IN PRODUCTION.")
    else:
        raise RuntimeError("CRITICAL: MESHKOR_DATABASE_URL is not set. Refusing to start in production mode.")

pool = None

async def init_pool():
    global pool
    pool = await asyncpg.create_pool(DB_URL, statement_cache_size=0)

async def close_pool():
    global pool
    if pool:
        await pool.close()

async def init_db():
    async with pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                org_id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                admin_email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                api_key_hash VARCHAR(64) NOT NULL UNIQUE,
                tier VARCHAR(32) NOT NULL DEFAULT 'advisory',
                status VARCHAR(32) NOT NULL DEFAULT 'active',
                created_at DOUBLE PRECISION NOT NULL,
                updated_at DOUBLE PRECISION NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS twins (
                ain TEXT PRIMARY KEY,
                org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
                status TEXT,
                last_active DOUBLE PRECISION,
                manifest_json TEXT,
                encrypted_payload TEXT,
                epoch_number INT DEFAULT 1
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS suspects (
                ain TEXT PRIMARY KEY,
                org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
                reason TEXT,
                blocked_at DOUBLE PRECISION
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS event_logs (
                id SERIAL PRIMARY KEY,
                org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
                ain TEXT,
                event_type TEXT,
                details TEXT,
                timestamp DOUBLE PRECISION
            )
        ''')
        
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS registry (
                agent_class TEXT PRIMARY KEY,
                class_ref TEXT,
                what_it_does TEXT,
                assumption TEXT,
                who_may_call TEXT,
                data_touched TEXT,
                owner TEXT,
                shared_or_per_person TEXT,
                status TEXT,
                confirmed_by TEXT
            )
        ''')
        
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS capability_requests (
                id SERIAL PRIMARY KEY,
                agent_class TEXT,
                requested_by TEXT,
                description TEXT,
                registry_consulted TEXT,
                rationale TEXT,
                outcome_ref TEXT,
                verdict TEXT,
                timestamp DOUBLE PRECISION,
                confirmed_by TEXT
            )
        ''')
        
        # Idempotent alters in case tables exist
        await conn.execute('ALTER TABLE twins ALTER COLUMN last_active TYPE double precision')
        await conn.execute('ALTER TABLE suspects ALTER COLUMN blocked_at TYPE double precision')
        await conn.execute('ALTER TABLE event_logs ALTER COLUMN timestamp TYPE double precision')
        await conn.execute('ALTER TABLE capability_requests ALTER COLUMN timestamp TYPE double precision')
        
    await seed_governance_data()

async def seed_governance_data():
    helpers = [
        ("github_analyzer", "Analyzes public GitHub repositories to extract technical skills and original work ratios.", "Student has linked a GitHub account.", "admissions_team, student_advisor", "profile.github", "kormic_engineering", "per-person"),
        ("course_mapper", "Maps technical interests extracted from GitHub to recommended academic course tracks.", "GitHub analysis has been successfully performed.", "admissions_team, student_advisor", "profile.github.analysis", "kormic_advising", "per-person"),
        ("university_querier", "Scrapes and queries university knowledge bases to answer prospective student questions.", "University URLs are accessible and target university persona is defined.", "prospective_student, student_advisor", "university_kb, external_web", "kormic_content_team", "shared")
    ]
    
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM registry WHERE agent_class IN ('NetworkScanner', 'LogAnalyzer')")
        await conn.execute("DELETE FROM capability_requests WHERE agent_class IN ('NetworkScanner', 'LogAnalyzer')")
        
        for h in helpers:
            val = await conn.fetchval("SELECT agent_class FROM registry WHERE agent_class=$1", h[0])
            if not val:
                await conn.execute('''
                    INSERT INTO registry 
                    (agent_class, class_ref, what_it_does, assumption, who_may_call, data_touched, owner, shared_or_per_person, status, confirmed_by)
                    VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, 'provisional', NULL)
                ''', *h)
                await conn.execute('''
                    INSERT INTO capability_requests 
                    (agent_class, requested_by, description, registry_consulted, rationale, outcome_ref, verdict, timestamp, confirmed_by)
                    VALUES ($1, 'system_bootstrap', 'Needs ability to run codebase helper', 'none', 'no prior helper touched this domain data', NULL, 'build_new', $2, NULL)
                ''', h[0], time.time())

# --- Multi-Tenant Organization Management ---

async def get_org_by_api_key_hash(api_key_hash: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT org_id, name, admin_email, tier, status, created_at
            FROM organizations WHERE api_key_hash = $1
        ''', api_key_hash)
    return dict(row) if row else None

async def get_org_by_email(admin_email: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT org_id, name, admin_email, password_hash, tier, status, created_at
            FROM organizations WHERE admin_email = $1
        ''', admin_email)
    return dict(row) if row else None

async def get_org_by_id(org_id: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT org_id, name, admin_email, tier, status, created_at
            FROM organizations WHERE org_id = $1
        ''', org_id)
    return dict(row) if row else None

async def create_organization(org_id: str, name: str, admin_email: str, password_hash: str, api_key_hash: str, tier: str = "advisory"):
    now = time.time()
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO organizations (org_id, name, admin_email, password_hash, api_key_hash, tier, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
        ''', org_id, name, admin_email, password_hash, api_key_hash, tier, now, now)
    return {"org_id": org_id, "name": name, "admin_email": admin_email, "tier": tier, "status": "active"}

async def list_all_organizations():
    async with pool.acquire() as conn:
        rows = await conn.fetch('''
            SELECT o.org_id, o.name, o.admin_email, o.tier, o.status, o.created_at,
                   COUNT(DISTINCT t.ain) as total_twins,
                   COUNT(DISTINCT s.ain) as total_suspects
            FROM organizations o
            LEFT JOIN twins t ON t.org_id = o.org_id
            LEFT JOIN suspects s ON s.org_id = o.org_id
            GROUP BY o.org_id, o.name, o.admin_email, o.tier, o.status, o.created_at
            ORDER BY o.created_at DESC
        ''')
    return [dict(r) for r in rows]

async def update_org_tier(org_id: str, tier: str):
    async with pool.acquire() as conn:
        await conn.execute('UPDATE organizations SET tier=$1, updated_at=$2 WHERE org_id=$3', tier, time.time(), org_id)

async def get_org_stats(org_id: str):
    async with pool.acquire() as conn:
        twins_count = await conn.fetchval('SELECT COUNT(*) FROM twins WHERE org_id=$1', org_id)
        active_count = await conn.fetchval("SELECT COUNT(*) FROM twins WHERE org_id=$1 AND status='active'", org_id)
        suspects_count = await conn.fetchval('SELECT COUNT(*) FROM suspects WHERE org_id=$1', org_id)
        events_count = await conn.fetchval('SELECT COUNT(*) FROM event_logs WHERE org_id=$1', org_id)
    return {
        "total_twins": twins_count,
        "active_agents": active_count,
        "suspected_agents": suspects_count,
        "total_events": events_count
    }

# --- Multi-Tenant Agent Operations ---

async def get_all_twins(org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            rows = await conn.fetch('SELECT ain, org_id, status, last_active, epoch_number FROM twins WHERE org_id=$1 ORDER BY last_active DESC', org_id)
        else:
            rows = await conn.fetch('SELECT ain, org_id, status, last_active, epoch_number FROM twins ORDER BY last_active DESC')
    
    from datetime import datetime
    twins = []
    for r in rows:
        dt = datetime.fromtimestamp(r['last_active']).strftime('%Y-%m-%d %H:%M:%S')
        twins.append({
            "ain": r['ain'],
            "org_id": r.get('org_id', 'unknown'),
            "status": r['status'],
            "last_active": dt,
            "epoch_number": r.get('epoch_number', 1)
        })
    return twins

async def get_active_agents(org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            rows = await conn.fetch("SELECT ain FROM twins WHERE org_id=$1 AND status != 'revoked'", org_id)
        else:
            rows = await conn.fetch("SELECT ain FROM twins WHERE status != 'revoked'")
    return [r['ain'] for r in rows]

async def get_suspects(org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            rows = await conn.fetch('SELECT ain, org_id, reason, blocked_at FROM suspects WHERE org_id=$1 ORDER BY blocked_at DESC', org_id)
        else:
            rows = await conn.fetch('SELECT ain, org_id, reason, blocked_at FROM suspects ORDER BY blocked_at DESC')
    from datetime import datetime
    return [{
        "ain": r['ain'],
        "org_id": r.get('org_id', 'unknown'),
        "reason": r['reason'],
        "blocked_at": datetime.fromtimestamp(r['blocked_at']).strftime('%Y-%m-%d %H:%M:%S')
    } for r in rows]

async def add_twin(ain: str, manifest: dict, encrypted_payload: str = "", org_id: str = "org_kormic", epoch_number: int = 1):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO twins (ain, org_id, status, last_active, manifest_json, encrypted_payload, epoch_number)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (ain) DO UPDATE SET 
            org_id = EXCLUDED.org_id,
            status = EXCLUDED.status, 
            last_active = EXCLUDED.last_active, 
            manifest_json = EXCLUDED.manifest_json, 
            encrypted_payload = EXCLUDED.encrypted_payload,
            epoch_number = EXCLUDED.epoch_number
        ''', ain, org_id, "hibernating", time.time(), json.dumps(manifest), encrypted_payload, epoch_number)

async def get_encrypted_twin(ain: str):
    async with pool.acquire() as conn:
        val = await conn.fetchval('SELECT encrypted_payload FROM twins WHERE ain=$1', ain)
    return val

async def revoke_agent_db(ain: str, org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2 AND org_id=$3', 'revoked', ain, org_id)
        else:
            await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'revoked', ain)

async def unblock_agent_db(ain: str, org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            await conn.execute('DELETE FROM suspects WHERE ain=$1 AND org_id=$2', ain, org_id)
            await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2 AND org_id=$3', 'hibernating', ain, org_id)
        else:
            await conn.execute('DELETE FROM suspects WHERE ain=$1', ain)
            await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'hibernating', ain)

async def wake_twin_db(ain: str, org_id: str = None):
    async with pool.acquire() as conn:
        if org_id:
            await conn.execute('DELETE FROM suspects WHERE ain=$1 AND org_id=$2', ain, org_id)
            await conn.execute('''
                UPDATE twins 
                SET status='active', epoch_number=epoch_number+1, last_active=$1 
                WHERE ain=$2 AND org_id=$3
            ''', time.time(), ain, org_id)
        else:
            await conn.execute('DELETE FROM suspects WHERE ain=$1', ain)
            await conn.execute('''
                UPDATE twins 
                SET status='active', epoch_number=epoch_number+1, last_active=$1 
                WHERE ain=$2
            ''', time.time(), ain)

async def flag_suspect(ain: str, reason: str, org_id: str = "org_kormic"):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO suspects (ain, org_id, reason, blocked_at) VALUES ($1, $2, $3, $4)
            ON CONFLICT (ain) DO UPDATE SET org_id = EXCLUDED.org_id, reason = EXCLUDED.reason, blocked_at = EXCLUDED.blocked_at
        ''', ain, org_id, reason, time.time())
        await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'suspected', ain)

async def log_event(ain: str, event_type: str, details: dict, org_id: str = "org_kormic"):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO event_logs (ain, org_id, event_type, details, timestamp) VALUES ($1, $2, $3, $4, $5)
        ''', ain, org_id, event_type, json.dumps(details), time.time())

async def get_events(org_id: str = None, limit: int = 50):
    async with pool.acquire() as conn:
        if org_id:
            rows = await conn.fetch('''
                SELECT ain, org_id, event_type, details, timestamp 
                FROM event_logs 
                WHERE org_id=$1 
                ORDER BY timestamp DESC LIMIT $2
            ''', org_id, limit)
        else:
            rows = await conn.fetch('''
                SELECT ain, org_id, event_type, details, timestamp 
                FROM event_logs 
                ORDER BY timestamp DESC LIMIT $1
            ''', limit)
    return [{
        'ain': r['ain'],
        'org_id': r.get('org_id', 'unknown'),
        'event_type': r['event_type'],
        'details': json.loads(r['details']) if r['details'] else {},
        'timestamp': r['timestamp']
    } for r in rows]

