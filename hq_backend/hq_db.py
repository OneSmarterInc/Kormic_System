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
            CREATE TABLE IF NOT EXISTS twins (
                ain TEXT PRIMARY KEY,
                status TEXT,
                last_active DOUBLE PRECISION,
                manifest_json TEXT,
                encrypted_payload TEXT
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS suspects (
                ain TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at DOUBLE PRECISION
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS event_logs (
                id SERIAL PRIMARY KEY,
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

async def get_all_twins():
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT ain, status, last_active FROM twins')
    
    from datetime import datetime
    twins = []
    for r in rows:
        dt = datetime.fromtimestamp(r['last_active']).strftime('%Y-%m-%d %H:%M:%S')
        twins.append({"ain": r['ain'], "status": r['status'], "last_active": dt})
    return twins

async def get_active_agents():
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT ain FROM twins WHERE status != $1', 'revoked')
    return [r['ain'] for r in rows]

async def get_suspects():
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT ain, reason, blocked_at FROM suspects')
    from datetime import datetime
    return [{"ain": r['ain'], "reason": r['reason'], "blocked_at": datetime.fromtimestamp(r['blocked_at']).strftime('%Y-%m-%d %H:%M:%S')} for r in rows]

async def add_twin(ain, manifest, encrypted_payload=""):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO twins (ain, status, last_active, manifest_json, encrypted_payload)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (ain) DO UPDATE SET 
            status = EXCLUDED.status, 
            last_active = EXCLUDED.last_active, 
            manifest_json = EXCLUDED.manifest_json, 
            encrypted_payload = EXCLUDED.encrypted_payload
        ''', ain, "hibernating", time.time(), json.dumps(manifest), encrypted_payload)

async def get_encrypted_twin(ain):
    async with pool.acquire() as conn:
        val = await conn.fetchval('SELECT encrypted_payload FROM twins WHERE ain=$1', ain)
    return val

async def revoke_agent_db(ain):
    async with pool.acquire() as conn:
        await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'revoked', ain)

async def unblock_agent_db(ain):
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM suspects WHERE ain=$1', ain)
        await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'hibernating', ain)

async def flag_suspect(ain, reason):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO suspects (ain, reason, blocked_at) VALUES ($1, $2, $3)
            ON CONFLICT (ain) DO UPDATE SET reason = EXCLUDED.reason, blocked_at = EXCLUDED.blocked_at
        ''', ain, reason, time.time())
        await conn.execute('UPDATE twins SET status=$1 WHERE ain=$2', 'suspected', ain)

async def log_event(ain, event_type, details):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO event_logs (ain, event_type, details, timestamp) VALUES ($1, $2, $3, $4)
        ''', ain, event_type, json.dumps(details), time.time())

async def get_events(limit=50):
    async with pool.acquire() as conn:
        rows = await conn.fetch('''
            SELECT ain, event_type, details, timestamp FROM event_logs ORDER BY timestamp DESC LIMIT $1
        ''', limit)
    return [{'ain': r['ain'], 'event_type': r['event_type'], 'details': json.loads(r['details']) if r['details'] else {}, 'timestamp': r['timestamp']} for r in rows]
