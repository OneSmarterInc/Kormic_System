import sqlite3
import json
import time
import os

DB_PATH = "hq_kormic.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Table for all registered agents (Twins)
    c.execute('''
        CREATE TABLE IF NOT EXISTS twins (
            ain TEXT PRIMARY KEY,
            status TEXT,
            last_active REAL,
            manifest_json TEXT,
            encrypted_payload TEXT
        )
    ''')
    # Table for suspected/flagged agents
    c.execute('''
        CREATE TABLE IF NOT EXISTS suspects (
            ain TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at REAL
        )
    ''')
    
    # Table for telemetry events
    c.execute('''
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ain TEXT,
            event_type TEXT,
            details TEXT,
            timestamp REAL
        )
    ''')

    # Table for Phase 1 Governance: Registry of planned agent classes
    c.execute('''
        CREATE TABLE IF NOT EXISTS registry (
            agent_class TEXT PRIMARY KEY,
            class_ref TEXT,
            what_it_does TEXT,
            assumption TEXT,
            who_may_call TEXT,
            data_touched TEXT,
            owner TEXT,
            shared_or_per_person TEXT,
            status TEXT
        )
    ''')
    
    # Safe migrations for existing rows
    try: c.execute('ALTER TABLE registry ADD COLUMN class_ref TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE registry ADD COLUMN what_it_does TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE registry ADD COLUMN assumption TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE registry ADD COLUMN owner TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE registry ADD COLUMN shared_or_per_person TEXT')
    except sqlite3.OperationalError: pass

    try: c.execute('ALTER TABLE registry ADD COLUMN confirmed_by TEXT')
    except sqlite3.OperationalError: pass
    
    # Table for Phase 1 Governance: Capability Requests log
    c.execute('''
        CREATE TABLE IF NOT EXISTS capability_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_class TEXT,
            requested_by TEXT,
            description TEXT,
            registry_consulted TEXT,
            rationale TEXT,
            outcome_ref TEXT,
            verdict TEXT,
            timestamp REAL
        )
    ''')
    
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN requested_by TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN description TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN registry_consulted TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN rationale TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN outcome_ref TEXT')
    except sqlite3.OperationalError: pass
    try: c.execute('ALTER TABLE capability_requests ADD COLUMN confirmed_by TEXT')
    except sqlite3.OperationalError: pass

    conn.commit()
    conn.close()
    
    # Seed the drafts from the codebase
    seed_governance_data()

def seed_governance_data():
    """
    Item 1: Draft registry rows from existing helper code.
    Prajval to confirm.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Delete legacy placeholders if they exist
    c.execute('DELETE FROM registry WHERE agent_class IN ("NetworkScanner", "LogAnalyzer")')
    c.execute('DELETE FROM capability_requests WHERE agent_class IN ("NetworkScanner", "LogAnalyzer")')
    
    helpers = [
        (
            "github_analyzer", 
            "Analyzes public GitHub repositories to extract technical skills and original work ratios.",
            "Student has linked a GitHub account.",
            "admissions_team, student_advisor",
            "profile.github",
            "kormic_engineering",
            "per-person"
        ),
        (
            "course_mapper",
            "Maps technical interests extracted from GitHub to recommended academic course tracks.",
            "GitHub analysis has been successfully performed.",
            "admissions_team, student_advisor",
            "profile.github.analysis",
            "kormic_advising",
            "per-person"
        ),
        (
            "university_querier",
            "Scrapes and queries university knowledge bases to answer prospective student questions.",
            "University URLs are accessible and target university persona is defined.",
            "prospective_student, student_advisor",
            "university_kb, external_web",
            "kormic_content_team",
            "shared"
        )
    ]
    
    for h in helpers:
        # Check if exists to avoid dupes
        c.execute('SELECT agent_class FROM registry WHERE agent_class=?', (h[0],))
        if not c.fetchone():
            c.execute('''
                INSERT INTO registry 
                (agent_class, class_ref, what_it_does, assumption, who_may_call, data_touched, owner, shared_or_per_person, status, confirmed_by)
                VALUES (?, NULL, ?, ?, ?, ?, ?, ?, "provisional", NULL)
            ''', h)
            
            c.execute('''
                INSERT INTO capability_requests 
                (agent_class, requested_by, description, registry_consulted, rationale, outcome_ref, verdict, timestamp, confirmed_by)
                VALUES (?, "system_bootstrap", "Needs ability to run codebase helper", "none", "no prior helper touched this domain data", NULL, "build_new", ?, NULL)
            ''', (h[0], time.time()))
            
    conn.commit()
    conn.close()

def get_all_twins():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ain, status, last_active FROM twins')
    rows = c.fetchall()
    conn.close()
    
    from datetime import datetime
    twins = []
    for r in rows:
        dt = datetime.fromtimestamp(r[2]).strftime('%Y-%m-%d %H:%M:%S')
        twins.append({"ain": r[0], "status": r[1], "last_active": dt})
    return twins

def get_active_agents():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ain FROM twins WHERE status != "revoked"')
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_suspects():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ain, reason, blocked_at FROM suspects')
    rows = c.fetchall()
    conn.close()
    # Format timestamp nicely for UI
    from datetime import datetime
    return [{"ain": r[0], "reason": r[1], "blocked_at": datetime.fromtimestamp(r[2]).strftime('%Y-%m-%d %H:%M:%S')} for r in rows]

def add_twin(ain, manifest, encrypted_payload=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO twins (ain, status, last_active, manifest_json, encrypted_payload) VALUES (?, ?, ?, ?, ?)',
              (ain, "hibernating", time.time(), json.dumps(manifest), encrypted_payload))
    conn.commit()
    conn.close()

def get_encrypted_twin(ain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT encrypted_payload FROM twins WHERE ain=?', (ain,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def revoke_agent_db(ain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE twins SET status="revoked" WHERE ain=?', (ain,))
    conn.commit()
    conn.close()

def unblock_agent_db(ain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Remove from suspects
    c.execute('DELETE FROM suspects WHERE ain=?', (ain,))
    # Set status back to active/hibernating
    c.execute('UPDATE twins SET status="hibernating" WHERE ain=?', (ain,))
    conn.commit()
    conn.close()

def flag_suspect(ain, reason):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO suspects (ain, reason, blocked_at) VALUES (?, ?, ?)', (ain, reason, time.time()))
    c.execute('UPDATE twins SET status="suspected" WHERE ain=?', (ain,))
    conn.commit()
    conn.close()


def log_event(ain, event_type, details):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO event_logs (ain, event_type, details, timestamp) VALUES (?, ?, ?, ?)', (ain, event_type, json.dumps(details), time.time()))
    conn.commit()
    conn.close()

def get_events(limit=50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ain, event_type, details, timestamp FROM event_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    return [{'ain': r[0], 'event_type': r[1], 'details': json.loads(r[2]) if r[2] else {}, 'timestamp': r[3]} for r in c.fetchall()]

