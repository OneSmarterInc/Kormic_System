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

    conn.commit()
    conn.close()
    
    # Do not call seed_governance_data() since we have no real helpers.
    seed_governance_data()

def seed_governance_data():
    """
    Item 2: Blocked on Kormic helper list. 
    Removing fake seeds NetworkScanner and LogAnalyzer.
    Empty registry is preferred over decorative fakes.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Delete legacy placeholders if they exist
    c.execute('DELETE FROM registry WHERE agent_class IN ("NetworkScanner", "LogAnalyzer")')
    c.execute('DELETE FROM capability_requests WHERE agent_class IN ("NetworkScanner", "LogAnalyzer")')
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
