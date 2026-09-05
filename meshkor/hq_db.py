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
