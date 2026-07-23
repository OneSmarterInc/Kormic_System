import sqlite3
import json
from typing import Optional
from kormic.interfaces.storage import RecordStore
from kormic.utils.serialize import canonical_json

# ==============================================================================
# EXTRA NOTIFICATION: THIS MODULE IS AN EXTRA ADDITION FOR TEST UTILITY AND 
# LOCAL PERSISTENCE STORAGE. NOT PART OF THE STRICT PHASE 1 SPECIFICATION SPEC.
# DESIGNED TO DEMONSTRATE DYNAMIC DATABASE INJECTION VIA RecordStore INTERFACE.
# ==============================================================================

class SQLiteRecordStore(RecordStore):
    """
    SQLite persistent implementation of the RecordStore protocol.
    Provides local file-based database storage without modifying existing interfaces.
    """
    def __init__(self, db_path: str = "kormic_agents.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a persistent connection context to SQLite database file."""
        return self._conn

    def _init_db(self) -> None:
        """Initializes tables for storing agent pedigrees and encrypted recovery twins."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Optimization for sub-millisecond writes:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            
            # 1. Table for pedigrees (JSON format serialization text)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pedigrees (
                    agent_code TEXT PRIMARY KEY,
                    pedigree_json TEXT NOT NULL
                )
            """)
            # 2. Table for recovery twin binaries
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS twins (
                    agent_code TEXT PRIMARY KEY,
                    sealed_blob BLOB NOT NULL
                )
            """)
            conn.commit()

    def put(self, agent_code: str, pedigree: dict) -> None:
        """Stores or updates the serialized pedigree dictionary in the SQLite database."""
        pedigree_json = canonical_json(pedigree)
        # Direct execution without `with` context manager block per operation drops overhead
        cursor = self._conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO pedigrees (agent_code, pedigree_json) VALUES (?, ?)",
            (agent_code, pedigree_json)
        )
        self._conn.commit()

    def get(self, agent_code: str) -> Optional[dict]:
        """Retrieves and deserializes the pedigree from SQLite. Returns None if not found."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pedigree_json FROM pedigrees WHERE agent_code = ?", (agent_code,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def put_twin(self, agent_code: str, sealed_blob: bytes) -> None:
        """Stores the encrypted/sealed recovery twin backup blob in SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO twins (agent_code, sealed_blob) VALUES (?, ?)",
                (agent_code, sqlite3.Binary(sealed_blob))
            )
            conn.commit()

    def get_twin(self, agent_code: str) -> Optional[bytes]:
        """Retrieves the encrypted twin recovery blob. Returns None if not found."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sealed_blob FROM twins WHERE agent_code = ?", (agent_code,))
            row = cursor.fetchone()
            if row:
                return bytes(row[0])
            return None
