import time
import unittest
import os
import uuid
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.ceremony import ThresholdCeremony
from kormic.interfaces.keys import Share
from kormic.runtime.controller import SessionController
from kormic.runtime.sandbox import Sandbox
from kormic.verify.engine import Verifier
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.behavior import BehaviorConfig
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.manager import AgentManager
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken
from kormic.crypto.algorithms import MLDSASigner

class DummyShare(Share):
    def __init__(self, idx: int, value: bytes):
        self.idx = idx
        self.value = value
        
    @property
    def share_index(self): return self.idx
    @property
    def share_data(self): return self.value

class TestPhase3Ceremony(unittest.TestCase):
    def setUp(self):
        self.ceremony = ThresholdCeremony(n=5, standard_quorum=3)
        # Use real Shamir shares instead of dummies
        self.custody = SoftwareKeyCustody()
        self.real_key = os.urandom(32)
        self.shares = self.custody.wrap_twin_key(self.real_key)
        
    def _mock_create(self):
        return "Agent Created"
        
    def _mock_destroy(self):
        return "Agent Destroyed"

    def test_ceremony_standard_quorum_success(self):
        # 3 out of 5 shares provided
        quorum_shares = self.shares[:3]
        result = self.ceremony.authorize_create(quorum_shares, self._mock_create)
        self.assertEqual(result, "Agent Created")
        
        result = self.ceremony.authorize_destroy(quorum_shares, self._mock_destroy)
        self.assertEqual(result, "Agent Destroyed")
        
    def test_ceremony_standard_quorum_fail(self):
        # 2 out of 5 shares provided
        quorum_shares = self.shares[:2]
        with self.assertRaises(PermissionError):
            self.ceremony.authorize_create(quorum_shares, self._mock_create)
            
    def test_ceremony_catastrophic_destroy_success(self):
        # 5 out of 5 shares provided
        result = self.ceremony.authorize_catastrophic_destroy(self.shares, self._mock_destroy)
        self.assertEqual(result, "Agent Destroyed")
        
    def test_ceremony_catastrophic_destroy_fail(self):
        # 4 out of 5 shares provided
        quorum_shares = self.shares[:4]
        with self.assertRaises(PermissionError):
            self.ceremony.authorize_catastrophic_destroy(quorum_shares, self._mock_destroy)

    def test_ceremony_dummy_shares_fail(self):
        # 3 out of 5 dummy shares provided (invalid Shamir format, index 0 is mathematically invalid in GF256)
        dummy_shares = [DummyShare(0, os.urandom(32)) for _ in range(3)]
        with self.assertRaises(PermissionError):
            self.ceremony.authorize_create(dummy_shares, self._mock_create)

class TestSelfDefense(unittest.TestCase):
    def setUp(self):
        self.db_path = f"test_defense_{uuid.uuid4().hex}.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        self.keys = SoftwareKeyCustody()
        self.keys.generate_epoch_key(1)
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.keys, self.store, default_epoch=1)
        
        self.central = CentralRegistryAuthority(self.keys)
        self.replica = RegionalReplicaRegistry("test", self.keys._root_pub)
        self.verifier = Verifier(self.replica)
        self.monitor = BehaviorMonitor(BehaviorConfig(0.8,0.5,0.2,0.5,0.1,0.3,2.0,5.0))
        
        self.agent_priv, self.agent_pub = MLDSASigner.generate_keypair()
        manifest = {"allowed_tools": [], "allowed_endpoints": [], "credential_scopes": [], "blast_radius": "test", "irreversible_scopes": []}
        self.ain, _ = self.manager.register_new_agent("CMP", "defense", "0001", "id", manifest, agent_pub_key=self.agent_pub.hex())
        
        self.replica.apply_snapshot(self.central.snapshot())
        
    def tearDown(self):
        self.store.close() if hasattr(self.store, 'close') else None
        try:
            os.remove(self.db_path)
        except OSError:
            pass
            
    def _get_token(self):
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        challenge = os.urandom(16).hex()
        payload = (ped.running_head + challenge).encode('utf-8')
        sig = MLDSASigner.sign(self.agent_priv, payload).hex()
        return ProofToken(self.ain, ped.birth_record.to_dict(), ped.running_head, len(ped.history), time.time(), "test", challenge, sig)

    def test_self_isolate(self):
        token = self._get_token()
        sandbox = Sandbox(self.verifier, token)
        controller = SessionController(sandbox, self.monitor, self.central, self.manager)
        
        # Agent calls self_isolate
        controller.self_isolate("Detected prompt injection attempt")
        
        # Verify history chain has the isolation event
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        self.assertEqual(len(ped.history), 1)
        self.assertIn("SELF_ISOLATION", ped.history[0].event)
        
        # Verify agent is revoked centrally
        self.assertIn(self.ain, self.central.revoked_agents)

if __name__ == '__main__':
    unittest.main()
