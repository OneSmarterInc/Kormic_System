import unittest
import os
import time
import uuid
from kormic.models.verify import ProofToken
from kormic.models.pedigree import Pedigree
from kormic.models.behavior import BehaviorConfig
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.verify.engine import Verifier
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.controller import SessionController
from kormic.behavior.monitor import BehaviorMonitor

class TestDriftWiring(unittest.TestCase):
    def setUp(self):
        self.db_path = f"test_wiring_{uuid.uuid4().hex}.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.key_custody, self.store, default_epoch=1)
        
        self.central = CentralRegistryAuthority(self.key_custody)
        self.registry = RegionalReplicaRegistry("test", self.key_custody._root_pub)
        
        self.verifier = Verifier(self.registry)
        
        config = BehaviorConfig(
            accuracy_flag_threshold=0.8,
            accuracy_halt_threshold=0.5,
            overconfidence_flag_threshold=0.2,
            overconfidence_halt_threshold=0.5,
            guardrail_hit_flag_threshold=0.1,
            guardrail_hit_halt_threshold=0.3,
            latency_drift_flag_multiplier=2.0,
            latency_drift_halt_multiplier=5.0
        )
        self.monitor = BehaviorMonitor(config)
        
        # 1. Agent Keypair
        self.agent_priv, self.agent_pub = MLDSASigner.generate_keypair()
        
        # 2. Manifest
        self.manifest = {
            "allowed_tools": ["db_read"],
            "allowed_endpoints": [],
            "credential_scopes": [],
            "blast_radius": "Test boundaries",
            "irreversible_scopes": []
        }
        
        # 3. Enroll Agent
        self.ain, _ = self.manager.register_new_agent(
            "CMP", "testowner", "0001", "realid", 
            self.manifest, 
            agent_pub_key=self.agent_pub.hex()
        )
        
        # Push snapshot so verifier works
        snap = self.central.snapshot()
        self.registry.apply_snapshot(snap)
        
    def tearDown(self):
        import gc
        import time
        gc.collect()
        time.sleep(0.1)
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass
            
    def _get_valid_token(self):
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        challenge = os.urandom(16).hex()
        payload = (ped.running_head + challenge).encode('utf-8')
        signature = MLDSASigner.sign(self.agent_priv, payload).hex()
        
        return ProofToken(
            agent_code=self.ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=len(ped.history),
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge,
            signature=signature
        )

    def test_wiring_drift_triggers_halt(self):
        token = self._get_valid_token()
        sandbox = Sandbox(self.verifier, token)
        controller = SessionController(sandbox, self.monitor, self.central, self.manager)
        
        # Agent uses legal tool
        controller.execute_tool("db_read")
        
        # Agent is NOT revoked yet
        self.assertNotIn(self.ain, self.central.revoked_agents)
        
        # Agent attempts illegal tool (exceeds blast radius)
        with self.assertRaises(PermissionError):
            controller.execute_tool("db_delete")
            
        # Sandbox blocked it, Controller caught it.
        # Check that it appended to history chain
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        self.assertEqual(len(ped.history), 1)
        self.assertEqual(ped.history[0].event, "MANIFEST_BREACH: TOOL")
        
        # Check that it globally revoked the agent
        self.assertIn(self.ain, self.central.revoked_agents)
        
        # If we take a new snapshot, the Replica gets the revocation
        snap = self.central.snapshot()
        self.registry.apply_snapshot(snap)
        self.assertTrue(self.registry.is_agent_revoked(self.ain))

if __name__ == '__main__':
    unittest.main()
