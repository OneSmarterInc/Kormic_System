import unittest
import os
import uuid
import time
import gc
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.credential import CredentialRoot
from kormic.runtime.controller import SessionController
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.behavior import BehaviorConfig
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken

class TestMeshKorEndToEnd(unittest.TestCase):
    def setUp(self):
        self.db_path = f"test_e2e_{uuid.uuid4().hex}.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        # Infrastructure
        self.keys = SoftwareKeyCustody()
        self.keys.generate_epoch_key(1)
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.keys, self.store, default_epoch=1)
        self.central = CentralRegistryAuthority(self.keys)
        self.replica = RegionalReplicaRegistry("us-east", self.keys._root_pub, central_sync=self.central)
        self.verifier = Verifier(self.replica)
        self.credential_root = CredentialRoot(self.verifier)
        self.monitor = BehaviorMonitor(BehaviorConfig(
            accuracy_flag_threshold=0.8, accuracy_halt_threshold=0.5,
            overconfidence_flag_threshold=0.2, overconfidence_halt_threshold=0.5,
            guardrail_hit_flag_threshold=0.1, guardrail_hit_halt_threshold=0.3,
            latency_drift_flag_multiplier=2.0, latency_drift_halt_multiplier=5.0
        ))

        # Agent Keypair
        self.agent_priv, self.agent_pub = MLDSASigner.generate_keypair()

    def tearDown(self):
        self.store.close() if hasattr(self.store, 'close') else None
        gc.collect()
        time.sleep(0.1)
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass

    def _get_token(self, ain):
        ped_dict = self.store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        challenge = os.urandom(16).hex()
        payload = (ped.running_head + challenge).encode('utf-8')
        sig = MLDSASigner.sign(self.agent_priv, payload).hex()
        return ProofToken(
            agent_code=ain, birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head, history_length=len(ped.history),
            freshness_timestamp=time.time(), authority_reference="e2e",
            challenge=challenge, signature=sig
        )

    def test_full_lifecycle_success(self):
        # 1. Birth
        manifest = {
            "allowed_tools": ["t1", "t2"],
            "allowed_endpoints": ["e1"],
            "credential_scopes": ["c1"],
            "blast_radius": "test",
            "irreversible_scopes": []
        }
        ain, _ = self.manager.register_new_agent("CMP", "e2e_agent", "0001", "id", manifest, agent_pub_key=self.agent_pub.hex())
        
        # 2. Sync to replica
        self.replica.apply_snapshot(self.central.snapshot())

        # 3. Session Start
        token = self._get_token(ain)
        sandbox = Sandbox(self.verifier, token)
        controller = SessionController(sandbox, self.monitor, self.central, self.manager)

        # 4. Valid Actions
        self.assertIn("executed", controller.execute_tool("t1"))
        self.assertIn("reached", controller.call_endpoint("e1"))
        
        # 5. Valid Credential Request
        token2 = self._get_token(ain)
        cred = self.credential_root.issue_scoped_credential(token2, "c1")
        self.assertTrue(cred["granted"])

        # 6. Verify History is clean
        ped_dict = self.store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        self.assertEqual(len(ped.history), 0)

    def test_full_lifecycle_manifest_breach(self):
        manifest = {
            "allowed_tools": ["t1"],
            "allowed_endpoints": ["e1"],
            "credential_scopes": ["c1"],
            "blast_radius": "test",
            "irreversible_scopes": []
        }
        ain, _ = self.manager.register_new_agent("CMP", "e2e_agent2", "0001", "id", manifest, agent_pub_key=self.agent_pub.hex())
        self.replica.apply_snapshot(self.central.snapshot())

        token = self._get_token(ain)
        sandbox = Sandbox(self.verifier, token)
        controller = SessionController(sandbox, self.monitor, self.central, self.manager)

        # Agent tries forbidden tool
        with self.assertRaises(PermissionError):
            controller.execute_tool("t2")

        # History should now contain the breach
        ped_dict = self.store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        self.assertEqual(len(ped.history), 1)
        self.assertIn("MANIFEST_BREACH", ped.history[0].event)

        # Central Registry should have the agent revoked instantly
        self.assertIn(ain, self.central.revoked_agents)

        # Replica updates via snapshot
        self.replica.apply_snapshot(self.central.snapshot())
        self.assertTrue(self.replica.is_agent_revoked(ain))

        # Further authentication attempts fail
        token_after = self._get_token(ain)
        res = self.verifier.verify_fast(token_after)
        self.assertEqual(res.status, "REVOKED")
        self.assertIn("revoked", res.reason)

if __name__ == '__main__':
    unittest.main()
