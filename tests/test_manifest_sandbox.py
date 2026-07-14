import unittest
import os
import uuid
import time
from kormic.models.verify import ProofToken
from kormic.models.pedigree import Pedigree
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.verify.engine import Verifier
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.credential import CredentialRoot

class TestManifestSandbox(unittest.TestCase):
    def setUp(self):
        self.db_path = f"test_manifest_sandbox_{uuid.uuid4().hex}.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.key_custody, self.store, default_epoch=1)
        
        self.registry = RegionalReplicaRegistry("test", self.key_custody._root_pub)
        self.central = CentralRegistryAuthority(self.key_custody)
        snap = self.central.snapshot()
        self.registry.apply_snapshot(snap)
        
        self.verifier = Verifier(self.registry)
        self.credential_root = CredentialRoot(self.verifier)
        
        # 1. Agent Keypair for FAST Challenge
        self.agent_priv, self.agent_pub = MLDSASigner.generate_keypair()
        
        # 2. Capability Manifest (C3 Code Pinning removed for optional Phase)
        self.manifest = {
            "allowed_tools": ["db_read"],
            "allowed_endpoints": ["api/v1/bank"],
            "credential_scopes": ["read:db", "refund:money"],
            "blast_radius": "Test boundaries",
            "irreversible_scopes": ["refund:money"]
        }
        
        # 3. Enroll Agent
        self.ain, _ = self.manager.register_new_agent(
            "CMP", "testowner", "0001", "realid", 
            self.manifest, 
            agent_pub_key=self.agent_pub.hex()
        )
        
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
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge,
            signature=signature
        )
        
    def test_sandbox_works_genuine_agent(self):
        # WORKS TEST: Genuine agent running correct code
        token = self._get_valid_token()
        box = Sandbox(self.verifier, token)
        
        # In-manifest actions should pass
        res = box.use_tool("db_read")
        self.assertIn("executed", res)
        
        res = box.call_endpoint("api/v1/bank")
        self.assertIn("reached", res)
        
        self.assertFalse(box.drift_detected())
        
    def test_sandbox_fails_out_of_manifest(self):
        # FAILS-CORRECTLY TEST: Agent tries to exceed blast radius C1
        token = self._get_valid_token()
        box = Sandbox(self.verifier, token)
        
        with self.assertRaises(PermissionError) as context:
            box.use_tool("db_delete")
        self.assertIn("BLOCKED", str(context.exception))
        
        self.assertTrue(box.drift_detected())

    def test_credential_root_works(self):
        # WORKS TEST: Request valid credential
        token = self._get_valid_token()
        res = self.credential_root.issue_scoped_credential(token, "read:db")
        self.assertTrue(res["granted"])
        
    def test_credential_root_fails_ambient_authority(self):
        # FAILS-CORRECTLY TEST: Request out-of-scope credential C2
        token = self._get_valid_token()
        res = self.credential_root.issue_scoped_credential(token, "admin:root")
        self.assertFalse(res["granted"])
        self.assertIn("Scope not explicitly declared", res["reason"])

    def test_credential_root_fails_irreversible(self):
        # FAILS-CORRECTLY TEST: Replit countermeasure
        token = self._get_valid_token()
        res = self.credential_root.issue_scoped_credential(token, "read:db", is_irreversible=True)
        self.assertFalse(res["granted"])
        self.assertIn("Action requested is irreversible", res["reason"])
        
if __name__ == '__main__':
    unittest.main()
