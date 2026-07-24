import unittest
import os
from kormic.models.identity import Identity
from kormic.models.pedigree import BirthRecord, Pedigree
from kormic.models.verify import ProofToken
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.verify.engine import Verifier
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority

class TestFastChallenge(unittest.TestCase):
    def setUp(self):
        import uuid
        self.db_path = f"test_fast_challenge_{uuid.uuid4().hex}.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.key_custody, self.store, default_epoch=1)
        
        from kormic.registry.distributed import RegionalReplicaRegistry
        # Replica mock for the verifier
        self.registry = RegionalReplicaRegistry("test", self.key_custody._root_pub, local_only=True)
        
        # Central mock to generate a snapshot and push it to the replica
        self.central = CentralRegistryAuthority(self.key_custody)
        snap = self.central.snapshot()
        self.registry.apply_snapshot(snap)
        
        self.verifier = Verifier(self.registry)
        
        # Agent keypair
        self.agent_priv, self.agent_pub = MLDSASigner.generate_keypair()
        
        self.manifest = {
            "allowed_tools": ["tool1"],
            "allowed_endpoints": ["api/v1/test"],
            "credential_scopes": ["scope1"],
            "blast_radius": "test radius",
            "code_pin": "dummyhash",
            "irreversible_scopes": []
        }
        
        # Enroll agent
        self.ain, _ = self.manager.register_new_agent(
            "CMP", "testowner", "0001", "realid", 
            self.manifest, 
            agent_pub_key=self.agent_pub.hex()
        )
        
    def tearDown(self):
        try:
            import gc
            import time
            gc.collect()
            time.sleep(0.1)
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass
            
    def test_fast_verify_works(self):
        # GAP 3: The WORKS test
        import time
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        
        challenge = self.verifier.generate_challenge()
        # Bind head to challenge
        payload = (ped.running_head + challenge).encode('utf-8')
        signature = MLDSASigner.sign(self.agent_priv, payload).hex()
        
        token = ProofToken(
            agent_code=self.ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge,
            signature=signature
        )
        
        res = self.verifier.verify_fast(token)
        self.assertEqual(res.status, "PASS")
        
    def test_fast_verify_tampered_head(self):
        # GAP 1: The FAILS-CORRECTLY test
        import time
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        
        challenge = self.verifier.generate_challenge()
        payload = (ped.running_head + challenge).encode('utf-8')
        signature = MLDSASigner.sign(self.agent_priv, payload).hex()
        
        # Hacker tampers with the head in the token, but keeps the same valid signature
        tampered_head = "0000000000000000000000000000000000000000000000000000000000000000"
        token = ProofToken(
            agent_code=self.ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=tampered_head,
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge,
            signature=signature
        )
        
        res = self.verifier.verify_fast(token)
        # Signature should fail because verification checks (tampered_head + challenge)
        self.assertEqual(res.status, "HALT_HARD")
        self.assertIn("Invalid FAST challenge signature", res.reason)

    def test_fast_verify_missing_signature_fails_closed(self):
        import time
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        
        # Attacker holds only PUBLIC birth record, no private key
        tampered_head = "0000000000000000000000000000000000000000000000000000000000000000"
        attacker_token = ProofToken(
            agent_code=self.ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=tampered_head,
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="x",
            challenge="",
            signature=""
        )
        
        res = self.verifier.verify_fast(attacker_token)
        self.assertEqual(res.status, "HALT_HARD")
        self.assertIn("no challenge/signature", res.reason)

    def test_credential_root_refuses_no_signature(self):
        import time
        from kormic.runtime.credential import CredentialRoot
        ped_dict = self.store.get(self.ain)
        ped = Pedigree.from_dict(ped_dict)
        
        attacker_token = ProofToken(
            agent_code=self.ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="x",
            challenge="",
            signature=""
        )
        
        cr = CredentialRoot(self.verifier)
        res = cr.issue_scoped_credential(attacker_token, "scope1")
        self.assertFalse(res["granted"])
        self.assertIn("no challenge/signature", res["reason"])

if __name__ == '__main__':
    unittest.main()
