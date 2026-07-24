import unittest
import time
from kormic.crypto.software import SoftwareKeyCustody
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.models.verify import ProofToken

class TestDistributedRegistry(unittest.TestCase):
    def setUp(self):
        # 1. Setup the underlying Key Custody and Central Authority
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1) # Epoch 1
        
        self.central = CentralRegistryAuthority(self.key_custody)
        
        # 2. Setup the Agent and Birth Record
        self.agent_code = "KMC.STU.agent001.0001.hash"
        payload = b'{"identity": "fake", "created_at": 100, "guardrails": [], "epoch_number": 1, "sig_alg": "ML-DSA-44"}'
        sig = self.key_custody.sign_birth(1, payload)
        
        self.birth_record = {
            "identity": "fake",
            "created_at": 100,
            "guardrails": [],
            "epoch_number": 1,
            "sig_alg": "ML-DSA-44",
            "signature": sig.hex()
        }
        self.token = ProofToken(
            agent_code=self.agent_code,
            birth_record=self.birth_record,
            history_length=0,
            current_head="fakehead",
            freshness_timestamp=time.time(),
            authority_reference="central_mock"
        )
        
        # 3. Take baseline snapshot and spin up Replicas
        baseline_snap = self.central.snapshot()
        
        root_pub = self.key_custody.get_root_public_key()
        self.us_east = RegionalReplicaRegistry("us-east", root_pub, central_sync=self.central)
        self.india_south = RegionalReplicaRegistry("india-south", root_pub, central_sync=self.central)
        
        # Apply baseline snapshot so both have the epoch keys
        self.assertTrue(self.us_east.apply_snapshot(baseline_snap))
        self.assertTrue(self.india_south.apply_snapshot(baseline_snap))
        
        # 4. Setup Verifiers targeting the regional replicas
        self.verifier_us = Verifier(registry=self.us_east)
        self.verifier_india = Verifier(registry=self.india_south)
        
    def test_revocation_fan_out_lag(self):
        """
        Proves that a distributed replica cleanly handles revocations, 
        and accurately simulates the residual risk window during propagation lag.
        """
        # Baseline: Both should pass (well, HALT_HARD on bad head, but not REVOKED)
        # We only care that they don't return REVOKED.
        res_us = self.verifier_us.verify_fast(self.token)
        self.assertNotEqual(res_us.status, "REVOKED")
        
        # 1. Central Authority Revokes the Agent
        self.central.revoke_agent(self.agent_code)
        
        # 2. Before Replica Syncs, US-East still accepts (LAG)
        res_lag = self.verifier_us.verify_fast(self.token)
        self.assertNotEqual(res_lag.status, "REVOKED")
        
        # 3. Replica Syncs
        snap = self.central.snapshot()
        self.us_east.apply_snapshot(snap)
        
        # 4. Now it's revoked
        res_sync = self.verifier_us.verify_fast(self.token)
        self.assertEqual(res_sync.status, "REVOKED")
        self.assertIn("explicitly revoked", res_sync.reason)

        # 1. Central Authority Revokes the Agent
        self.central.revoke_agent(self.agent_code)
        
        # 2. Central Authority generates a new Signed Snapshot
        new_snap = self.central.snapshot()
        
        # 3. Simulate Fan-Out: US-East gets it immediately. India-South experiences network lag.
        self.assertTrue(self.us_east.apply_snapshot(new_snap))
        # india_south does NOT apply it yet.
        
        # 4. Verification in US-East instantly blocks the agent
        res_us_after = self.verifier_us.verify_fast(self.token)
        self.assertEqual(res_us_after.status, "REVOKED", "US-East should instantly revoke the agent")
        self.assertIn("explicitly revoked", res_us_after.reason)
        
        # 5. Verification in India-South temporarily passes it (The Risk Window)
        res_india_after = self.verifier_india.verify_fast(self.token)
        self.assertNotEqual(res_india_after.status, "REVOKED", "India-South should lag and not revoke yet")
        
        # 6. Finally, India-South syncs the snapshot
        self.assertTrue(self.india_south.apply_snapshot(new_snap))
        
        # 7. Verification in India-South now blocks the agent
        res_india_final = self.verifier_india.verify_fast(self.token)
        self.assertEqual(res_india_final.status, "REVOKED", "India-South should block the agent after syncing")

    def test_default_construction_rejects_insecure_mode(self):
        """
        Prove that default construction (omitting central_sync) is hard-rejected
        and requires explicit opt-in to bypass, preventing accidental cross-replica replay vulnerabilities.
        """
        import pytest
        # 1. Omitting central_sync raises ValueError
        with self.assertRaisesRegex(ValueError, "central_sync is required"):
            RegionalReplicaRegistry("us-east", self.key_custody._root_pub)
            
        # 2. Explicitly opting in works but warns
        replica = RegionalReplicaRegistry("us-east", self.key_custody._root_pub, local_only=True)
        self.assertIsNone(replica.central_sync)

if __name__ == '__main__':
    unittest.main()
