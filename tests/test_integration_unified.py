import unittest
import time
import os
import tempfile
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.manager import AgentManager
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.verify import ProofToken
from kormic.crypto.twin import TwinManager

from kormic.models.behavior import BehaviorConfig

class TestUnifiedSystemIntegration(unittest.TestCase):
    def setUp(self):
        # 1. Infrastructure
        self.fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.fd)
        
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1) # Epoch 1
        self.record_store = SQLiteRecordStore(self.db_path)
        
        # 2. Phase 2: Registry & Replicas
        self.central_registry = CentralRegistryAuthority(self.key_custody)
        root_pub = self.key_custody.get_root_public_key()
        self.replica_us = RegionalReplicaRegistry("us-east", root_pub)
        self.replica_eu = RegionalReplicaRegistry("eu-west", root_pub)
        
        # 3. Phase 1 & 2: Managers and Verifiers
        self.agent_manager = AgentManager(self.key_custody, self.record_store)
        
        config = BehaviorConfig(
            accuracy_flag_threshold=0.90, accuracy_halt_threshold=0.80,
            overconfidence_flag_threshold=0.10, overconfidence_halt_threshold=0.20,
            guardrail_hit_flag_threshold=0.05, guardrail_hit_halt_threshold=0.10,
            latency_drift_flag_multiplier=2.0, latency_drift_halt_multiplier=5.0
        )
        self.behavior_monitor = BehaviorMonitor(config)
        
        self.verifier = Verifier(registry=self.replica_us) # Users hitting US server

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_end_to_end_lifecycle(self):
        """
        Tests the COMPLETE Unified Kormic Architecture (Phase 1 & Phase 2 combined).
        """
        # ==========================================
        # STAGE 1: BIRTH & INITIAL TWIN (Phase 1 & 2)
        # ==========================================
        agent_code, master_shares = self.agent_manager.register_new_agent(
            agent_type="STU",
            entity_ref="unified_agent",
            instance_num="0001",
            real_world_id="Integration Test",
            guardrails={"access": "standard"}
        )
        self.assertTrue(agent_code.startswith("KMC.STU.unified_agent.0001"))
        self.assertEqual(len(master_shares), 5, "Shamir split must yield 5 shares")
        
        # Ensure twin is immediately backed up (Event 0)
        baseline_twin = self.record_store.get_twin(agent_code)
        self.assertIsNotNone(baseline_twin)

        # ==========================================
        # STAGE 2: INITIAL REGISTRY SYNC (Phase 2)
        # ==========================================
        snap_v1 = self.central_registry.snapshot()
        self.assertTrue(self.replica_us.apply_snapshot(snap_v1))
        
        # Verify Agent is valid
        ped_dict = self.record_store.get(agent_code)
        token = ProofToken(
            agent_code=agent_code,
            birth_record=ped_dict["birth_record"],
            history_length=0,
            current_head=ped_dict["running_head"],
            freshness_timestamp=time.time(),
            authority_reference="central"
        )
        res = self.verifier.verify_fast(token)
        self.assertEqual(res.status, "PASS")

        # ==========================================
        # STAGE 3: CHURN & BEHAVIOR (Phase 1 & 2)
        # ==========================================
        for i in range(1, 11):
            new_shares = self.agent_manager.add_event(agent_code, f"event_{i}", snapshot_k=5)
            
            if i % 5 == 0:
                self.assertIsNotNone(new_shares, f"Twin MUST seal at event {i}")
                master_shares = new_shares  # UPDATE SHAMIR SHARES FOR LATEST TWIN
            else:
                self.assertIsNone(new_shares, f"Twin should NOT seal at event {i}")

        # Behavior Monitor Check
        healthy_metrics = {"accuracy": 0.95, "policy_violation": False}
        report = self.behavior_monitor.evaluate(agent_code, healthy_metrics)
        self.assertEqual(report.status, "OK", "Agent behavior should be OK")

        # ==========================================
        # STAGE 4: ISOLATION & REVOCATION (Phase 1 & 2)
        # ==========================================
        # Agent goes rogue, triggers a HALT behavior
        rogue_metrics = {"policy_violation": True}
        report_bad = self.behavior_monitor.evaluate(agent_code, rogue_metrics)
        self.assertEqual(report_bad.status, "HALT", "Agent must be halted by behavior monitor")
        
        # Root Authority receives HALT signal and Revokes Agent globally
        self.central_registry.revoke_agent(agent_code)
        snap_v2 = self.central_registry.snapshot()
        
        # Replica US pulls the new snapshot
        self.replica_us.apply_snapshot(snap_v2)
        
        # Verification should now fail instantly via Bloom Filter!
        res_fail = self.verifier.verify_fast(token)
        self.assertEqual(res_fail.status, "REVOKED", "Bloom filter MUST block revoked agent")

        # ==========================================
        # STAGE 5: CATASTROPHE & RECOVERY (Phase 2)
        # ==========================================
        # Central DB goes down, Agent live data is wiped
        self.record_store.put(agent_code, {})
        wiped_data = self.record_store.get(agent_code)
        self.assertEqual(wiped_data, {}, "Live database wiped")
        
        # Executive Ceremony (3 out of 5 shares)
        quorum = [master_shares[0], master_shares[2], master_shares[4]]
        sealed_blob = self.record_store.get_twin(agent_code)
        
        # Wake Twin
        restored_pedigree = TwinManager.wake_twin(sealed_blob, quorum, self.key_custody)
        
        # Validate Bounded Data Loss
        # We did 10 events. The twin sealed exactly at Event 10. So loss = 0.
        self.assertEqual(len(restored_pedigree.history), 10, "Restored pedigree should have 10 events")
        self.assertEqual(restored_pedigree.history[-1].event, "event_10")
        
        # Put the restored pedigree back into the live database
        self.record_store.put(agent_code, restored_pedigree.to_dict())
        
        # Prove restored pedigree is cryptographically valid
        token_restored = ProofToken(
            agent_code=agent_code,
            birth_record=restored_pedigree.birth_record.to_dict(),
            history_length=10,
            current_head=restored_pedigree.running_head,
            freshness_timestamp=time.time(),
            authority_reference="central"
        )
        
        # Un-revoke the agent centrally to allow it to pass again (simulating human review clearing the flag)
        self.central_registry.revoked_agents.remove(agent_code)
        self.central_registry.version += 1 # Bump version so replica accepts it
        snap_v3 = self.central_registry.snapshot()
        self.replica_us.apply_snapshot(snap_v3)
        
        # Use a fresh verifier to represent a clean verification state (cache cleared)
        verifier_final = Verifier(registry=self.replica_us)
        
        # Final Verification
        res_restored = verifier_final.verify_fast(token_restored)
        self.assertEqual(res_restored.status, "PASS", "Restored Twin must pass FAST verification seamlessly")


if __name__ == '__main__':
    unittest.main()
