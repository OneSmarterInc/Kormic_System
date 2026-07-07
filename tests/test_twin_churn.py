import unittest
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.manager import AgentManager
from kormic.crypto.twin import TwinManager

class TestTwinChurnSnapshot(unittest.TestCase):
    def setUp(self):
        import tempfile
        import os
        self.fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.fd)
        
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.record_store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.key_custody, self.record_store)

    def tearDown(self):
        import os
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_snapshot_twin_bounded_loss(self):
        """
        Proves the High-Churn Snapshot Twin logic (Section 6.4).
        An agent adds 7 events. The Twin syncs every 5 events (K=5).
        Upon catastrophic restore, the Twin should have exactly 5 events,
        proving a bounded data loss of (K-1) events, but saving massive bandwidth.
        """
        # 1. Create agent (seals baseline twin at 0 events)
        agent_code, latest_shares = self.manager.register_new_agent(
            agent_type="STU",
            entity_ref="churn_agent",
            instance_num="0001",
            real_world_id="churn_test",
            guardrails={}
        )
        
        # 2. Add 7 Events (Snapshot K=5)
        # Events 1-4: Live DB updates, Twin does NOT sync (saves bandwidth)
        for i in range(1, 5):
            new_shares = self.manager.add_event(agent_code, f"event_{i}", snapshot_k=5)
            self.assertIsNone(new_shares, "Twin should not seal on events 1-4")
            
        # Event 5: Live DB updates, Twin DOES sync (K=5)
        new_shares = self.manager.add_event(agent_code, "event_5", snapshot_k=5)
        self.assertIsNotNone(new_shares, "Twin MUST seal on event 5")
        latest_shares = new_shares # Executives receive new shares
        
        # Events 6-7: Live DB updates, Twin does NOT sync
        for i in range(6, 8):
            new_shares = self.manager.add_event(agent_code, f"event_{i}", snapshot_k=5)
            self.assertIsNone(new_shares, "Twin should not seal on events 6-7")
            
        # 3. Verify Live DB has all 7 events
        live_pedigree = self.record_store.get(agent_code)
        self.assertEqual(len(live_pedigree["history"]), 7, "Live agent should have 7 events")
        
        # 4. SIMULATE CATASTROPHIC CRASH (Delete Live Database)
        self.record_store.put(agent_code, {}) # Wipe it out
        
        # 5. RESTORE FROM TWIN
        # We grab the ciphertext blob from the twin store
        sealed_blob = self.record_store.get_twin(agent_code)
        
        # We gather 3 of the 5 shares (Key Ceremony)
        quorum = [latest_shares[0], latest_shares[2], latest_shares[4]]
        
        # Wake the Twin
        restored_pedigree = TwinManager.wake_twin(sealed_blob, quorum, self.key_custody)
        
        # 6. ASSERT BOUNDED LOSS
        # The restored pedigree should have EXACTLY 5 events. Events 6 and 7 were lost in the crash.
        self.assertEqual(len(restored_pedigree.history), 5, "Restored twin should have exactly 5 events")
        self.assertEqual(restored_pedigree.history[-1].event, "event_5")
        
        print(f"\n[Churn Test] Live Agent crashed at 7 events.")
        print(f"[Churn Test] Restored from Twin at 5 events.")
        print(f"[Churn Test] Bounded Loss: 2 events (Max allowed was K-1 = 4).")
        print(f"[Churn Test] Bandwidth Saved: Did not ship 6 full Pedigree ciphertext blobs over the network.")

if __name__ == '__main__':
    unittest.main()
