import time
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.manager import AgentManager
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.models.verify import ProofToken
from kormic.crypto.twin import TwinManager
from kormic.logger import kormic_logger

def run_phase2_demo():
    print("\n1. System Init log.")
    
    # Use an in-memory DB for a clean demo run
    import tempfile
    import os
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    key_custody = SoftwareKeyCustody()
    key_custody.generate_epoch_key(1)
    record_store = SQLiteRecordStore(db_path)
    
    # 1. Setup Distributed Architecture
    central = CentralRegistryAuthority(key_custody)
    root_pub = key_custody.get_root_public_key()
    replica_us = RegionalReplicaRegistry("us-east", root_pub, central_sync=central_hq)
    replica_india = RegionalReplicaRegistry("india-south", root_pub, central_sync=central_hq)
    
    # 2. Manager and Verifiers
    manager = AgentManager(key_custody, record_store)
    verifier_us = Verifier(registry=replica_us)
    verifier_india = Verifier(registry=replica_india)

    print("\n2] Creating Agent & Sealing Initial Twin.")
    agent_code, latest_shares = manager.register_new_agent(
        agent_type="STU",
        entity_ref="demo_agent",
        instance_num="0001",
        real_world_id="John Doe",
        guardrails={"access": "standard"}
    )
    print(f"Agent Created: {agent_code}")
    print(f"5 Shamir Shares Generated for the Twin Key.")
    input("\nEnter.")
    
    print("\n3] Simulation of Agent Events (Snapshot Twin K=5).")
    print("Adding 4 events.")
    for i in range(1, 5):
        manager.add_event(agent_code, f"event_{i}", snapshot_k=5)
        print(f"  Added event_{i}")
        time.sleep(0.5)
        
    print("Adding 5th event. TWIN WILL SEAL (K=5 snapshot limit reached).")
    new_shares = manager.add_event(agent_code, "event_5", snapshot_k=5)
    print(f"  Added event_5")
    if new_shares:
        latest_shares = new_shares
        
    input("\nEnter.")
        
    print("\n4] Pushing Initial Snapshot to Regions.")
    baseline_snap = central.snapshot()
    replica_us.apply_snapshot(baseline_snap)
    replica_india.apply_snapshot(baseline_snap)
    print("Replicas successfully synced and built local Bloom Filters.")

    input("\nEnter.")

    print("\n5] Revoking the Agent (Distributed Registry Fan-Out & Bloom Filter).")
    central.revoke_agent(agent_code)
    new_snap = central.snapshot()
    
    print("-> Pushing new snapshot to US-East.")
    replica_us.apply_snapshot(new_snap)
    
    print("-> Simulating network lag, India-South has NOT received yet.")
    
    # We need a ProofToken to verify
    ped_dict = record_store.get(agent_code)
    token = ProofToken(
        agent_code=agent_code,
        birth_record=ped_dict["birth_record"],
        history_length=len(ped_dict["history"]),
        current_head=ped_dict["running_head"],
        freshness_timestamp=time.time(),
        authority_reference="central"
    )
    
    res_us = verifier_us.verify_fast(token)
    print(f"US-East Verification: {res_us.status} It blocked the agent instantly")
    
    res_india = verifier_india.verify_fast(token)
    print(f"India-South Verification: {res_india.status} It still passes the agent due to simulated lag.")
    
    print("\n-> Pushing snapshot to India-South to resolve lag...")
    replica_india.apply_snapshot(new_snap)
    res_india2 = verifier_india.verify_fast(token)
    print(f"India-South Verification after Sync: {res_india2.status} (Agent blocked!)")

    input("\nEnter.")

    print("\n6] Data Loss & Encrypted Twin Recovery.")
    print("Simulating server crash: Deleting Live Agent Database...")
    record_store.put(agent_code, {}) # Wipe live data
    
    print("Gathering executive hardware keys.")
    quorum = [latest_shares[0], latest_shares[2], latest_shares[3]]
    
    print("Waking Twin.")
    sealed_blob = record_store.get_twin(agent_code)
    restored_pedigree = TwinManager.wake_twin(sealed_blob, quorum, key_custody)
    
    print(f"Agent successfully restored!")
    print(f"Restored History Length: {len(restored_pedigree.history)}")
    
    # print("\n" + "="*80)
    # print("PHASE 2 DEMO COMPLETE. Check kormic_activity.log for internal system details!")
    # print("="*80)
    
    # Cleanup DB
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except:
            pass

if __name__ == "__main__":
    run_phase2_demo()
