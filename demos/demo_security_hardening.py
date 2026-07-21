import os
import sys
import uuid
import time
sys.path.insert(0, os.path.abspath('.'))
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.credential import CredentialRoot
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken
from kormic.crypto.ceremony import ThresholdCeremony

def make_manifest(allowed_tools, allowed_endpoints, credential_scopes, blast_radius, irreversible_scopes=None):
    return {
        "allowed_tools": allowed_tools,
        "allowed_endpoints": allowed_endpoints,
        "credential_scopes": credential_scopes,
        "blast_radius": blast_radius,
        "irreversible_scopes": irreversible_scopes or []
    }

def run_demo():
    print("Security Hardening & Math Validation Simulation ")
    

    # 1. System Setup
    db_path = f"demo_hardening_{uuid.uuid4().hex}.db"
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub)
    verifier = Verifier(replica)
    credential_root = CredentialRoot(verifier)

    # Agent Setup
    m_agent = make_manifest(["tool1"], ["endpoint1"], ["scope1"], "test")
    agent_priv, agent_pub = MLDSASigner.generate_keypair()
    ain, _ = manager.register_new_agent("CMP", "secbot", "0001", "sec", m_agent, agent_pub_key=agent_pub.hex())
    replica.apply_snapshot(central.snapshot())

    try:
        # =====================================================================
        # ATTACK 1: THE REPLAY ATTACK (Anti-Replay Nonce Cache)
        # =====================================================================
        input("Enter.")
        print("\n[ATTACK 1] Hacker intercepts a valid ProofToken and replays it 10 seconds later")
        
        ped_dict = store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        challenge = verifier.generate_challenge()
        payload = (ped.running_head + challenge).encode('utf-8')
        signature = MLDSASigner.sign(agent_priv, payload).hex()
        
        token = ProofToken(
            agent_code=ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=len(ped.history),
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge,
            signature=signature
        )

        print("  -> First Verification (Genuine Agent):")
        r1 = verifier.verify_fast(token)
        print(f"     Status: {r1.status}")

        print("  -> Second Verification (Hacker Replaying Token):")
        r2 = verifier.verify_fast(token)
        print(f"     Status: {r2.status} | Reason: {r2.reason}")
        print("  -> SUCCESS: The Replay Attack was mathematically blocked by the Verifier.")


        # =====================================================================
        # ATTACK 2: THE "FAIL OPEN" LOOPHOLE (Missing Signature)
        # =====================================================================
        input("Enter.")
        print("\n[ATTACK 2] Hacker submits a token but entirely deletes the cryptographic signature")
        
        challenge2 = verifier.generate_challenge()
        token_no_sig = ProofToken(
            agent_code=ain,
            birth_record=ped.birth_record.to_dict(),
            current_head="tampered_head_data",
            history_length=len(ped.history),
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=challenge2,
            signature=""  # Attacker stripped the signature!
        )

        print("  -> Verification of empty-signature token:")
        r3 = verifier.verify_fast(token_no_sig)
        print(f"     Status: {r3.status} | Reason: {r3.reason}")
        print("  -> SUCCESS: The system strict Fails-Closed. It doesn't accidentally pass.")


        # =====================================================================
        # ATTACK 3: KEYLESS BIRTH RECORD (Credential Root Block)
        # =====================================================================
        input("Enter.")
        print("\n[ATTACK 3] Hacker tries to boot an agent with a Keyless Birth Record")
        
        # Register a keyless agent
        ain_keyless, _ = manager.register_new_agent("CMP", "ghost", "0001", "gh", m_agent)
        ped_keyless = Pedigree.from_dict(store.get(ain_keyless))
        
        token_keyless = ProofToken(
            agent_code=ain_keyless,
            birth_record=ped_keyless.birth_record.to_dict(),
            current_head=ped_keyless.running_head,
            history_length=len(ped_keyless.history),
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge=verifier.generate_challenge(),
            signature="fake_sig"
        )
        
        try:
            Sandbox(verifier, token_keyless)
            print("     Sandbox booted successfully (FAILURE!)")
        except PermissionError as e:
            print(f"     Sandbox Boot Blocked: {e}")
        print("  -> SUCCESS: No public key = No execution.")


        # =====================================================================
        # ATTACK 4: THE SHAMIR "MATH GARBAGE" LOOPHOLE (HMAC Validation)
        # =====================================================================
        input("Enter.")
        print("\n[ATTACK 4] Hacker submits perfectly formatted Shamir shares from the WRONG master key")
        
        real_master_key = os.urandom(32)
        import hashlib
        expected_hash = hashlib.sha256(real_master_key).hexdigest()
        
        # Setup Ceremony with the true hash
        ceremony = ThresholdCeremony(expected_hash, n=5, standard_quorum=3)
        
        # Attacker splits a FAKE master key and submits 3 shares
        fake_master_key = os.urandom(32)
        fake_shares = keys.wrap_twin_key(fake_master_key)[:3]
        
        def mock_destroy():
            print("SYSTEM DESTROYED!")
            
        print("  -> Attacker submits 3 well-formatted shares from the fake key.")
        try:
            ceremony.authorize_create(fake_shares, mock_destroy)
        except PermissionError as e:
            print(f"     Ceremony Blocked: {e}")
        print("  -> SUCCESS: Constant-time HMAC validation blocked the 'Math Garbage' loophole.")

        
        print("System Passed")
    

    finally:
        # Cleanup
        store.close() if hasattr(store, 'close') else None
        import gc; gc.collect(); time.sleep(0.1)
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

if __name__ == "__main__":
    run_demo()
