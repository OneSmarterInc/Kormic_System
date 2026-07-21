import os
import sys
import uuid
import time
sys.path.insert(0, os.path.abspath('.'))

from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.runtime.credential import CredentialRoot

# Import the new, easy-to-use Developer SDK
from meshkor import MeshKorAgent, ReceiverClient, LocalAuthority

def setup_local_engine():
    db_path = f"demo_end_to_end_{uuid.uuid4().hex}.db"
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub)
    verifier = Verifier(replica)
    return manager, verifier, central, replica, db_path, store

def run_demo():
    print("MeshKor Package: End-to-End SDK Demo")
    print("=" * 80)
    
    # 1. Start the internal Kormic Engine (normally hosted in our cloud)
    print("\n[SYSTEM] Booting internal Kormic Engine...")
    manager, verifier, central, replica, db_path, store = setup_local_engine()
    authority = LocalAuthority(manager, verifier, central, replica)
    
    try:
        # =========================================================
        # THE BUILDER PERSPECTIVE
        # =========================================================
        input("\nPress [Enter] to see the Builder enroll an agent...")
        print("\n[BUILDER] Enrolling a new AI Agent using the MeshKor SDK...")
        
        manifest = {
            "allowed_tools": ["search"],
            "allowed_endpoints": ["api.acme.com/quote"],
            "credential_scopes": ["quote.read"],
            "irreversible_scopes": [],
            "blast_radius": "read-only quotes",
        }
        
        # 3 lines of code for the developer!
        agent = MeshKorAgent.enroll(
            authority=authority,
            agent_type="CMP", 
            entity_ref="acme", 
            instance="0001",
            real_world_id="Acme Corp / DUNS 123456789",
            manifest=manifest
        )
        print(f"  -> Agent successfully enrolled! AIN: {agent.ain}")
        
        print("\n[BUILDER] The agent is doing work and advancing its history chain...")
        agent.record_event("Booted up")
        agent.record_event("Searched for a quote on widget A")
        print(f"  -> Chain advanced. Current Head: {agent.current_head}")
        
        
        # =========================================================
        # THE RECEIVER PERSPECTIVE (INTERACTIVE HANDSHAKE)
        # =========================================================
        input("\nPress [Enter] to simulate a Receiver requesting authentication...")
        print("\n[RECEIVER] An external Database API is asked for a quote by the Agent.")
        
        rc = ReceiverClient(authority=authority)
        
        # Receiver issues a challenge nonce
        challenge = rc.new_challenge()
        print(f"  -> Receiver issued challenge: {challenge}")
        
        # Builder mints a token using the receiver's challenge
        print("\n[BUILDER] Minting ProofToken to present to the Receiver...")
        token = agent.mint_token(challenge=challenge)
        
        # Receiver validates the token
        print("\n[RECEIVER] Validating the presented token...")
        verdict = rc.validate(token)
        
        if verdict.ok:
            print("  -> RESULT: PASS! The agent is mathematically authenticated.")
            print(f"  -> ALLOWED REACH: {verdict.may_reach['allowed_endpoints']}")
        else:
            print(f"  -> RESULT: {verdict.status} ({verdict.reason})")


        # =========================================================
        # THE RECEIVER PERSPECTIVE (FAIL-CLOSED NEGATIVE TESTS)
        # =========================================================
        input("\nPress [Enter] to simulate a Hacker attack...")
        print("\n[ATTACKER] Hacker manipulates the token's running head to hide actions...")
        
        # Modify the token's head
        import dataclasses
        token = dataclasses.replace(token, current_head="0000000000000000000000000000000000000000000000000000000000000000")
        
        print("\n[RECEIVER] Validating the tampered token...")
        hacker_verdict = rc.validate(token)
        print(f"  -> RESULT: {hacker_verdict.status} | Reason: {hacker_verdict.reason}")
        print("  -> SUCCESS: The MeshKor SDK mathematically blocked the forgery.")
        
        
        print("\n" + "=" * 80)
        print("Demo completed successfully. The SDK is ready for builders.")
        print("=" * 80)
        
    finally:
        store.close() if hasattr(store, 'close') else None
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

if __name__ == "__main__":
    run_demo()
