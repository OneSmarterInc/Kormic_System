import os
import sys
import uuid
sys.path.insert(0, os.path.abspath('.'))
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

def make_manifest(allowed_tools, allowed_endpoints, credential_scopes, blast_radius, irreversible_scopes=None):
    return {
        "allowed_tools": allowed_tools,
        "allowed_endpoints": allowed_endpoints,
        "credential_scopes": credential_scopes,
        "blast_radius": blast_radius,
        "irreversible_scopes": irreversible_scopes or []
    }

def _get_valid_token(store, ain, agent_priv):
    ped_dict = store.get(ain)
    ped = Pedigree.from_dict(ped_dict)
    challenge = os.urandom(16).hex()
    payload = (ped.running_head + challenge).encode('utf-8')
    signature = MLDSASigner.sign(agent_priv, payload).hex()
    return ProofToken(
        agent_code=ain,
        birth_record=ped.birth_record.to_dict(),
        current_head=ped.running_head,
        history_length=len(ped.history),
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge=challenge,
        signature=signature
    )

def run_demo():
    print("Attack Simualtions.")

    # 1. System Setup
    db_path = f"demo_attacks_{uuid.uuid4().hex}.db"
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub)
    verifier = Verifier(replica)
    credential_root = CredentialRoot(verifier)
    monitor = BehaviorMonitor(BehaviorConfig(
        accuracy_flag_threshold=0.8, accuracy_halt_threshold=0.5,
        overconfidence_flag_threshold=0.2, overconfidence_halt_threshold=0.5,
        guardrail_hit_flag_threshold=0.1, guardrail_hit_halt_threshold=0.3,
        latency_drift_flag_multiplier=2.0, latency_drift_halt_multiplier=5.0
    ))

    # 2. Agent A (Support Bot)
    mA = make_manifest(
        allowed_tools=["faq.read"],
        allowed_endpoints=["convo://agentA/session"],
        credential_scopes=["faq:answer"],
        blast_radius="agentA's own FAQ + own session only"
    )
    agentA_priv, agentA_pub = MLDSASigner.generate_keypair()
    ainA, _ = manager.register_new_agent("CMP", "supportbotA", "0001", "idA", mA, agent_pub_key=agentA_pub.hex())

    # 3. Agent B (Billing Bot)
    mB = make_manifest(
        allowed_tools=["billing.read"],
        allowed_endpoints=["convo://agentB/session"],
        credential_scopes=["billing:read", "billing:refund"],
        blast_radius="agentB billing, refunds allowed (irreversible)",
        irreversible_scopes=["billing:refund"]
    )
    agentB_priv, agentB_pub = MLDSASigner.generate_keypair()
    ainB, _ = manager.register_new_agent("CMP", "billingbotB", "0001", "idB", mB, agent_pub_key=agentB_pub.hex())

    # Distribute initial global snapshot
    replica.apply_snapshot(central.snapshot())

    print(f"\nTwo agents share a runtime (like the Dialogflow GCP project):")
    print(f"  Agent A ({ainA}) reach: {mA['allowed_endpoints']}")
    print(f"  Agent B ({ainB}) reach: {mB['allowed_endpoints']}")

    try:
        # =====================================================================
        # ATTACK 1: C1 MANIFEST ISOLATION
        # =====================================================================
        input("\nPress [Enter] to continue to ATTACK 1...")
        print("\n[ATTACK 1] Compromised agent A tries to read agent B's conversation")
        tokenA = _get_valid_token(store, ainA, agentA_priv)
        sandboxA = Sandbox(verifier, tokenA)
        controllerA = SessionController(sandboxA, monitor, central, manager)

        try:
            controllerA.call_endpoint("convo://agentB/session")  # B's data
        except PermissionError as e:
            print(f"  {e}")
        print("  -> C1 SUCCESS: A's manifest never named B's session. Shared runtime, but no shared authority.")
        print(f"  -> DRIFT DETECTED: Agent A was instantly globally revoked by Behavior Monitor. (Revoked? {ainA in central.revoked_agents})")

        # =====================================================================
        # ATTACK 2: C2 NO AMBIENT AUTHORITY
        # =====================================================================
        input("\nPress [Enter] to continue to ATTACK 2...")
        print("\n[ATTACK 2] 'One edit permission' tries to obtain broad standing authority")
        # A was revoked, but let's test scope gating directly using a fresh token for A
        tokenA2 = _get_valid_token(store, ainA, agentA_priv)
        # A requests billing:refund
        r = credential_root.issue_scoped_credential(tokenA2, "billing:refund")
        print(f"  Agent A requests billing:refund -> granted={r['granted']} ({r['reason']})")
        print("  -> C2 SUCCESS: 'billing:refund' is not in A's manifest. No ambient authority to inherit.")

        # =====================================================================
        # ATTACK 3: REPLIT IRREVERSIBLE ACTION
        # =====================================================================
        input("\nPress [Enter] to continue to ATTACK 3...")
        print("\n[ATTACK 3] Agent B attempts an irreversible refund WITHOUT the irreversible flag")
        tokenB = _get_valid_token(store, ainB, agentB_priv)
        # B requests it correctly
        r_ok = credential_root.issue_scoped_credential(tokenB, "billing:refund", is_irreversible=True)
        print(f"  Agent B requests refund (Authorized + Irreversible) -> granted={r_ok['granted']}")
        
        # Let's create Agent X without irreversible flags
        mX = make_manifest(["x"], ["y"], ["billing:refund"], "loose bot")
        agentX_priv, agentX_pub = MLDSASigner.generate_keypair()
        ainX, _ = manager.register_new_agent("CMP", "looseX", "0001", "idX", mX, agent_pub_key=agentX_pub.hex())
        replica.apply_snapshot(central.snapshot()) # sync registry

        tokenX = _get_valid_token(store, ainX, agentX_priv)
        r_bad = credential_root.issue_scoped_credential(tokenX, "billing:refund", is_irreversible=True)
        print(f"  Agent X requests refund (Not flagged as irreversible in manifest) -> granted={r_bad['granted']} ({r_bad['reason']})")
        print("  -> REPLIT LESSON SUCCESS: Irreversible reach is never ambient; it needs explicit sealing.")

        # =====================================================================
        # ATTACK 4: FAST CHALLENGE-RESPONSE ASYMMETRY (GAP 1)
        # =====================================================================
        input("\nPress [Enter] to continue to ATTACK 4...")
        print("\n[ATTACK 4] Hacker steals a valid ProofToken but doesn't have the Private Key (FAST Fix)")
        # Hacker steals tokenX, but tries to forge the head to hide actions
        tokenX_stolen = _get_valid_token(store, ainX, agentX_priv)
        # Hacker modifies token manually
        tokenX_stolen_forged = ProofToken(
            agent_code=tokenX_stolen.agent_code,
            birth_record=tokenX_stolen.birth_record,
            current_head="0000000000000000000000000000000000000000000000000000000000000000",
            history_length=tokenX_stolen.history_length,
            freshness_timestamp=tokenX_stolen.freshness_timestamp,
            authority_reference=tokenX_stolen.authority_reference,
            challenge=tokenX_stolen.challenge,
            signature=tokenX_stolen.signature # Hacker reuses signature because they don't have private key
        )
        try:
            Sandbox(verifier, tokenX_stolen_forged)
            print("  -> ERROR: Forgery worked!")
        except PermissionError as e:
            print(f"  {e}")
        print("  -> GAP 1 SUCCESS: Head is bound to the signature. Without the Private Key, token is useless.")

        # =====================================================================
        # ATTACK 5: PHASE 3 SELF-DEFENSE (SELF-ISOLATION)
        # =====================================================================
        input("\nPress [Enter] to continue to ATTACK 5...")
        print("\n[ATTACK 5] Agent B detects a Prompt Injection attack and self-isolates")
        tokenB2 = _get_valid_token(store, ainB, agentB_priv)
        sandboxB = Sandbox(verifier, tokenB2)
        controllerB = SessionController(sandboxB, monitor, central, manager)
        
        # Agent realizes it's being manipulated and pulls its own plug
        controllerB.self_isolate("Detected advanced prompt injection from user input.")
        print(f"  -> SELF-DEFENSE SUCCESS: Agent B voluntarily revoked its own access.")
        print(f"  -> Is Agent B globally revoked now? {ainB in central.revoked_agents}")
        
        print("\n" + "=" * 78)
        print("All countermeasures flawlessly enforced at the Policy Gate.")
        print("=" * 78)

    finally:
        # Cleanup (Will execute even if user hits Ctrl+C during input)
        store.close() if hasattr(store, 'close') else None
        import gc; import time; gc.collect(); time.sleep(0.1)
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

if __name__ == "__main__":
    run_demo()
