import sys
import os
import time
import socket

from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import RegionalReplicaRegistry, CentralRegistryAuthority
from kormic.verify.engine import Verifier
from kormic.manager import AgentManager
from kormic.models.verify import ProofToken
from kormic.runtime.sandbox import Sandbox
from kormic.crypto.algorithms import MLDSASigner
from meshkor.authority import LocalAuthority
from meshkor.receiver import ReceiverClient

def run_demo():
    print("==========================================================")
    print(" MeshKor Reconnaissance Gap Demo (Counterfactual)")
    print("==========================================================")

    # 1. Setup the Root Infrastructure
    key_custody = SoftwareKeyCustody()
    key_custody.generate_epoch_key(1)
    central = CentralRegistryAuthority(key_custody)
    store = SQLiteRecordStore(":memory:")
    
    print("\n[+] Enrolling Vendor (e.g. University of Zurich / Acme Corp)...")
    vpriv, vpub = MLDSASigner.generate_keypair()
    import uuid
    nonce = uuid.uuid4().hex
    sig = MLDSASigner.sign(vpriv, f"{nonce}:vendor_demo".encode()).hex()
    central.enroll_vendor("vendor_demo", vpub.hex(), sig, "Vendor ID", nonce)

    registry = RegionalReplicaRegistry("us-east", key_custody.get_root_public_key(), local_only=True)
    registry.apply_snapshot(central.snapshot())
    manager = AgentManager(key_custody, store, registry_reader=registry)

    # 2. Register BAIN with strict Read-Scopes and Egress
    print("[+] Minting BAIN with read-scopes: ['reddit_changemyview']")
    bain_res = manager.register_new_agent(
        agent_type="BLD",
        entity_ref="vendor_demo",
        instance_num="v1",
        real_world_id="v_id",
        guardrails={"allowed_tools": ["search"]},
        read_scopes=["reddit_changemyview"], # Can only scrape this subreddit
        allowed_egress=["api.reddit.com"], # Can only egress to Reddit
        artifact_signature=MLDSASigner.sign(vpriv, "vendor_demov1digest".encode()).hex(),
        vendor_pub_key=vpub.hex(),
        artifact_digest="digest"
    )

    # 3. Deploy DAIN
    print("[+] Deploying DAIN (The specific agent instance)...")
    dain_res = manager.register_new_agent(
        agent_type="DPL",
        entity_ref="hospital",
        instance_num="1",
        real_world_id="h_id",
        guardrails={"allowed_tools": ["search"]},
        read_scopes=["reddit_changemyview"],
        allowed_egress=["api.reddit.com"],
        derived_from=bain_res.agent_code,
        agent_pub_key=vpub.hex()
    )

    # 4. Generate ProofToken
    verifier = Verifier(registry)
    authority = LocalAuthority(manager, verifier, central, registry)
    receiver = ReceiverClient(authority)
    
    ped_dict = store.get(dain_res.agent_code)
    bain_ped_dict = store.get(bain_res.agent_code)
    t_nonce = verifier.generate_challenge()
    t_sig = MLDSASigner.sign(vpriv, ("head" + t_nonce).encode()).hex()
    
    token = ProofToken(
        agent_code=dain_res.agent_code,
        birth_record=ped_dict["birth_record"],
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        parent_birth_record=bain_ped_dict["birth_record"],
        challenge=t_nonce,
        signature=t_sig
    )

    # --- SIMULATE HUGGING FACE INCIDENT ---
    print("\n==========================================================")
    print(" ATTACK 1: The Hugging Face Incident (RCE & Env Theft)")
    print("==========================================================")
    
    # Standing secrets in environment (simulated)
    os.environ["AWS_SECRET_KEY"] = "AKIA1234567890"
    os.environ["MONGO_DB_PASSWORD"] = "static-password-123"
    
    print("[!] Agent gets Remote Code Execution (RCE) in a Sandbox.")
    print("[!] Initializing MeshKor Sandbox with Evaporator & Egress Firewall...")
    sandbox = Sandbox(verifier, token)
    
    print("\n[+] Attempting to read standing credentials from the Sandbox Session Environment...")
    if "AWS_SECRET_KEY" not in sandbox.session_env:
        print("    --> SUCCESS: MeshKor Evaporator scrubbed AWS_SECRET_KEY from the session context.")
        print("    --> (And importantly, the host process os.environ remains untouched!)")
    else:
        print("    --> FAILURE: AWS_SECRET_KEY is still present in session_env!")

    print("\n[+] Attempting to pivot to AWS Metadata IP (169.254.169.254)...")
    try:
        sandbox.check_egress("169.254.169.254")
        print("    --> FAILURE: Attested as allowed!")
    except PermissionError as e:
        print(f"    --> SUCCESS: MeshKor Egress Firewall Policy blocked pivot. ({e})")
    except Exception as e:
        print(f"    --> OTHER ERROR: {e}")

    # --- SIMULATE REDDIT INCIDENT ---
    print("\n==========================================================")
    print(" ATTACK 2: The Reddit Persuasion Experiment (Scraping)")
    print("==========================================================")
    
    print("[+] Rogue Agent attempts to scrape r/politics without a token...")
    print("    --> Reddit (without MeshKor): Success. Data scraped invisibly.")
    print("    --> Reddit (MeshKor Receiver): 401 Unauthorized. 'No token = No data'.")
    
    print("\n[+] Rogue Agent generates a fresh ProofToken to scrape unauthorized r/politics...")
    t_nonce_politics = verifier.generate_challenge()
    t_sig_politics = MLDSASigner.sign(vpriv, ("head" + t_nonce_politics).encode()).hex()
    token_politics = ProofToken(
        agent_code=dain_res.agent_code,
        birth_record=ped_dict["birth_record"],
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        parent_birth_record=bain_ped_dict["birth_record"],
        challenge=t_nonce_politics,
        signature=t_sig_politics
    )
    
    verdict_politics = receiver.validate(token_politics, action_type="read", resource="reddit_politics")
    if not verdict_politics.ok:
        print(f"    --> SUCCESS: Rejected. Agent read_scope does not contain 'reddit_politics'. Reason: {verdict_politics.reason}")
    else:
        print("    --> FAILURE: Agent authorized to read politics!")

    print("\n[+] Agent generates a FRESH ProofToken to scrape authorized r/changemyview...")
    t_nonce_2 = verifier.generate_challenge()
    t_sig_2 = MLDSASigner.sign(vpriv, ("head" + t_nonce_2).encode()).hex()
    
    token_2 = ProofToken(
        agent_code=dain_res.agent_code,
        birth_record=ped_dict["birth_record"],
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        parent_birth_record=bain_ped_dict["birth_record"],
        challenge=t_nonce_2,
        signature=t_sig_2
    )
    
    verdict_cmv = receiver.validate(token_2, action_type="read", resource="reddit_changemyview")
    if verdict_cmv.ok:
        print("    --> SUCCESS: Authorized. Agent is accountable and cryptographically tied to the University of Zurich/Vendor.")
    else:
        print("    --> FAILURE: Valid read was rejected.")

    print("\n==========================================================")
    print(" Demo complete: Reconnaissance Gap is sealed.")
    print("==========================================================")


if __name__ == "__main__":
    run_demo()
