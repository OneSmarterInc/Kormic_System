import os
import time
import json
import uuid

from rich.console import Console
from rich.panel import Panel

from kormic.crypto.software import SoftwareKeyCustody, ThresholdPolicy
from kormic.crypto.algorithms import MLDSASigner
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.manager import AgentManager
from kormic.models.approval import DelegationAssertion
from kormic.verify.engine import Verifier
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.credential import CredentialRoot
from kormic.runtime.controller import SessionController
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.behavior import BehaviorConfig
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken
from kormic.runtime.detection import DevDetectionSink

console = Console()

def _get_valid_token(store, ain, agent_priv):
    ped_dict = store.get(ain)
    ped = Pedigree.from_dict(ped_dict)
    challenge = os.urandom(16).hex()
    payload = json.dumps({
        "current_head": ped.running_head,
        "challenge": challenge,
        "sig_alg": 'ML-DSA-87',
        "fmt_ver": 1
    }, sort_keys=True).encode('utf-8')
    signature = MLDSASigner.sign('ML-DSA-87', agent_priv, payload).hex()
    parent_dict = store.get(ped.birth_record.derived_from) if ped.birth_record.derived_from else None
    parent_br = Pedigree.from_dict(parent_dict).birth_record.to_dict() if parent_dict else None
    return ProofToken(
        agent_code=ain,
        birth_record=ped.birth_record.to_dict(),
        parent_birth_record=parent_br,
        current_head=ped.running_head,
        history_length=len(ped.history),
        freshness_timestamp=time.time(),
        authority_reference="demo_central",
        challenge=challenge,
        signature=signature,
        sig_alg='ML-DSA-87',
        fmt_ver=1
    )

def run_demo():
    console.print(Panel.fit("[bold cyan]KORMIC: GOLDEN PATH END-TO-END DEMO[/bold cyan]"))
    db_path = f"demo_golden_{uuid.uuid4().hex}.db"
    
    sink = DevDetectionSink()
    h1_priv, h1_pub = MLDSASigner.generate_keypair('ML-DSA-87')
    h2_priv, h2_pub = MLDSASigner.generate_keypair('ML-DSA-87')
    h3_priv, h3_pub = MLDSASigner.generate_keypair('ML-DSA-87')
    enrolled_holders = {"exec1": h1_pub, "exec2": h2_pub, "exec3": h3_pub}
    threshold_policy = ThresholdPolicy(k=2, n=3, enrolled_holders=enrolled_holders, detection_sink=sink)
    keys = SoftwareKeyCustody(threshold_policy=threshold_policy)
    
    console.print("[dim]Step 9: Threshold Root Operation (Done early to bootstrap)[/dim]")
    op_key = "generate_epoch_key_1"
    threshold_policy.approve(op_key, "exec1", MLDSASigner.sign('ML-DSA-87', h1_priv, op_key.encode('utf-8')))
    threshold_policy.approve(op_key, "exec2", MLDSASigner.sign('ML-DSA-87', h2_priv, op_key.encode('utf-8')))
    keys.generate_epoch_key(1)
    console.print("[green]Root operation success via 2-of-3 threshold quorum.[/green]")
    
    store = SQLiteRecordStore(db_path)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub, central_sync=central)
    manager = AgentManager(keys, store, default_epoch=1, registry_reader=replica)
    verifier = Verifier(replica)
    credential_root = CredentialRoot(verifier)
    monitor = BehaviorMonitor(BehaviorConfig(
        accuracy_flag_threshold=0.8, accuracy_halt_threshold=0.5,
        overconfidence_flag_threshold=0.2, overconfidence_halt_threshold=0.5,
        guardrail_hit_flag_threshold=0.1, guardrail_hit_halt_threshold=0.3,
        latency_drift_flag_multiplier=2.0, latency_drift_halt_multiplier=5.0
    ))
    
    try:
        console.print("\n[dim]Step 1: Vendor Enrollment[/dim]")
        vendor_priv, vendor_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        vendor_name = "golden_vendor"
        challenge = "nonce_1"
        payload = f"{challenge}:{vendor_name}".encode('utf-8')
        signature = MLDSASigner.sign('ML-DSA-87', vendor_priv, payload).hex()
        central.enroll_vendor(vendor_name, vendor_pub.hex(), signature, "vendor.com", challenge)
        console.print(f"[green]Vendor '{vendor_name}' enrolled successfully.[/green]")
        
        console.print("\n[dim]Step 2 & 8: Principal Delegation & Build Identity Issuance[/dim]")
        prin_priv, prin_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        central.enroll_principal("sec_admin", prin_pub.hex(), MLDSASigner.sign('ML-DSA-87', prin_priv, f"nonce_2:sec_admin".encode('utf-8')).hex(), "admin.vendor.com", "nonce_2")
        
        assertion_unsigned = DelegationAssertion(principal_ref="sec_admin", action="release", target="sha256:111", nonce="123456789", expiry=time.time() + 60)
        delegation_sig = MLDSASigner.sign('ML-DSA-87', prin_priv, assertion_unsigned.signable_payload()).hex()
        import dataclasses
        assertion = dataclasses.replace(assertion_unsigned, signature=delegation_sig)
        
        bain_manifest = {
            "allowed_tools": ["read_db", "write_db"],
            "allowed_endpoints": ["api.vendor.com"],
            "credential_scopes": [],
            "blast_radius": "all",
            "irreversible_scopes": [],
            "read_scopes": ["public:docs", "internal:logs"],
            "allowed_egress": ["vendor.com", "metrics.com"]
        }
        keys.threshold_policy = None
        snap = central.snapshot()
        keys.threshold_policy = threshold_policy
        replica.apply_snapshot(snap)
        
        vendor_payload = ("golden_vendor" + "v1" + "sha256:111").encode('utf-8')
        vendor_sig = MLDSASigner.sign('ML-DSA-87', vendor_priv, vendor_payload).hex()
        bain, _ = manager.register_new_agent(
            agent_type="BLD",
            entity_ref="golden_vendor",
            instance_num="v1",
            real_world_id="GoldenBot",
            guardrails=bain_manifest,
            artifact_signature=vendor_sig,
            vendor_pub_key=vendor_pub.hex(),
            artifact_digest="sha256:111",
            approval_assertion=assertion.__dict__,
            read_scopes=bain_manifest["read_scopes"],
            allowed_egress=bain_manifest["allowed_egress"]
        )
        console.print(f"[green]BAIN Issued: {bain}[/green]")
        
        console.print("\n[dim]Step 3: Deployment Issuance with Containment[/dim]")
        dain_manifest = {
            "allowed_tools": ["read_db"],
            "allowed_endpoints": ["api.vendor.com"],
            "credential_scopes": [],
            "irreversible_scopes": [],
            "blast_radius": "all",
            "read_scopes": ["public:docs"],
            "allowed_egress": ["vendor.com"]
        }
        agent_priv, agent_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        dain, _ = manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital_a",
            instance_num="0001",
            real_world_id="deployment_1",
            guardrails=dain_manifest,
            agent_pub_key=agent_pub.hex(),
            derived_from=bain,
            read_scopes=dain_manifest["read_scopes"],
            allowed_egress=dain_manifest["allowed_egress"]
        )
        console.print(f"[green]DAIN Issued: {dain}[/green]")
        keys.threshold_policy = None
        snap = central.snapshot()
        keys.threshold_policy = threshold_policy
        replica.apply_snapshot(snap)
        
        console.print("\n[dim]Step 4: Session Open and Verification[/dim]")
        token = _get_valid_token(store, dain, agent_priv)
        sandbox = Sandbox(verifier, token, detection_sink=sink)
        controller = SessionController(sandbox, monitor, central, manager)
        console.print("[green]Session opened and verified FAST Challenge.[/green]")
        
        console.print("\n[dim]Step 5: Legitimate Operation[/dim]")
        controller.execute_tool("read_db")
        sandbox.read_information("public:docs")
        sandbox.check_egress("vendor.com")
        console.print("[green]Allowed operations completed successfully.[/green]")
        
        console.print("\n[dim]Step 6: Refused Operation with Detection[/dim]")
        try:
            controller.execute_tool("write_db")
        except PermissionError:
            console.print("[yellow]write_db blocked (out of DAIN manifest)[/yellow]")
        assert sink.events[-1].event_kind in ("manifest_breach", "out_of_scope_tool")
        
        try:
            sandbox.read_information("internal:logs")
        except PermissionError:
            console.print("[yellow]read_information blocked (out of DAIN read scopes)[/yellow]")
        
        try:
            sandbox.check_egress("evil.com")
        except PermissionError:
            console.print("[yellow]egress blocked (out of DAIN egress config)[/yellow]")
            
        console.print("\n[dim]Step 7: Recon Escalation[/dim]")
        for i in range(25):
            try:
                sandbox.check_egress(f"scan-{i}.evil.com")
            except PermissionError:
                pass
        recon_events = [e for e in sink.events if e.event_kind == "reconnaissance_breadth"]
        if recon_events:
            console.print("[bold red]Ongoing Reconnaissance Breadth detected and flagged![/bold red]")
            
        console.print("\n[dim]Step 10: Chain Verification and Cascading Recall[/dim]")
        
        agent_priv2, agent_pub2 = MLDSASigner.generate_keypair('ML-DSA-87')
        dain2, _ = manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital_c",
            instance_num="0003",
            real_world_id="deployment_3",
            guardrails=dain_manifest,
            agent_pub_key=agent_pub2.hex(),
            derived_from=bain,
            read_scopes=dain_manifest["read_scopes"],
            allowed_egress=dain_manifest["allowed_egress"]
        )
        keys.threshold_policy = None
        snap_pre = central.snapshot()
        replica.apply_snapshot(snap_pre)
        keys.threshold_policy = threshold_policy
        
        token2 = _get_valid_token(store, dain2, agent_priv2)
        res = verifier.verify_fast(token2)
        console.print(f"Pre-revocation FAST status for new DAIN: [green]{res.status}[/green]")
        
        console.print(f"[yellow]Revoking parent BAIN: {bain}[/yellow]")
        keys.threshold_policy = None
        central.revoke_agent(bain)
        snap2 = central.snapshot()
        replica.apply_snapshot(snap2)
        keys.threshold_policy = threshold_policy
        
        res2 = verifier.verify_fast(token2)
        console.print(f"Post-revocation FAST status for child DAIN: [red]{res2.status}[/red]")
        assert res2.status == "REVOKED"
        
        console.print("\n[bold cyan]Golden Path Demo Complete![/bold cyan]")
    finally:
        if hasattr(store, 'close'):
            store.close()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except:
                pass

if __name__ == "__main__":
    run_demo()
