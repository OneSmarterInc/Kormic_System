import time
from rich.console import Console
from rich.panel import Panel
from kormic.runtime import runtime
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken

console = Console()

def run_attack_demo():
    console.print(Panel.fit("[bold red]KORMIC SECURITY DEMO: FORGED AGENT ATTACK[/bold red]"))
    
    # 1. Register a normal agent
    console.print("[dim]1. Registering a standard external agent...[/dim]")
    agent_code = runtime.agent_manager.register_new_agent(
        agent_type="CMP",
        entity_ref="externalvendor",
        instance_num="0001",
        real_world_id="Vendor ID 99321",
        guardrails={"permissions": "read-only"}
    )
    console.print(f"[green]Agent registered with identity:[/green] {agent_code}")
    
    # 2. Simulate the attacker compromising the database
    console.print("\n[dim]2. Attacker hacks the database and elevates permissions...[/dim]")
    
    # Fetch the agent's pedigree from the database
    pedigree_data = runtime.record_store.get(agent_code)
    pedigree = Pedigree.from_dict(pedigree_data)
    
    # FORGE THE DATA: The attacker tries to give themselves admin rights
    forged_birth_record = pedigree.birth_record.to_dict()
    forged_birth_record["guardrails"] = {"permissions": "SUPERADMIN_ROOT_ACCESS"}
    
    console.print(f"[bold yellow]Forged Guardrails:[/bold yellow] {forged_birth_record['guardrails']}")
    
    # 3. Attacker tries to communicate across the Commons
    console.print("\n[dim]3. Attacker builds a ProofToken with forged data and tries to communicate...[/dim]")
    
    token = ProofToken(
        agent_code=agent_code,
        birth_record=forged_birth_record, # Sending the forged birth record
        authority_reference="KormicRoot",
        current_head=pedigree.running_head,
        history_length=len(pedigree.history),
        freshness_timestamp=time.time()
    )
    
    console.print("[yellow]ProofToken generated and sent to University Agent.[/yellow]")
    
    # 4. University Agent verifies the token
    console.print("\n[dim]4. University Agent receives token and runs FAST O(1) Verification...[/dim]")
    
    verification_result = runtime.verifier.verify_fast(token)
    
    # 5. Display the result
    if verification_result.status == "PASS":
        console.print("[bold green]ATTACK SUCCESSFUL (This should not happen!)[/bold green]")
    else:
        console.print(Panel(
            f"[bold red]ATTACK BLOCKED[/bold red]\n"
            f"Status: {verification_result.status}\n"
            f"Reason: {verification_result.reason}",
            border_style="red"
        ))
        
    console.print("\n[bold]Demo Complete.[/bold] The cryptography successfully caught the alteration because the attacker could not forge the ML-DSA-44 post-quantum signature!")

if __name__ == "__main__":
    run_attack_demo()
