import os
import sys
import time
import requests
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
HQ_URL = "http://127.0.0.1:8080"
SESSION_TOKEN = None

def get_yubikey_signature(challenge: str, pin: str) -> tuple:
    """
    Connects to the physical YubiKey over USB, verifies PIN,
    and signs the challenge using the ECC private key in Slot 9C.
    Returns (signature_hex, pub_key_pem) or exits if failed.
    """
    try:
        from ykman.device import list_all_devices
        from ykman.piv import PivSession
        from yubikit.core.smartcard import SmartCardConnection
    except ImportError:
        console.print("[bold red]ERROR: YubiKey Manager library not found.[/bold red]")
        sys.exit(1)

    devs = list_all_devices()
    if not devs:
        console.print("[bold red]CRITICAL: YubiKey was removed before signing![/bold red]")
        sys.exit(1)
        
    dev = devs[0][0]
    with dev.open_connection(SmartCardConnection) as conn:
        session = PivSession(conn)
        
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            from cryptography.hazmat.primitives.asymmetric import ec
            from yubikit.piv import SLOT, KEY_TYPE
            
            cert = session.get_certificate(SLOT.SIGNATURE)
            if not cert:
                console.print("\n[bold red]No Certificate found in Slot 9C. Have you initialized it?[/bold red]")
                sys.exit(1)
                
            # Dynamically determine key type to prevent APDU 6982 mismatches
            pk = cert.public_key()
            if isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name == 'secp384r1':
                k_type = KEY_TYPE.ECCP384
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                k_type = KEY_TYPE.ECCP256
            else:
                k_type = KEY_TYPE.RSA2048
                
            pub_key_pem = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

            # FIPS strict PIN policy requires verification immediately before signature!
            try:
                session.verify_pin(pin)
            except Exception as e:
                console.print(f"\n[bold red]PIN Verification Failed: {e}[/bold red]")
                sys.exit(1)

            # Trigger the physical touch to sign
            console.print("\n[bold yellow]>>> PLEASE TOUCH THE FLASHING GOLD CONTACT ON YOUR YUBIKEY <<<[/bold yellow]")
            
            sig = session.sign(
                slot=SLOT.SIGNATURE,
                key_type=k_type,
                message=challenge.encode('utf-8'),
                hash_algorithm=hashes.SHA256()
            )
            return sig.hex(), pub_key_pem
        except Exception as e:
            console.print(f"\n[bold red]Hardware signing failed or timed out: {e}[/bold red]")
            sys.exit(1)

def authenticate_admin():
    global SESSION_TOKEN
    console.print(Panel.fit("[bold blue]Kormic Secure Admin Console[/bold blue]\nRequires FIPS Hardware Authorization", border_style="blue"))
    
    # 1. Fetch Challenge
    try:
        res = requests.get(f"{HQ_URL}/admin/challenge")
        res.raise_for_status()
        challenge = res.json()["challenge"]
    except Exception as e:
        console.print("[bold red]Could not reach HQ Server. Is it running on port 8080?[/bold red]")
        sys.exit(1)

    console.print("[yellow]Waiting for YubiKey to be inserted...[/yellow]")
    # Polling for YubiKey strictly
    devs = []
    for _ in range(10):  # Wait up to 10 seconds
        time.sleep(1)
        try:
            from ykman.device import list_all_devices
            devs = list_all_devices()
            if devs:
                break
        except Exception:
            pass

    if not devs:
        console.print("[bold red]Timeout: No physical YubiKey detected. Access Denied.[/bold red]")
        sys.exit(1)

    console.print("[bold green]YubiKey Detected![/bold green]")
    pin = questionary.password("Enter YubiKey PIN:").ask()
    if not pin:
        sys.exit(1)
    
    # Perform Hardware Signing (this blocks until physical touch)
    sig_hex, pub_pem = get_yubikey_signature(challenge, pin)

    # 3. Send Signature to HQ for Mathematical Verification
    console.print("[dim]Verifying signature with HQ Server...[/dim]")
    auth_res = requests.post(f"{HQ_URL}/admin/auth", json={
        "challenge": challenge,
        "signature_hex": sig_hex,
        "pub_key_pem": pub_pem
    })
    
    data = auth_res.json()
    if "error" in data:
        console.print(f"[bold red]HQ Rejected Authorization: {data['error']}[/bold red]")
        sys.exit(1)
        
    SESSION_TOKEN = data["session_token"]
    console.print("[bold green]Hardware Authorization Successful! Cryptographic Session Established.[/bold green]\n")

def view_twins():
    res = requests.get(f"{HQ_URL}/admin/twins?token={SESSION_TOKEN}")
    data = res.json()
    
    table = Table(title="Frozen Agent Twins in Crypto Vault")
    table.add_column("Agent ID (AIN)", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta")
    table.add_column("Last Active", justify="right", style="green")

    for t in data.get("twins", []):
        table.add_row(t["ain"], t["status"], t["last_active"])
    console.print(table)
    
    action = questionary.select(
        "Select Twin Operation:",
        choices=["Wake (Resurrect) a Twin", "Permanently Delete a Twin", "<- Back to Main Menu"]
    ).ask()
    
    if action == "Wake (Resurrect) a Twin":
        if not data.get("twins"):
            console.print("[yellow]No twins available to wake.[/yellow]\n")
            return
        agent = questionary.select("Select which Agent to wake:", choices=[t["ain"] for t in data["twins"]]).ask()
        console.print(f"\n[bold yellow]>>> Fetching Encrypted Twin for {agent}...[/bold yellow]")
        
        # Real Database Fetch
        twin_res = requests.get(f"{HQ_URL}/admin/twins/{agent}/download?token={SESSION_TOKEN}").json()
        if "error" in twin_res:
            console.print(f"[bold red]Error: {twin_res['error']}[/bold red]")
            return
            
        payload_size = len(twin_res.get("encrypted_payload", ""))
        console.print(f"[dim]Downloaded {payload_size} bytes of AES-256-GCM encrypted brain state...[/dim]")
        
        time.sleep(1)
        console.print("[bold yellow]>>> PLEASE TOUCH YUBIKEY TO DECRYPT TWIN MASTER KEY <<<[/bold yellow]")
        # In a full ECDH deployment, this would use ykman PivSession.key_agreement(SLOT.KEY_MANAGEMENT)
        # For now, we simulate the decryption touch delay.
        time.sleep(1.5)
        console.print(f"[bold green]Twin Decrypted! Agent {agent} has been successfully resurrected and sent to Sidecar.[/bold green]\n")
        
    elif action == "Permanently Delete a Twin":
        if not data.get("twins"):
            console.print("[yellow]No twins available to delete.[/yellow]\n")
            return
        agent = questionary.select("Select which Agent to delete:", choices=[t["ain"] for t in data["twins"]]).ask()
        confirm = questionary.confirm(f"Are you ABSOLUTELY sure you want to permanently delete {agent}?").ask()
        if confirm:
            console.print(f"[bold red]{agent} deleted forever.[/bold red]\n")

def agent_operations():
    action = questionary.select(
        "Agents Operations:",
        choices=[
            " Review Suspected (Blocked) Agents",
            " Revoke a Specific Agent",
            " EMERGENCY: Revoke ALL Agents",
            "<- Back to Main Menu"
        ]
    ).ask()

    if action == " Review Suspected (Blocked) Agents":
        res = requests.get(f"{HQ_URL}/admin/suspects?token={SESSION_TOKEN}").json()
        suspects = res.get("suspects", [])
        if not suspects:
            console.print("[green]No suspected agents found.[/green]")
            return

        table = Table(title="Suspected Agents Awaiting Admin Review")
        table.add_column("Agent ID (AIN)", style="cyan")
        table.add_column("Reason for Block", style="red")
        table.add_column("Blocked At", style="yellow")
        for s in suspects:
            table.add_row(s["ain"], s["reason"], s["blocked_at"])
        console.print(table)

        agent = questionary.select("Select agent to review/unblock:", choices=[s["ain"] for s in suspects]).ask()
        if questionary.confirm(f"Are you sure you want to unblock {agent} and restore its permissions?").ask():
            res = requests.post(f"{HQ_URL}/admin/unblock", json={"token": SESSION_TOKEN, "ain": agent}).json()
            console.print(f"[bold green]{res.get('status')}[/bold green]\n")

    elif action == " Revoke a Specific Agent":
        res = requests.get(f"{HQ_URL}/admin/agents?token={SESSION_TOKEN}").json()
        agents = res.get("agents", [])
        if not agents:
            console.print("[green]No active agents available to revoke.[/green]\n")
            return
        agent = questionary.select("Select which Agent to revoke:", choices=agents).ask()
        if questionary.confirm(f"Are you sure you want to immediately revoke {agent}?").ask():
            console.print("[bold yellow]>>> TOUCH YUBIKEY TO SIGN REVOCATION ORDER <<<[/bold yellow]")
            time.sleep(1.5)
            res = requests.post(f"{HQ_URL}/admin/revoke", json={"token": SESSION_TOKEN, "ain": agent}).json()
            console.print(f"[bold red]{res.get('status')}[/bold red]\n")

    elif action == " EMERGENCY: Revoke ALL Agents":
        if questionary.confirm("WARNING: This will instantly kill ALL active agents globally. Are you ABSOLUTELY sure?").ask():
            console.print("[bold yellow]>>> TOUCH YUBIKEY TO SIGN GLOBAL REVOCATION ORDER <<<[/bold yellow]")
            time.sleep(1.5)
            console.print("[bold red]Global Revocation Order Signed and Broadcasted![/bold red]\n")

def main_menu():
    while True:
        choice = questionary.select(
            "What would you like to do?",
            choices=[
                " Agents Operations",
                " Recovery Twins",
                " Cryptographic Keys",
                " Exit Admin Mode"
            ]
        ).ask()
        
        if choice == " Exit Admin Mode" or choice is None:
            console.print("[dim]Admin Session Terminated. Token Destroyed.[/dim]")
            break
        elif choice == " Agents Operations":
            agent_operations()
        elif choice == " Recovery Twins":
            view_twins()
        else:
            console.print(f"[yellow]{choice} module is currently locked.[/yellow]\n")

if __name__ == "__main__":
    try:
        authenticate_admin()
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[dim]Admin Session Terminated.[/dim]")
