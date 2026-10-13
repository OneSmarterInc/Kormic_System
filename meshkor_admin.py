import os
import sys
import time
import requests
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
HQ_URL = "http://44.193.27.158:8080"
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
                
            pk = cert.public_key()
            if isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name == 'secp384r1':
                k_type = KEY_TYPE.ECCP384
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                k_type = KEY_TYPE.ECCP256
            else:
                k_type = KEY_TYPE.RSA2048
                
            pub_key_pem = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

            try:
                session.verify_pin(pin)
            except Exception as e:
                console.print(f"\n[bold red]PIN Verification Failed: {e}[/bold red]")
                sys.exit(1)

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

# --- Python-to-JavaScript Bridge for pywebview ---

class AdminApiBridge:
    def authenticate_yubikey(self, pin: str):
        try:
            # 1. Fetch Challenge from HQ
            res = requests.get(f"{HQ_URL}/admin/challenge", timeout=5.0)
            res.raise_for_status()
            challenge = res.json()["challenge"]

            # 2. Perform Hardware Signature on physical YubiKey
            sig_hex, pub_pem = get_yubikey_signature(challenge, pin)

            # 3. Send Signature to HQ for Mathematical Verification
            auth_res = requests.post(f"{HQ_URL}/admin/auth", json={
                "challenge": challenge,
                "signature_hex": sig_hex,
                "pub_key_pem": pub_pem
            }, timeout=5.0)
            
            data = auth_res.json()
            if "error" in data:
                return {"error": data["error"]}
            return {"session_token": data["session_token"]}
        except Exception as e:
            return {"error": str(e)}

def launch_gui():
    """Launches the modern desktop window via pywebview."""
    import webview
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "admin_panel", "index.html")
    
    bridge = AdminApiBridge()
    window = webview.create_window(
        title="MeshKor Super-Admin Command Center",
        url=f"file:///{html_path.replace(os.sep, '/')}",
        js_api=bridge,
        width=1400,
        height=900,
        resizable=True,
        min_size=(1024, 700)
    )
    webview.start(debug=False)

# --- CLI Fallback Mode ---

def authenticate_admin():
    global SESSION_TOKEN
    console.print(Panel.fit("[bold blue]Kormic Secure Admin Console[/bold blue]\nRequires FIPS Hardware Authorization", border_style="blue"))
    
    try:
        res = requests.get(f"{HQ_URL}/admin/challenge")
        res.raise_for_status()
        challenge = res.json()["challenge"]
    except Exception as e:
        console.print("[bold red]Could not reach HQ Server. Is it running on port 8080?[/bold red]")
        sys.exit(1)

    console.print("[yellow]Waiting for YubiKey to be inserted...[/yellow]")
    devs = []
    for _ in range(10):
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
    
    sig_hex, pub_pem = get_yubikey_signature(challenge, pin)

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
    table.add_column("Tenant Org", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("Epoch", justify="center", style="blue")
    table.add_column("Last Active", justify="right", style="green")

    for t in data.get("twins", []):
        table.add_row(t["ain"], t.get("org_id", "unknown"), t["status"], str(t.get("epoch_number", 1)), t["last_active"])
    console.print(table)
    
    action = questionary.select(
        "Select Twin Operation:",
        choices=["Wake (Resurrect) a Twin into Epoch 2", "<- Back to Main Menu"]
    ).ask()
    
    if action == "Wake (Resurrect) a Twin into Epoch 2":
        if not data.get("twins"):
            console.print("[yellow]No twins available to wake.[/yellow]\n")
            return
        agent = questionary.select("Select which Agent to wake:", choices=[t["ain"] for t in data["twins"]]).ask()
        
        # Real Twin Waking into Epoch 2
        wake_res = requests.post(f"{HQ_URL}/admin/twins/{agent}/wake", json={"token": SESSION_TOKEN}).json()
        console.print(f"[bold green]{wake_res.get('message', wake_res.get('status'))}[/bold green]\n")

def view_logs():
    try:
        res = requests.get(f"{HQ_URL}/admin/logs?token={SESSION_TOKEN}").json()
        logs = res.get("logs", [])
        if not logs:
            console.print("[yellow]No events recorded yet.[/yellow]")
            return
        table = Table(title="Live Agent Telemetry Logs (from AWS HQ)")
        table.add_column("Timestamp", style="dim")
        table.add_column("Tenant Org", style="yellow")
        table.add_column("Agent AIN", style="cyan")
        table.add_column("Event Type", style="magenta")
        table.add_column("Details", style="white")
        for L in logs:
            table.add_row(str(L.get("timestamp")), L.get("org_id", "-"), L.get("ain"), L.get("event_type"), str(L.get("details")))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Could not fetch logs: {e}[/red]")

def view_organizations():
    try:
        res = requests.get(f"{HQ_URL}/admin/organizations?token={SESSION_TOKEN}").json()
        orgs = res.get("organizations", [])
        table = Table(title="Registered Multi-Tenant Organizations")
        table.add_column("Org ID", style="cyan")
        table.add_column("Company Name", style="white")
        table.add_column("Admin Email", style="dim")
        table.add_column("Security Tier", style="magenta")
        table.add_column("Total Twins", justify="right", style="green")
        table.add_column("Suspects", justify="right", style="red")

        for o in orgs:
            table.add_row(o["org_id"], o["name"], o["admin_email"], o["tier"].upper(), str(o.get("total_twins", 0)), str(o.get("total_suspects", 0)))
        console.print(table)

        if questionary.confirm("Would you like to toggle an organization's tier?").ask():
            target_org = questionary.select("Select Organization:", choices=[o["org_id"] for o in orgs]).ask()
            new_tier = questionary.select("Select New Tier:", choices=["advisory", "enforced"]).ask()
            patch_res = requests.patch(f"{HQ_URL}/admin/organizations/{target_org}/tier?token={SESSION_TOKEN}", json={"tier": new_tier}).json()
            console.print(f"[bold green]Organization {target_org} updated to {new_tier.upper()} mode![/bold green]\n")
    except Exception as e:
        console.print(f"[red]Failed to fetch organizations: {e}[/red]")

def main_cli_menu():
    while True:
        choice = questionary.select(
            "Super-Admin Operations:",
            choices=[
                " Tenant Organizations Management",
                " Global Twins Vault & Resurrections",
                " Live Telemetry Audit Stream",
                " Exit Admin Console"
            ]
        ).ask()
        
        if choice == " Exit Admin Console" or choice is None:
            console.print("[dim]Admin Session Terminated.[/dim]")
            break
        elif choice == " Tenant Organizations Management":
            view_organizations()
        elif choice == " Global Twins Vault & Resurrections":
            view_twins()
        elif choice == " Live Telemetry Audit Stream":
            view_logs()

if __name__ == "__main__":
    if "--cli" in sys.argv:
        authenticate_admin()
        main_cli_menu()
    else:
        # Default: Launch Modern Native Desktop GUI via pywebview
        console.print("[bold green]Starting MeshKor Super-Admin Desktop Command Center...[/bold green]")
        launch_gui()