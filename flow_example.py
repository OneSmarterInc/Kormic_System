from meshkor.sdk import MeshKorSDK
from meshkor.python_adapter import require_meshkor_token
import json

# ---------------------------------------------------------
# 1. THE PROTECTED RESOURCE (e.g. Django Database API)
# ---------------------------------------------------------
@require_meshkor_token(sidecar_addr="127.0.0.1:5053")
def query_sensitive_database(query: str, token_str: str = None, verified_ain: str = None):
    # This code only runs if the MeshKor token was cryptographically valid!
    print(f"\n[RESOURCE] Access GRANTED for Agent: {verified_ain}")
    print(f"[RESOURCE] Executing Query: {query}")
    return "Database Results: { 'status': 'success', 'data': 'Top Secret' }"

# ---------------------------------------------------------
# 2. THE AI AGENT
# ---------------------------------------------------------
if __name__ == "__main__":
    print("[AGENT] Booting up...")
    sdk = MeshKorSDK("127.0.0.1:5053")

    # The Agent Enrolls
    manifest = {"allowed_tools": ["db_query"], "allowed_endpoints": [], "credential_scopes": [], "blast_radius": "low"}
    ain = sdk.enroll(agent_type="CMP", instance="001", manifest=manifest)
    print(f"[AGENT] Enrolled successfully. My AIN is: {ain}")

    # The Agent does some work
    print("[AGENT] Analyzing user request...")
    sdk.record_action("Analyzed user request")
    print("[AGENT] Deciding to query database...")
    sdk.record_action("Decided to query database")

    # The Agent generates a ProofToken to access the database
    proof_token = sdk.mint_token()
    token_json = json.dumps(proof_token.to_dict())

    print("\n[AGENT] Attempting to query the protected database...")
    try:
        # We pass the token_str to the protected resource (simulating an HTTP header)
        result = query_sensitive_database("SELECT * FROM users", token_str=token_json)
        print(f"[AGENT] Received response: {result}")
    except Exception as e:
        print(f"[RESOURCE] Access DENIED: {e}")
