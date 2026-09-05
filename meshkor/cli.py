import argparse
from meshkor.sidecar_daemon import serve
from meshkor.authority import LocalAuthority
from kormic.registry.distributed import RegionalReplicaRegistry
from kormic.crypto.software import SoftwareKeyCustody
from kormic.verify.engine import Verifier
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from meshkor.hq_client import HQClient

def start_sidecar():
    parser = argparse.ArgumentParser(description="Start the MeshKor Sidecar Daemon")
    parser.add_argument("--port", type=int, default=5050, help="Port to run the gRPC Sidecar on")
    parser.add_argument("--hq-url", type=str, default="http://127.0.0.1:8080", help="URL of the Cloud HQ")
    parser.add_argument("--db-path", type=str, default="meshkor_sidecar.db", help="Path to local SQLite database")
    
    args = parser.parse_args()
    
    print(f"Starting MeshKor Sidecar on port {args.port}...")
    print(f"Connecting to Cloud HQ at {args.hq_url}...")
    # 1. Connect to HQ
    hq_client = HQClient(args.hq_url)
    
    # 2. Setup Local Replica using the HQ Client
    replica = RegionalReplicaRegistry('customer-vpc', hq_client.fetch_root_pub(), central_sync=hq_client)
    try:
        replica.apply_snapshot(hq_client.snapshot())
        print("Successfully synced revocation list from HQ.")
    except Exception as e:
        print(f"Warning: Could not sync with HQ on boot: {e}")
        
    # 3. Setup Sidecar Engine
    # For testing, we fetch the epoch private key from HQ so the sidecar can act as an authority
    key_custody = SoftwareKeyCustody()
    epoch, priv, pub = hq_client.fetch_test_keys()
    key_custody._epoch_keys[epoch] = (priv, pub)
    
    manager = AgentManager(key_custody, SQLiteRecordStore(args.db_path), default_epoch=1, registry_reader=replica)
    local_auth = LocalAuthority(manager, Verifier(replica), None, replica)
    
    # 4. Start gRPC Server
    serve(local_auth, args.port)

if __name__ == "__main__":
    start_sidecar()
