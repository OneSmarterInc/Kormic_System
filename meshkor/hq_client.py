import requests
from kormic.registry.distributed import RegionalReplicaRegistry, RegistrySnapshot

class HQClient:
    def __init__(self, hq_url: str):
        self.hq_url = hq_url.rstrip('/')

    def snapshot(self) -> RegistrySnapshot:
        resp = requests.get(f"{self.hq_url}/snapshot")
        resp.raise_for_status()
        return RegistrySnapshot(**resp.json())
        
    def fetch_root_pub(self) -> bytes:
        resp = requests.get(f"{self.hq_url}/root_key")
        resp.raise_for_status()
        return bytes.fromhex(resp.json()["root_pub"])
    def fetch_epoch_pub(self, epoch: int) -> bytes:
        # Sidecar only needs the public key to verify signatures!
        # In a real app, this would be part of the snapshot or a dedicated endpoint,
        # but for now we can just return a dummy or rely on the registry snapshot
        # Let's add it properly if needed, or sidecar gets it from snapshot
        pass

    def enroll_agent(self, agent_type: str, entity_ref: str, instance: str, real_world_id: str, manifest: dict, agent_pub_key: str = ""):
        req = {
            "agent_type": agent_type,
            "entity_ref": entity_ref,
            "instance": instance,
            "real_world_id": real_world_id,
            "manifest": manifest,
            "agent_pub_key": agent_pub_key
        }
        res = requests.post(f"{self.hq_url}/enroll", json=req)
        res.raise_for_status()
        return res.json()
        
    def spend_nonce(self, nonce: str) -> None:
        requests.post(f"{self.hq_url}/spend_nonce", json={"nonce": nonce})
