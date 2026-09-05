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
        
    def fetch_test_keys(self):
        res = requests.get(f"{self.hq_url}/test_keys")
        res.raise_for_status()
        data = res.json()
        return data["epoch"], bytes.fromhex(data["priv"]), bytes.fromhex(data["pub"])
        
    def spend_nonce(self, nonce: str) -> None:
        requests.post(f"{self.hq_url}/spend_nonce", json={"nonce": nonce})
