try:
    import grpc
    import meshkor.meshkor_pb2 as meshkor_pb2
    import meshkor.meshkor_pb2_grpc as meshkor_pb2_grpc
except ImportError:
    grpc = None
from .authority import Authority
import json

class RemoteAuthority(Authority):
    """
    Final Phase 4 Implementation.
    Communicates with the ultra-low latency Sidecar Daemon via gRPC.
    """
    def __init__(self, sidecar_addr="127.0.0.1:5050"):
        self.channel = grpc.insecure_channel(sidecar_addr)
        self.stub = meshkor_pb2_grpc.MeshKorSidecarStub(self.channel)
        
    def enroll_pubkey(self, agent_type: str, entity_ref: str, instance: str, 
                      real_world_id: str, manifest: dict, agent_pub_key: str) -> str:
        req = meshkor_pb2.EnrollRequest(
            agent_type=agent_type,
            entity_ref=entity_ref,
            instance=instance,
            real_world_id=real_world_id,
            manifest_json=json.dumps(manifest),
            agent_pub_key=agent_pub_key
        )
        res = self.stub.EnrollAgent(req)
        return res.ain

    def get_pedigree(self, ain: str) -> dict:
        req = meshkor_pb2.PedigreeRequest(ain=ain)
        res = self.stub.GetPedigree(req)
        return json.loads(res.pedigree_json)

    def record_event(self, ain: str, event_description: str) -> str:
        req = meshkor_pb2.RecordRequest(ain=ain, event_data=event_description)
        res = self.stub.RecordEvent(req)
        return res.new_head

    def get_verifier(self):
        class RemoteVerifierProxy:
            def __init__(self, stub):
                self.stub = stub
                
            def verify_fast(self, token):
                req = meshkor_pb2.VerifyRequest(ain=token.agent_code, token_json=json.dumps(token.to_dict()))
                res = self.stub.VerifyToken(req)
                from kormic.models.verify import VerificationResult
                return VerificationResult(res.status, res.reason, token.agent_code, 1)
                
            def verify_full(self, token, history_links):
                raise NotImplementedError("Full verify is only for HQ")
                
        return RemoteVerifierProxy(self.stub)

    def issue_challenge(self) -> str:
        res = self.stub.GetChallenge(meshkor_pb2.ChallengeRequest())
        return res.nonce
