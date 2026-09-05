import json
from concurrent import futures
import grpc
from meshkor import meshkor_pb2
from meshkor import meshkor_pb2_grpc
from meshkor.authority import LocalAuthority

class MeshKorSidecarServicer(meshkor_pb2_grpc.MeshKorSidecarServicer):
    def __init__(self, local_authority: LocalAuthority):
        self.auth = local_authority

    def EnrollAgent(self, request, context):
        manifest = json.loads(request.manifest_json)
        ain = self.auth.enroll_pubkey(
            request.agent_type, request.entity_ref, request.instance,
            request.real_world_id, manifest, request.agent_pub_key
        )
        return meshkor_pb2.EnrollResponse(ain=ain)

    def GetChallenge(self, request, context):
        nonce = self.auth.issue_challenge()
        return meshkor_pb2.ChallengeResponse(nonce=nonce)

    def GetPedigree(self, request, context):
        ped_dict = self.auth.get_pedigree(request.ain)
        return meshkor_pb2.PedigreeResponse(pedigree_json=json.dumps(ped_dict))

    def RecordEvent(self, request, context):
        new_head = self.auth.record_event(request.ain, request.event_data)
        return meshkor_pb2.RecordResponse(new_head=new_head)

    def VerifyToken(self, request, context):
        token_dict = json.loads(request.token_json)
        from kormic.models.verify import ProofToken
        token = ProofToken(**token_dict)
        res = self.auth.get_verifier().verify_fast(token)
        return meshkor_pb2.VerifyResponse(status=res.status, reason=res.reason)

def serve(local_authority: LocalAuthority, port=5050):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    meshkor_pb2_grpc.add_MeshKorSidecarServicer_to_server(
        MeshKorSidecarServicer(local_authority), server
    )
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    print(f"Sidecar Daemon listening on port {port}...")
    server.wait_for_termination()
