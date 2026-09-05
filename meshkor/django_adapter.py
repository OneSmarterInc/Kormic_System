from rest_framework import authentication
from rest_framework import exceptions
from kormic.models.verify import ProofToken
from meshkor.remote import RemoteAuthority
import json

class MeshKorAuthentication(authentication.BaseAuthentication):
    """
    Django REST Framework authentication class that verifies a MeshKor ProofToken.
    Requires `sidecar_addr` to be configured, or assumes 127.0.0.1:5050.
    """
    def __init__(self, sidecar_addr="127.0.0.1:5050"):
        self.auth = RemoteAuthority(sidecar_addr)
        self.verifier = self.auth.get_verifier()

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('MeshKor '):
            return None # Authentication not attempted

        token_str = auth_header.split(' ')[1]
        try:
            token_dict = json.loads(token_str)
            token = ProofToken(**token_dict)
            
            # Verify the token via the local sidecar
            res = self.verifier.verify_fast(token)
            if res.status != "PASS":
                raise exceptions.AuthenticationFailed(f"MeshKor Token Rejected: {res.reason}")
                
            # The token is valid. Return (user, auth) tuple. 
            # We map the AIN to the 'user' for DRF views to use.
            return (token.agent_code, token)
            
        except Exception as e:
            raise exceptions.AuthenticationFailed(f"Invalid MeshKor Token: {str(e)}")
