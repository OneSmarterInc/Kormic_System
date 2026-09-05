import functools
import json
from kormic.models.verify import ProofToken
from meshkor.remote import RemoteAuthority

class MeshKorUnauthorized(Exception):
    pass

def require_meshkor_token(sidecar_addr="127.0.0.1:5050"):
    """
    A plain Python decorator to protect generic Python functions.
    Expects the wrapped function to accept a `token_str` keyword argument
    containing the serialized ProofToken.
    """
    auth = RemoteAuthority(sidecar_addr)
    verifier = auth.get_verifier()
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            token_str = kwargs.get('token_str')
            if not token_str:
                raise MeshKorUnauthorized("Missing token_str argument")
                
            try:
                if isinstance(token_str, str):
                    token_dict = json.loads(token_str)
                else:
                    token_dict = token_str
                    
                token = ProofToken(**token_dict)
                res = verifier.verify_fast(token)
                
                if res.status != "PASS":
                    raise MeshKorUnauthorized(f"MeshKor Token Rejected: {res.reason}")
                    
                # Store the verified AIN in kwargs so the function can use it
                kwargs['verified_ain'] = token.agent_code
                
            except Exception as e:
                raise MeshKorUnauthorized(f"Invalid MeshKor Token: {str(e)}")
                
            return func(*args, **kwargs)
        return wrapper
    return decorator
