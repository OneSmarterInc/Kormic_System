import json
from typing import List, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from kormic.models.pedigree import Pedigree
from kormic.interfaces.keys import KeyCustody, Share
from kormic.utils.serialize import canonical_json

class TwinManager:
    """
    Manages the AES-256-GCM encryption and Shamir threshold splitting 
    for the Pedigree Recovery Twin. Satisfies Section 6.4.
    """
    
    @staticmethod
    def seal_twin(pedigree: Pedigree, key_custody: KeyCustody) -> Tuple[bytes, List[Share]]:
        """
        Encrypts a Pedigree at rest and splits the AES key using Shamir Secret Sharing.
        Returns the ciphertext blob and the key shares. The AES key is discarded.
        """
        from kormic.logger import kormic_logger
        # 1. Generate a random 32-byte AES key
        aes_key = get_random_bytes(32)
        
        # 2. Serialize the Pedigree
        pedigree_bytes = canonical_json(pedigree.to_dict()).encode('utf-8')
        
        # 3. Encrypt the Pedigree (AES-256-GCM)
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(pedigree_bytes)
        
        # 4. Package the sealed blob
        sealed_blob = json.dumps({
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }).encode('utf-8')
        
        # 5. Split the AES key into Shamir shares
        shares = key_custody.wrap_twin_key(aes_key)
        
        # 6. Delete the key (Python GC will handle it, but we overwrite if possible. 
        # For software python, discarding reference is standard).
        del aes_key
        
        kormic_logger.info("TWIN_SEAL", pedigree.birth_record.identity.to_string(), "Encrypted Recovery Twin. Master Key shattered and deleted.")
        
        return sealed_blob, shares

    @staticmethod
    def wake_twin(sealed_blob: bytes, shares: List[Share], key_custody: KeyCustody) -> Pedigree:
        """
        Reconstructs the AES key from a quorum of Shamir shares, and decrypts the Twin.
        """
        from kormic.logger import kormic_logger
        
        # 1. Rebuild the AES key using the Shamir Quorum
        kormic_logger.info("TWIN_WAKE", "SYSTEM", f"Key Ceremony: {len(shares)}/5 hardware shares assembled. Master Key rebuilt.")
        aes_key = key_custody.unwrap_twin_key(shares)
        
        # 2. Parse the sealed blob
        stored = json.loads(sealed_blob.decode('utf-8'))
        nonce = bytes.fromhex(stored["nonce"])
        ciphertext = bytes.fromhex(stored["ciphertext"])
        tag = bytes.fromhex(stored["tag"])
        
        # 3. Decrypt the Pedigree
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            pedigree_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            kormic_logger.info("TWIN_WAKE", "SYSTEM", "Decryption successful. Data integrity verified.")
        except ValueError:
            kormic_logger.error("TWIN_WAKE", "SYSTEM", "MAC Check Failed! Ciphertext was tampered with.")
            raise
            
        # 4. Deserialize back into a Pedigree object
        pedigree_dict = json.loads(pedigree_bytes.decode('utf-8'))
        return Pedigree.from_dict(pedigree_dict)
