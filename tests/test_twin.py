import unittest
import time
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.twin import TwinManager
from kormic.models.pedigree import Pedigree, BirthRecord, HistoryLink
from kormic.models.identity import Identity
from kormic.utils.exceptions import CryptographicError

class TestEncryptedRecoveryTwin(unittest.TestCase):
    def setUp(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        
        # Create a mock Pedigree
        ident = Identity("STU", "entity123", "0001", "a" * 64)
        birth = BirthRecord(
            identity=ident,
            created_at=time.time(),
            guardrails={},
            epoch_number=1,
            sig_alg="ML-DSA-44",
            signature=b"fakesig"
        )
        self.original_pedigree = Pedigree(
            birth_record=birth,
            history=[
                HistoryLink(1, "woke", time.time(), "prevhash", "thishash")
            ],
            running_head="fakehead"
        )

    def test_twin_encryption_and_shamir_recovery(self):
        """
        Proves the Twin is AES-encrypted at rest and its key is Shamir-split.
        Proves 3 shares recover the Twin perfectly, while 2 shares fail.
        """
        # 1. Seal the Twin
        sealed_blob, shares = TwinManager.seal_twin(self.original_pedigree, self.key_custody)
        
        # Verify the blob is JSON containing AES-GCM parameters (it's ciphertext)
        self.assertIn(b"nonce", sealed_blob)
        self.assertIn(b"ciphertext", sealed_blob)
        self.assertIn(b"tag", sealed_blob)
        self.assertNotIn(b"fakehead", sealed_blob) # The data must be encrypted!
        
        self.assertEqual(len(shares), 5, "Should generate 5 Shamir shares")
        
        # 2. Simulate Quorum Assembly (3 out of 5 shares)
        quorum = [shares[0], shares[2], shares[4]]
        
        # 3. Wake the Twin
        recovered_pedigree = TwinManager.wake_twin(sealed_blob, quorum, self.key_custody)
        
        # 4. Verify Perfect Match
        self.assertEqual(recovered_pedigree.running_head, self.original_pedigree.running_head)
        self.assertEqual(recovered_pedigree.birth_record.identity.to_string(), self.original_pedigree.birth_record.identity.to_string())
        self.assertEqual(len(recovered_pedigree.history), 1)
        
        # 5. Assert Failure with < 3 shares
        bad_quorum = [shares[0], shares[1]]
        with self.assertRaises(CryptographicError):
            TwinManager.wake_twin(sealed_blob, bad_quorum, self.key_custody)

    def test_twin_tamper_resistance(self):
        """
        Proves AES-GCM authenticates the ciphertext and rejects tampering.
        """
        sealed_blob, shares = TwinManager.seal_twin(self.original_pedigree, self.key_custody)
        quorum = [shares[0], shares[1], shares[2]]
        
        # Tamper with the ciphertext (flip a byte)
        import json
        stored = json.loads(sealed_blob.decode('utf-8'))
        ct_bytes = bytearray.fromhex(stored["ciphertext"])
        ct_bytes[0] ^= 0x01 # Flip one bit
        stored["ciphertext"] = ct_bytes.hex()
        tampered_blob = json.dumps(stored).encode('utf-8')
        
        # AES-GCM should raise ValueError on MAC check failure
        with self.assertRaises(ValueError):
            TwinManager.wake_twin(tampered_blob, quorum, self.key_custody)

if __name__ == '__main__':
    unittest.main()
