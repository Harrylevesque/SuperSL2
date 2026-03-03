from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
import os


# -----------------------------
# Prepare public key for storage
# (import safely from transport string)
# -----------------------------
def import_public_key(public_key_str: str) -> bytes:
    return Base64Encoder.decode(public_key_str.encode())


# -----------------------------
# Generate authentication challenge
# -----------------------------
def generate_challenge() -> bytes:
    return os.urandom(32)


# -----------------------------
# Verify signature
# -----------------------------
def verify_client_signature(public_key: bytes, challenge: bytes, signature: bytes) -> bool:
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(signature)
        return True
    except BadSignatureError:
        return False