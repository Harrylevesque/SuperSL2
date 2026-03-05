from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
import os
import time
import json
import hashlib


# Replay cache: challenge_id -> expiry_time
_used_challenges = {}



def import_public_key(public_key_str: str) -> bytes:
    return Base64Encoder.decode(public_key_str.encode())




def generate_challenge(window_seconds=3) -> str:
    challenge = os.urandom(64)
    issued_at = time.monotonic()

    challenge_id = hashlib.sha256(challenge).hexdigest()
    _used_challenges[challenge_id] = issued_at + window_seconds

    payload = {
        "challenge": Base64Encoder.encode(challenge).decode(),
        "issued_at": issued_at,
        "challenge_id": challenge_id
    }

    return json.dumps(payload)



def _cleanup_cache():
    now = time.monotonic()
    expired = [cid for cid, exp in _used_challenges.items() if exp <= now]
    for cid in expired:
        del _used_challenges[cid]



def verify_client_signature(otp_pubk: bytes, payload_json: str, signature: bytes, window_seconds=30) -> bool:
    try:
        _cleanup_cache()

        payload = json.loads(payload_json)

        challenge = Base64Encoder.decode(payload["challenge"].encode())
        issued_at = payload["issued_at"]
        challenge_id = payload["challenge_id"]

        now = time.monotonic()

        # Expiry check
        if now - issued_at > window_seconds:
            return False

        # Replay check
        if challenge_id not in _used_challenges:
            return False

        # One-time use
        del _used_challenges[challenge_id]

        message = challenge + str(issued_at).encode()

        verify_key = VerifyKey(otp_pubk)
        verify_key.verify(signature)

        return True

    except (BadSignatureError, KeyError, ValueError):
        return False